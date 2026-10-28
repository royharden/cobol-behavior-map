"""Source-only, fail-closed coverage over externally normalized original traces.

No decoder, instrumentation, execution, filesystem IO or authentication is
implemented here. All actual behavior remains runtime-unverified. Hashes bind
bytes but cannot establish that a compiler ran or an authority admitted a case.
"""
from collections.abc import Iterable
from typing import Literal

from cobolmap.contracts import SourcePointer, sha256
from cobolmap.parse.models import IRNode, ProgramIR

from .trace_models import CoverageResult, TraceCase, TraceContext, TraceDecoder, TraceEvent

__all__ = ["coverage", "CoverageResult", "TraceCase", "TraceContext", "TraceDecoder", "TraceEvent"]

_EXPRESSIONS = frozenset({"literal", "reference", "binary", "compare", "boolean"})


def _pointer_key(pointer: SourcePointer) -> tuple[str, str, int, int, int, int]:
    return (pointer.source_sha256, pointer.filename, pointer.line_start,
            pointer.line_end, pointer.byte_start, pointer.byte_end)


def _statements(nodes: tuple[IRNode, ...]) -> Iterable[IRNode]:
    # Follow syntactic statement bodies only, never expressions or PERFORM edges.
    for node in nodes:
        yield node
        yield from _statements(node.body)
        yield from _statements(node.otherwise)


def coverage(program: ProgramIR, records: tuple[TraceCase, ...], *,
             context: TraceContext | None = None) -> CoverageResult:
    """Aggregate unique original hits only after every record clears all gates.

    Denominators include all original syntax, including unreachable paragraphs
    and statements. Any missing evidence yields no partial hits. One record
    without statement identity makes the whole statement numerator unknown.
    Trusted context must come from an external admission/authentication boundary.
    """
    # Do not materialize arbitrary iterables: iteration could invoke caller code
    # before admission. The declared seam is an exact immutable tuple.
    if type(records) is not tuple:
        return CoverageResult(status="invalid", issues=("trace_records_exact_tuple_required",))
    invalid: list[str] = []
    pending: list[str] = []
    paragraphs: dict[str, SourcePointer] = {}
    statements: dict[tuple[str, str, int, int, int, int], tuple[str, SourcePointer]] = {}
    source = program.source.encode("utf-8")
    if sha256(source) != program.source_sha256:
        invalid.append("original_source_hash_mismatch")
    for paragraph in program.paragraphs:
        if paragraph.name in paragraphs:
            invalid.append("duplicate_original_paragraph")
        paragraphs[paragraph.name] = paragraph.span
        try:
            paragraph.span.resolve(source, program.filename)
        except (ValueError, UnicodeError):
            invalid.append("original_paragraph_pointer_unresolved")
        for node in _statements(paragraph.statements):
            key = _pointer_key(node.span)
            if node.kind in _EXPRESSIONS:
                invalid.append("expression_in_original_statement_tree")
            if key in statements:
                invalid.append("ambiguous_original_statement_identity")
            statements[key] = (paragraph.name, node.span)
            try:
                node.span.resolve(source, program.filename)
            except (ValueError, UnicodeError):
                invalid.append("original_statement_pointer_unresolved")
            if not (paragraph.span.byte_start <= node.span.byte_start
                    and node.span.byte_end <= paragraph.span.byte_end):
                invalid.append("original_statement_outside_paragraph")

    def result(status: Literal["not_run", "pending", "invalid"], issues: list[str]) -> CoverageResult:
        # Unknown/invalid never exposes a numerator or partial hit union.
        return CoverageResult(status=status, paragraph_denominator=len(paragraphs),
                              statement_denominator=len(statements),
                              issues=tuple(dict.fromkeys(issues)))

    # Frozen models remain declarations, and model_construct can bypass their
    # validators. Rebuild from their closed Python shape, rather than validating
    # an existing instance (which Pydantic may accept without revalidation).
    # Exact classes prevent a supplied subclass overriding model_dump here.
    if context is not None:
        if type(context) is not TraceContext:
            return result("invalid", invalid + ["trace_context_closed_shape_required"])
        try:
            context = TraceContext.model_validate(TraceContext.model_dump(context, mode="python"))
        except (ValueError, TypeError, AttributeError):
            return result("invalid", invalid + ["trace_context_shape_invalid"])
    checked_records: list[TraceCase] = []
    for record in records:
        if type(record) is not TraceCase:
            return result("invalid", invalid + ["trace_case_closed_shape_required"])
        try:
            checked_records.append(TraceCase.model_validate(TraceCase.model_dump(record, mode="python")))
        except (ValueError, TypeError, AttributeError):
            return result("invalid", invalid + ["trace_case_shape_invalid"])
    records = tuple(checked_records)

    if not paragraphs:
        invalid.append("original_paragraphs_missing")
    if context is None:
        pending.append("trusted_trace_context_missing")
    else:
        if not context.admitted:
            pending.append("admission_pending")
        if not context.trusted_context:
            pending.append("authenticated_context_missing")
        if not context.trusted_normalized:
            pending.append("authenticated_normalization_missing")
        if not context.trusted_case_hashes:
            pending.append("trusted_case_membership_missing")
        if context.admission_authority is None:
            pending.append("admission_authority_missing")
        if context.approved_framing is None:
            pending.append("approved_framing_missing")
        if context.expected_untraced_pins is None or context.expected_traced_pins is None:
            pending.append("expected_phase_pins_missing")

    paragraph_hits: set[str] = set()
    statement_hits: set[tuple[str, str, int, int, int, int]] = set()
    repeated: dict[str, tuple[object, object]] = {}
    for record in records:
        untraced, traced = record.untraced, record.traced
        for phase, observation in (("untraced", untraced), ("traced", traced)):
            if observation.candidate_sha256 is not None:
                invalid.append(f"{phase}_must_be_original")
            if observation.source_sha256 != program.source_sha256:
                invalid.append(f"{phase}_source_mismatch")
            if observation.outcome == "not_run":
                pending.append(f"{phase}_not_run")
            elif observation.outcome not in {"completed", "handled"}:
                invalid.append(f"{phase}_uncontrolled_outcome")
            if observation.ordinary is None:
                pending.append(f"{phase}_ordinary_missing")
            elif observation.ordinary.return_code not in observation.allowed_return_codes:
                invalid.append(f"{phase}_undeclared_return")
            pending.extend(f"{phase}_{issue}" for issue in observation.evidence.missing_actual())
            if context is not None:
                if (observation.task_id, observation.program_id) != (context.task_id, context.program_id):
                    invalid.append(f"{phase}_context_identity_mismatch")
                if context.trusted_case_hashes and observation.case_sha256 not in context.trusted_case_hashes:
                    invalid.append(f"{phase}_untrusted_case")
                expected = (context.expected_untraced_pins if phase == "untraced"
                            else context.expected_traced_pins)
                if expected is not None and observation.evidence.pins is not None and observation.evidence.pins != expected:
                    invalid.append(f"{phase}_execution_pin_mismatch")
                if (context.admission_authority is not None
                        and observation.evidence.admission_authority is not None
                        and observation.evidence.admission_authority != context.admission_authority):
                    invalid.append(f"{phase}_admission_authority_mismatch")
        if ((untraced.task_id, untraced.program_id, untraced.case_sha256)
                != (traced.task_id, traced.program_id, traced.case_sha256)):
            invalid.append("trace_pair_identity_mismatch")
        if untraced.allowed_return_codes != traced.allowed_return_codes:
            invalid.append("trace_pair_return_declaration_mismatch")
        if untraced.ordinary is not None and traced.ordinary is not None and untraced.ordinary != traced.ordinary:
            invalid.append("traced_untraced_ordinary_mismatch")
        ordinary_pair = (untraced.ordinary, traced.ordinary)
        if untraced.case_sha256 in repeated and repeated[untraced.case_sha256] != ordinary_pair:
            invalid.append("nondeterministic_repeated_case_ordinary")
        repeated[untraced.case_sha256] = ordinary_pair
        if traced.trace_artifact is None:
            pending.append("raw_trace_artifact_missing")
        else:
            try:
                traced.trace_artifact.check_bytes(record.raw_trace)
            except ValueError:
                invalid.append("raw_trace_artifact_hash_mismatch")
        if context is not None and context.approved_framing is not None and record.framing != context.approved_framing:
            invalid.append("unapproved_trace_framing")
        # Receipt existence/shape is structural. Neither its content nor its
        # authenticity is checked locally; trusted_normalized asserts external
        # verification of the exact event/raw/framing/source/identity binding.
        for event in record.events:
            paragraph = paragraphs.get(event.paragraph)
            if paragraph is None:
                invalid.append("unknown_trace_paragraph")
                continue
            try:
                event.pointer.resolve(source, program.filename)
            except (ValueError, UnicodeError):
                invalid.append("trace_pointer_unresolved")
            if event.kind == "paragraph":
                if event.pointer != paragraph:
                    invalid.append("paragraph_event_full_span_mismatch")
                else:
                    paragraph_hits.add(event.paragraph)
            elif event.kind == "statement":
                key = _pointer_key(event.pointer)
                declared = statements.get(key)
                if declared is None or declared[0] != event.paragraph:
                    invalid.append("statement_event_identity_mismatch")
                else:
                    paragraph_hits.add(event.paragraph)
                    statement_hits.add(key)
            else:
                invalid.append("unknown_trace_event_kind")
    if context is not None and context.trusted_case_hashes - repeated.keys():
        pending.append("expected_scored_cases_missing")
    if invalid:
        return result("invalid", invalid + pending)
    if not records:
        return result("not_run", pending + ["trace_records_missing"])
    if pending:
        return result("pending", pending)
    statements_known = all(record.statement_identity for record in records)
    return CoverageResult(
        status="complete", evidence_mode="actual",
        paragraph_numerator=len(paragraph_hits), paragraph_denominator=len(paragraphs),
        statement_numerator=len(statement_hits) if statements_known else None,
        statement_denominator=len(statements),
        paragraph_hits=tuple(name for name in paragraphs if name in paragraph_hits),
        unreached_paragraphs=tuple(name for name in paragraphs if name not in paragraph_hits),
        statement_hits=tuple(span for key, (_, span) in statements.items() if key in statement_hits) if statements_known else (),
        unreached_statements=tuple(span for key, (_, span) in statements.items() if key not in statement_hits) if statements_known else (),
        issues=() if statements_known else ("statement_identity_unknown",),
    )
