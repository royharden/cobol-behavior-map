"""Bounded FUTURE oracle orchestration; default refusal, no execution backend.

Admission is supplied by the responsible caller. Hash pins/declarations are checked
for consistency; they cannot authenticate that caller or certify a compiler run.
"""
from itertools import islice
from typing import Iterable

from cobolmap.contracts import Claim, EvidenceBinding, FieldValue, TaskBinding
from .evaluator import Untestable, _bindings, _guard, evaluate_claim
from .fields import display_matches, validate_decoded_value, validate_layout
from .models import (
    CaseCandidate, ClaimCounterexample, ClaimResult, Minimizer, Oracle, OracleWitness,
)

MAX_PROPOSALS = 1000
MAX_ORACLE_CASES = 50


def _candidate_issues(candidate: CaseCandidate, task: TaskBinding, source: bytes,
                      evidence: EvidenceBinding) -> tuple[str, ...]:
    issues = []
    if candidate.partition != "dev": issues.append("dev_partition_required")
    if (candidate.task_id != task.task_id or candidate.program_id != task.program_id
            or candidate.source_sha256 != task.oracle_source.sha256):
        issues.append("candidate_task_source_binding")
    if candidate.provenance.byte_length == 0:
        issues.append("empty_case_provenance")
    # Input decoding is an explicit separate trust decision by the admitted caller.
    # The source-bound layout is checked here; decoder/case correspondence is not
    # invented from a scalar binding or from a generation-only provenance hash.
    if (candidate.trusted_decoded_inputs is not True
            or candidate.input_decoding_authority != evidence.admission_authority):
        issues.append("trusted_input_decoding_admission_required")
    try:
        values = _bindings(candidate.inputs, "input")
        layouts = {layout.name: layout for layout in candidate.input_layouts}
        if len(layouts) != len(candidate.input_layouts) or set(layouts) != {k[1] for k in values}:
            issues.append("input_layout_binding_coverage")
        for binding in candidate.inputs:
            if binding.field.name in layouts:
                validate_layout(layouts[binding.field.name], binding.field,
                                source, task.oracle_source.path)
                validate_decoded_value(layouts[binding.field.name], binding.value)
    except (ValueError, UnicodeError) as error:
        issues.append(str(error))
    return tuple(issues)


def _witness_issues(witness: OracleWitness, candidate: CaseCandidate,
                    task: TaskBinding, evidence: EvidenceBinding, source: bytes) -> tuple[str, ...]:
    observed = witness.observation
    issues = list(observed.evidence.missing_actual())
    # A run context shares authority and pins; each invocation retains its own
    # required actual runtime receipt. Receipt equality would collapse case lineage.
    if (observed.evidence.mode != evidence.mode
            or observed.evidence.pins != evidence.pins
            or observed.evidence.admission_authority != evidence.admission_authority):
        issues.append("observation_admission_binding")
    if (observed.task_id != task.task_id or observed.program_id != task.program_id
            or observed.source_sha256 != task.oracle_source.sha256
            or observed.case_sha256 != candidate.case.case_sha256
            or observed.candidate_sha256 is not None):
        issues.append("oracle_task_source_case_binding")
    if observed.outcome not in ("completed", "handled") or observed.ordinary is None:
        issues.append("ordinary_oracle_observation_required")
        return tuple(issues)
    ordinary = observed.ordinary
    try:
        values = _bindings(witness.outputs, "output")
        resolved = set()
        for field in witness.fields:
            binding = field.binding
            key = (binding.field.scope, binding.field.name)
            if key in resolved or key not in values or values[key] != binding.value:
                issues.append("ambiguous_or_unbound_field_witness")
                continue
            resolved.add(key)
            validate_layout(field.layout, binding.field, source, task.oracle_source.path)
            data = (ordinary.output.data if field.channel == "output"
                    else ordinary.stdout if field.channel == "stdout" else ordinary.stderr)
            if data is None or field.byte_end > len(data):
                issues.append("unobservable_field_span")
                continue
            raw = data[field.byte_start:field.byte_end]
            if field.encoding == "display":
                if (field.channel != "output"
                        or field.byte_start != field.record_start + field.layout.offset
                        or (field.record_start > 0 and data[field.record_start - 1:field.record_start] != b"\n")
                        or b"\n" in data[field.record_start:field.byte_start]
                        or not display_matches(raw, field.layout, binding.value)):
                    issues.append("display_field_witness_mismatch")
            # Textual emission stays lexical: no whitespace/sign normalization.
            elif raw != binding.value.value.encode("ascii"):
                issues.append("field_witness_bytes_mismatch")
        if resolved != set(values): issues.append("output_binding_without_byte_witness")
    except (ValueError, UnicodeError) as error:
        issues.append(str(error))
    return tuple(issues)


def _size(candidate: CaseCandidate) -> tuple[int, int, bytes]:
    raw = candidate.case.file_bytes()
    return (len(raw) if raw is not None else 0, len(candidate.case.records), raw or b"")


def search_claim(
    claim: Claim, cases: Iterable[CaseCandidate], oracle: Oracle | None, *,
    admitted: bool = False, source: bytes, task: TaskBinding,
    evidence: EvidenceBinding, seed: int = 0, minimizer: Minimizer | None = None,
) -> ClaimResult:
    """Search at most 50 distinct admitted dev oracle cases, 1000 proposals total.

    Caller case provenance and ordering are explicit. Boundaries precede other cases;
    seed deterministically ranks each group by case hash. Exhaustion is not proof of
    an impossible guard. Minimization reports only best_found among measured cases.
    No callback is invoked until explicit admission and all supplied dev cases pass
    source/task/partition checks. Caller must supply an authentic admission context.
    Input-only guards filter before the oracle. Guards referencing outputs are
    evaluated only after validated byte witnesses; false guards consume a call
    but never count as support. Total calls stay capped at 50 in either path.
    """
    def refused(status: str, *issues: str) -> ClaimResult:
        return ClaimResult(claim_id=claim.claim_id, status=status, issues=tuple(issues))

    if admitted is not True:
        return refused("not_run", "explicit_caller_admission_required")
    missing = evidence.missing_actual()
    if missing:
        return refused("not_run", *missing)
    if oracle is None:
        return refused("not_run", "oracle_unavailable")
    if task.split != "dev":
        return refused("untestable", "dev_task_required")
    try:
        task.oracle_source.check_bytes(source)
        claim.span.resolve(source, task.oracle_source.path)
    except (ValueError, UnicodeError) as error:
        return refused("untestable", "pointer_unresolved:" + str(error))
    # Only input-only conjunctions can safely filter before an actual observation.
    input_only_guard = not any(part.left.scope != "input" or (
        isinstance(part.right, FieldValue) and part.right.field.scope != "input"
    ) for part in claim.guard)
    if type(seed) is not int:
        return refused("untestable", "integer_seed_required")

    # No lookahead beyond the declared proposal budget, even for infinite iterables.
    supplied = tuple(islice(cases, MAX_PROPOSALS))
    for candidate in supplied:
        issues = _candidate_issues(candidate, task, source, evidence)
        if issues:
            return refused("untestable", *issues)
    # Stable deterministic pseudo-random ordering without an ambient RNG or hash().
    mask = seed % (1 << 256)
    ordered = sorted(supplied, key=lambda c: (
        not c.boundary, int(c.case.case_sha256, 16) ^ mask, c.case.case_sha256,
    ))
    proposals = len(supplied)
    seen: set[str] = set()
    calls = 0
    support: list[OracleWitness] = []
    boundary = False
    issues: list[str] = []
    counterexample: ClaimCounterexample | None = None

    def observe(candidate: CaseCandidate) -> tuple[str, OracleWitness | None]:
        nonlocal calls
        candidate_issues = _candidate_issues(candidate, task, source, evidence)
        if candidate_issues:
            issues.extend(candidate_issues)
            return "untestable", None
        if candidate.case.case_sha256 in seen:
            return "duplicate", None
        seen.add(candidate.case.case_sha256)
        try:
            if input_only_guard and not _guard(claim, _bindings(candidate.inputs, "input")):
                return "guard_false", None
        except (Untestable, ValueError) as error:
            issues.append(str(error))
            return "untestable", None
        calls += 1
        try:
            witness = oracle(candidate)
            if not isinstance(witness, OracleWitness):
                issues.append("typed_oracle_witness_required")
                return "untestable", None
            witness_issues = _witness_issues(witness, candidate, task, evidence, source)
            if witness_issues:
                issues.extend(witness_issues)
                return "untestable", None
        except Exception:
            # Exception messages may contain provider data; never treat faults as outputs.
            issues.append("oracle_callback_failed")
            return "untestable", None
        result = evaluate_claim(claim, candidate.inputs, witness.outputs)
        issues.extend(result.issues)
        return result.status, witness

    for candidate in ordered:
        if calls >= MAX_ORACLE_CASES:
            break
        status, witness = observe(candidate)
        if status == "violated" and witness is not None:
            counterexample = ClaimCounterexample(candidate=candidate, witness=witness)
            break
        if status == "satisfied" and witness is not None:
            support.append(witness)
            boundary = boundary or candidate.boundary

    if (counterexample is not None and minimizer is not None
            and proposals < MAX_PROPOSALS and calls < MAX_ORACLE_CASES):
        try:
            smaller = minimizer(counterexample.candidate)
            for candidate in islice(smaller, MAX_PROPOSALS - proposals):
                proposals += 1
                if calls >= MAX_ORACLE_CASES:
                    break
                # Reject foreign partitions before deciding whether a case is smaller.
                candidate_issues = _candidate_issues(candidate, task, source, evidence)
                if candidate_issues:
                    issues.extend(candidate_issues)
                    break
                if _size(candidate) >= _size(counterexample.candidate):
                    continue
                status, witness = observe(candidate)
                if status == "violated" and witness is not None:
                    counterexample = ClaimCounterexample(
                        candidate=candidate, witness=witness, minimization="best_found",
                    )
        except Exception:
            issues.append("minimizer_callback_failed")

    unique_issues = tuple(dict.fromkeys(issues))
    if counterexample is not None:
        status = "refuted"
    elif support and len(support) >= 10 and boundary and not issues:
        status = "supported_on_N"
    elif issues:
        status = "untestable"
    else:
        status = "pending"
        unique_issues = ("finite_search_insufficient_support",) if support else ("no_observed_satisfying_cases",)
    return ClaimResult(
        claim_id=claim.claim_id, status=status,
        evidence_mode="actual" if support or counterexample is not None else "not_run",
        supported_cases=len(support), oracle_calls=calls, proposals=proposals,
        boundary_observed=boundary, witnesses=tuple(support),
        counterexample=counterexample, issues=unique_issues,
    )
