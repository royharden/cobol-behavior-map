"""Fail-closed loop reduction source; runtime and compiler parity are unverified.

Admission, callback identity, isolation and hard interruption belong to an external
trusted adapter. The monotonic clock here only cooperates with that adapter; it
cannot interrupt a blocking Python call. No default execution adapter is supplied.
"""
import re
import time

from cobolmap.contracts import (
    ArtifactRef, CaseBundle, ExecutionObservation, ExecutionPins, MapField, sha256,
)
from cobolmap.diff.comparator import compare
from cobolmap.shared.codec import decode_record

from .minimize_fields import case_for, field_proposals, layout
from .minimize_models import (
    BoundedMismatchOracle, LoopContext, ObservationPair, ReductionResult, ReductionStep,
)


def _validated_case(case: CaseBundle) -> None:
    if not isinstance(case, CaseBundle):
        raise ValueError("case_bundle_required")
    CaseBundle.model_validate(case.model_dump())


def _validate_context(case: CaseBundle, context: LoopContext) -> tuple:
    if not isinstance(context, LoopContext):
        raise ValueError("loop_context_required")
    if (context.admitted is not True or context.trusted_loop_context is not True
            or context.trusted_callback is not True or context.partition != "loop"):
        raise ValueError("externally_trusted_loop_context_required")
    if (not isinstance(context.original_loop_hashes, frozenset)
            or len(context.original_loop_hashes) != 32
            or any(not isinstance(h, str) or re.fullmatch(r"[0-9a-f]{64}", h) is None
                   for h in context.original_loop_hashes)):
        raise ValueError("exact_32_original_loop_hashes_required")
    if case.case_sha256 not in context.original_loop_hashes:
        raise ValueError("origin_not_in_original_loop_partition")
    if type(context.source) is not bytes or sha256(context.source) != context.source_sha256:
        raise ValueError("raw_source_hash_mismatch")
    if (not isinstance(context.candidate_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", context.candidate_sha256) is None):
        raise ValueError("candidate_hash_required")
    if (context.oracle_pins is None or context.candidate_pins is None
            or context.admission_authority is None or context.callback_authority is None):
        raise ValueError("expected_pin_pair_and_external_authorities_required")
    for pin in (context.oracle_pins, context.candidate_pins):
        if not isinstance(pin, ExecutionPins):
            raise ValueError("execution_pins_required")
        ExecutionPins.model_validate(pin.model_dump())
    for authority in (context.admission_authority, context.callback_authority):
        if not isinstance(authority, ArtifactRef):
            raise ValueError("authority_artifact_reference_required")
        ArtifactRef.model_validate(authority.model_dump())
    filenames = set()
    for field in context.input_fields + context.output_fields:
        if not isinstance(field, MapField):
            raise ValueError("declared_map_field_required")
        MapField.model_validate(field.model_dump())
        field.span.resolve(context.source)
        filenames.add(field.span.filename)
    if len(filenames) != 1 or any(f.storage != "output" for f in context.output_fields):
        raise ValueError("consistent_input_output_pointers_required")
    specs = layout(context.input_fields)
    for record in case.records:
        decode_record(record, specs)
    return specs


def _comparison(pair: ObservationPair, case: CaseBundle, context: LoopContext):
    if not isinstance(pair, ObservationPair):
        raise ValueError("callback_observation_pair_required")
    for role, observation, pins, candidate in (
            ("oracle", pair.oracle, context.oracle_pins, None),
            ("candidate", pair.candidate, context.candidate_pins, context.candidate_sha256)):
        if not isinstance(observation, ExecutionObservation):
            raise ValueError(f"{role}:execution_observation_required")
        ExecutionObservation.model_validate(observation.model_dump())
        if (observation.task_id != context.task_id or observation.program_id != context.program_id
                or observation.source_sha256 != context.source_sha256
                or observation.case_sha256 != case.case_sha256
                or observation.candidate_sha256 != candidate):
            raise ValueError(f"{role}:observation_binding_mismatch")
        if (observation.evidence.pins != pins
                or observation.evidence.admission_authority != context.admission_authority):
            raise ValueError(f"{role}:expected_pins_or_authority_mismatch")
    return compare(pair.oracle, pair.candidate, admitted=True, fields=context.output_fields)


def _criterion(pair: ObservationPair, difference):
    """Keep full raw channels for unknown/heuristic class suggestions."""
    left, right = pair.oracle.ordinary, pair.candidate.ordinary
    if left is None or right is None:
        raise ValueError("ordinary_payload_required")
    channel = difference.channel
    if channel == "output_presence":
        return left.output.present, right.output.present
    if channel == "output":
        return left.output.data, right.output.data
    if channel == "return_code":
        return left.return_code, right.return_code
    if channel in ("stdout", "stderr"):
        return getattr(left, channel), getattr(right, channel)
    raise ValueError("ordinary_mismatch_channel_required")


def _preserves(baseline: ObservationPair, baseline_diff, pair: ObservationPair, result) -> bool:
    if result.status != "mismatch":
        return False
    for original in baseline_diff.differences:
        matches = [d for d in result.differences
                   if (d.channel, d.classification, d.field_name) ==
                   (original.channel, original.classification, original.field_name)]
        if not matches:
            return False
        if (original.basis == "byte_heuristic" or original.classification == "unknown"):
            if _criterion(pair, original) != _criterion(baseline, original):
                return False
    return True


def minimize_loop(case: CaseBundle, baseline: ObservationPair | None = None,
                  callback: BoundedMismatchOracle | None = None, *,
                  context: LoopContext | None = None, max_proposals=100,
                  timeout_seconds=10.0) -> ReductionResult:
    """Return an actual-grounded best found case, or pending/not_run without calls.

    At most 100 derivative proposals (including duplicates) and ten cooperative
    seconds are available, including validation. Every retained step carries the actual
    derivative witness. Sealed origin membership is never extended to derivatives.
    Outbound feedback remains blocked pending adoption of the derivative seam.
    """
    started = time.monotonic()
    issues = ["outbound_feedback_pending_derivative_seam"]
    origin = case.case_sha256 if isinstance(case, CaseBundle) else None

    def pending(issue):
        return ReductionResult(status="pending", origin_case_sha256=origin,
                               issues=tuple(issues + [issue]), minimization="not_run",
                               elapsed_seconds=time.monotonic() - started)

    if (type(max_proposals) is not int or max_proposals < 0
            or type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds <= 10):
        return pending("invalid_reduction_bounds")
    limit = min(max_proposals, 100)
    deadline = started + min(float(timeout_seconds), 10.0)
    if baseline is None or context is None or callback is None:
        return pending("baseline_context_and_bounded_callback_required")
    try:
        _validated_case(case)
        specs = _validate_context(case, context)
        if getattr(callback, "hard_timeout", False) is not True or not callable(
                getattr(callback, "evaluate", None)):
            return pending("externally_trusted_hard_timeout_callback_required")
        baseline_diff = _comparison(baseline, case, context)
        if baseline_diff.status != "mismatch":
            return pending("actual_ordinary_baseline_mismatch_required")
    except Exception as exc:
        return pending(f"baseline_or_context_refused:{type(exc).__name__}:{exc}")

    best, witness = case, baseline
    lineage: list[ReductionStep] = []
    seen = {origin}
    proposals = calls = 0
    stopped = time.monotonic() >= deadline
    if stopped:
        issues.append("cooperative_deadline_reached")

    def keepgoing() -> bool:
        nonlocal stopped
        if stopped:
            return False
        if time.monotonic() >= deadline:
            if "cooperative_deadline_reached" not in issues:
                issues.append("cooperative_deadline_reached")
            stopped = True
            return False
        return True

    def permit_proposal() -> bool:
        nonlocal proposals, stopped
        if not keepgoing():
            return False
        if proposals >= limit:
            issues.append("proposal_limit_reached")
            stopped = True
            return False
        proposals += 1
        return True

    def attempt(proposal: CaseBundle, reason: str) -> bool:
        nonlocal best, witness, calls, stopped
        # Check time even for repeated hashes: duplicates consume proposal budget
        # and cannot bypass the cooperative deadline.
        if not keepgoing() or proposal.case_sha256 in seen:
            return False
        seen.add(proposal.case_sha256)
        try:
            _validated_case(proposal)
            if (proposal.input_present != case.input_present
                    or (bool(case.records) and not 1 <= len(proposal.records) <= 64)):
                raise ValueError("input_scenario_changed")
            for record in proposal.records:
                decode_record(record, specs)
            if getattr(callback, "hard_timeout", False) is not True:
                raise ValueError("hard_timeout_capability_withdrawn")
            evaluate = callback.evaluate
            if not callable(evaluate):
                raise ValueError("callback_evaluate_unavailable")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                issues.append("cooperative_deadline_reached")
                stopped = True
                return False
            calls += 1
            pair = evaluate(proposal, timeout_seconds=remaining, context=context)
            if time.monotonic() >= deadline:
                issues.append("late_callback_response_rejected")
                stopped = True
                return False
            result = _comparison(pair, proposal, context)
            if (pair.oracle.allowed_return_codes != baseline.oracle.allowed_return_codes
                    or pair.candidate.allowed_return_codes != baseline.candidate.allowed_return_codes):
                raise ValueError("callback_changed_declared_return_codes")
            if result.status not in ("match", "mismatch"):
                raise ValueError(f"ordinary_callback_evidence_required:{result.status}")
            if not _preserves(baseline, baseline_diff, pair, result):
                return False
            if not keepgoing():
                return False
            lineage.append(ReductionStep(best.case_sha256, proposal.case_sha256, reason, pair))
            best, witness = proposal, pair
            return True
        except Exception as exc:
            issues.append(f"callback_or_proposal_refused:{type(exc).__name__}:{exc}")
            stopped = True
            return False

    # ddmin removes contiguous ranges while retaining order and one nonempty
    # record. Missing-file and present-empty origins propose no fabricated bytes.
    granularity = 2
    while len(best.records) > 1 and not stopped:
        width = (len(best.records) + granularity - 1) // granularity
        reduced = False
        for start in range(0, len(best.records), width):
            if not keepgoing():
                break
            records = best.records[:start] + best.records[start + width:]
            if not records:
                continue
            if not permit_proposal():
                break
            if attempt(case_for(records, input_present=best.input_present),
                       "ordered_contiguous_record_removal"):
                granularity = max(2, granularity - 1)
                reduced = True
                break
            if stopped:
                break
        if not reduced:
            if granularity >= len(best.records):
                break
            granularity = min(len(best.records), granularity * 2)
    changed = True
    while changed and not stopped:
        changed = False
        for proposal in field_proposals(best, specs, permit=permit_proposal, keepgoing=keepgoing):
            if attempt(proposal, "declared_field_simplification"):
                changed = True
                break
            if stopped:
                break
    if time.monotonic() >= deadline and "cooperative_deadline_reached" not in issues:
        issues.append("cooperative_deadline_reached")
    return ReductionResult(status="best_found", origin_case_sha256=origin,
                           case=best, witness=witness, lineage=tuple(lineage),
                           proposals=proposals, callback_calls=calls,
                           elapsed_seconds=time.monotonic() - started,
                           issues=tuple(issues), minimization="best_found")
