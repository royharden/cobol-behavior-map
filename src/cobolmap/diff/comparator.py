"""Exact observed-byte comparison; construction source remains runtime-unverified.

No IO, oracle invocation, candidate execution, or receipt authentication occurs here.
``admitted`` is a trusted caller's assertion that admission/authentication already
occurred outside this module. A true boolean and well-formed hashes prove nothing
on their own. Never expose this assertion directly to untrusted observation data.
"""
from typing import Literal

from ..contracts import (
    ByteDifference, ComparisonResult, DivergenceClass, ExecutionObservation,
    MapField, sha256,
)

_ORDINARY = frozenset({"completed", "handled"})
_CANDIDATE_FAILURES = frozenset({
    "crash", "timeout", "forbidden", "import_violation", "output_cap", "resource_cap",
})
_SHARED_PINS = (
    "compiler_version", "compiler_sha256", "compiler_config_sha256",
    "runtime_config_sha256", "libcob_sha256", "default_conf_sha256",
    "generator_sha256", "shim_sha256",
)


def _first_offset(expected: bytes, actual: bytes) -> int | None:
    for offset, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            return offset
    return min(len(expected), len(actual)) if len(expected) != len(actual) else None


def _field_at(raw: bytes, offset: int | None, fields: tuple[MapField, ...]) -> MapField | None:
    """Resolve only an unambiguous DISPLAY output span within its LF record."""
    if offset is None or offset >= len(raw) or raw[offset:offset + 1] == b"\n":
        return None
    record_start = raw.rfind(b"\n", 0, offset) + 1
    column = offset - record_start
    candidates = [field for field in fields
                  if field.storage == "output" and field.usage == "DISPLAY"
                  and field.offset is not None
                  and field.offset <= column < field.offset + field.width]
    return candidates[0] if len(candidates) == 1 else None


def classify_bytes(expected: bytes, actual: bytes, *,
                   field: MapField | None = None) -> DivergenceClass:
    """Suggest a byte heuristic, never an established semantic cause.

    Layout-dependent numeric suggestions require the actual supplied field. This
    function cannot establish SIZE ERROR, rounding, or truncation from bytes alone.
    It does not determine comparison equality or normalize the compared payload.
    """
    if expected == actual:
        return "unknown"
    if expected.count(b"\n") != actual.count(b"\n"):
        return "record_count"
    if expected.strip(b" ") == actual.strip(b" "):
        return "padding"
    if field is None or field.usage != "DISPLAY":
        return "unknown"
    if field.digits == 0:
        return "alpha"
    if (field.sign == "leading_separate" and expected[:1] in (b"+", b"-")
            and actual[:1] in (b"+", b"-") and expected[1:] == actual[1:]):
        return "sign"
    # An explicit decimal-point displacement is only a scale *suggestion*.
    # Implied-decimal DISPLAY bytes alone cannot identify such a cause.
    if (field.scale > 0 and expected.count(b".") == actual.count(b".") == 1
            and expected.find(b".") != actual.find(b".")
            and expected.replace(b".", b"") == actual.replace(b".", b"")):
        return "scale"
    return "value"


def _byte_difference(channel: Literal["output", "stdout", "stderr"],
                     expected: bytes, actual: bytes,
                     fields: tuple[MapField, ...]) -> ByteDifference:
    offset = _first_offset(expected, actual)
    field = _field_at(expected, offset, fields) if channel == "output" else None
    expected_part, actual_part = expected, actual
    if field is not None and field.offset is not None and offset is not None:
        start = expected.rfind(b"\n", 0, offset) + 1 + field.offset
        # Use the corresponding actual record, not a byte position shifted by an
        # earlier length difference. A missing record leaves the heuristic unknown.
        record_index = expected[:offset].count(b"\n")
        actual_records = actual.split(b"\n")
        expected_part = expected[start:].split(b"\n", 1)[0][:field.width]
        actual_part = (actual_records[record_index][field.offset:field.offset + field.width]
                       if record_index < len(actual_records) else b"")
    classification = classify_bytes(expected, actual)
    if classification == "unknown" and field is not None:
        classification = classify_bytes(expected_part, actual_part, field=field)
    return ByteDifference(
        channel=channel, classification=classification, first_offset=offset,
        field_name=field.name if field else None,
        expected_sha256=sha256(expected), actual_sha256=sha256(actual),
        expected_bytes=expected, actual_bytes=actual,
        basis="byte_heuristic",
        detail="Exact byte mismatch; classification is a heuristic, not an established cause.",
    )


def compare(expected: ExecutionObservation, actual: ExecutionObservation, *,
            admitted: bool = False, fields: tuple[MapField, ...] = ()) -> ComparisonResult:
    """Compare externally admitted actual observations without byte normalization.

    Context/pin mismatch and incomplete evidence refuse comparison. Oracle faults
    invalidate the comparison, while candidate faults are candidate failures.
    Neither matching crashes nor undeclared returns can produce a match. Separate
    oracle/candidate image identities must exist but need not be equal.
    """
    issues: list[str] = []
    if admitted is not True:
        issues.append("external_admission_required")
    if expected.candidate_sha256 is not None:
        issues.append("expected:oracle_reference_required")
    if actual.candidate_sha256 is None:
        issues.append("actual:candidate_pin_missing")
    for role, observation in (("expected", expected), ("actual", actual)):
        issues.extend(f"{role}:{issue}" for issue in observation.evidence.missing_actual())
    for name in ("task_id", "program_id", "source_sha256", "case_sha256"):
        if getattr(expected, name) != getattr(actual, name):
            issues.append(f"context_mismatch:{name}")
    if expected.allowed_return_codes != actual.allowed_return_codes:
        issues.append("context_mismatch:allowed_return_codes")
    left_pins, right_pins = expected.evidence.pins, actual.evidence.pins
    if left_pins is not None and right_pins is not None:
        for name in _SHARED_PINS:
            if getattr(left_pins, name) != getattr(right_pins, name):
                issues.append(f"pin_mismatch:{name}")
        if not left_pins.compiler_version.strip() or not right_pins.compiler_version.strip():
            issues.append("compiler_version_missing")
    if any(field.span.source_sha256 != expected.source_sha256 for field in fields):
        issues.append("field_source_mismatch")
    if issues:
        return ComparisonResult(status="pending", issues=tuple(issues))

    if expected.outcome == "not_run":
        return ComparisonResult(status="pending", issues=("expected:not_run",))
    if expected.outcome not in _ORDINARY:
        return ComparisonResult(status="infra_invalid", issues=(f"expected:{expected.outcome}",))
    if expected.ordinary is None:
        return ComparisonResult(status="infra_invalid", issues=("expected:ordinary_payload_missing",))
    if expected.ordinary.return_code not in expected.allowed_return_codes:
        return ComparisonResult(status="infra_invalid", issues=("expected:undeclared_return",))
    if actual.outcome == "not_run":
        return ComparisonResult(status="pending", issues=("actual:not_run",))
    if actual.outcome == "infra_invalid":
        return ComparisonResult(status="infra_invalid", issues=("actual:infra_invalid",))
    if actual.outcome in _CANDIDATE_FAILURES:
        return ComparisonResult(status="candidate_failure", equal=False,
                                issues=(f"actual:{actual.outcome}",))
    if actual.ordinary is None or actual.outcome not in _ORDINARY:
        return ComparisonResult(status="candidate_failure", equal=False,
                                issues=("actual:ordinary_payload_missing",))
    if actual.ordinary.return_code not in actual.allowed_return_codes:
        return ComparisonResult(status="candidate_failure", equal=False,
                                issues=("actual:undeclared_return",))

    left, right = expected.ordinary, actual.ordinary
    differences: list[ByteDifference] = []
    if left.output.present != right.output.present:
        differences.append(ByteDifference(
            channel="output_presence", detail="Absent and present-empty outputs are distinct.",
            expected_sha256=sha256(left.output.data) if left.output.data is not None else None,
            actual_sha256=sha256(right.output.data) if right.output.data is not None else None,
            expected_bytes=left.output.data, actual_bytes=right.output.data,
        ))
    elif left.output.data is not None and right.output.data is not None:
        if left.output.data != right.output.data:
            differences.append(_byte_difference("output", left.output.data, right.output.data, fields))
    for channel in ("stdout", "stderr"):
        left_bytes, right_bytes = getattr(left, channel), getattr(right, channel)
        if left_bytes != right_bytes:
            differences.append(_byte_difference(channel, left_bytes, right_bytes, ()))
    if left.return_code != right.return_code:
        differences.append(ByteDifference(
            channel="return_code", detail=f"Expected {left.return_code}; actual {right.return_code}.",
        ))
    if differences:
        return ComparisonResult(status="mismatch", equal=False, differences=tuple(differences))
    return ComparisonResult(status="match", equal=True)
