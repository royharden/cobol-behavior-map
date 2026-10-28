"""Untrusted guest-frame decoding; no execution, observation or authority."""
import json
import re
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from cobolmap.contracts import FrozenModel, Identifier, Sha256, canonical_json, sha256
from .pins import SDK_PATHS, exact

NATIVE_CAP = 1048576
CONTROL_CAP = 2 * NATIVE_CAP + 8192
TransportFlag = Literal["cpu", "wall", "memory", "pids", "scratch", "output", "forbidden", "import", "signal"]


class CandidateTransportSpec(FrozenModel):
    abi: Literal["m10-run-case-v1"] = "m10-run-case-v1"
    control_fd: Literal[3] = 3
    framing: Literal["canonical-ascii-json-eof"] = "canonical-ascii-json-eof"
    control_capture_bytes: Literal[2105344] = CONTROL_CAP
    logical_ordinary_bytes: Literal[1048576] = NATIVE_CAP
    physical_policy_bytes: Literal[1048576] = NATIVE_CAP
    collect_physical_stdout: Literal[True] = True
    collect_physical_stderr: Literal[True] = True
    collect_process_resources: Literal[True] = True
    output_accounting: Literal["unresolved_native_cap"] = "unresolved_native_cap"


class ControlCapture(FrozenModel):
    data: Annotated[bytes, Field(max_length=CONTROL_CAP)]
    observed_bytes: Annotated[int, Field(ge=0)]
    truncated: bool = False
    complete: bool = True

    @model_validator(mode="after")
    def counts(self) -> Self:
        if self.observed_bytes < len(self.data) or (not self.truncated and self.observed_bytes != len(self.data)):
            raise ValueError("captured bytes/count/truncation mismatch")
        return self


class PhysicalCapture(ControlCapture):
    data: Annotated[bytes, Field(max_length=NATIVE_CAP)]


class CandidateSidecar(FrozenModel):
    plan_sha256: Sha256
    backend_id: Identifier
    execution_id: Identifier
    control: ControlCapture
    physical_stdout: PhysicalCapture
    physical_stderr: PhysicalCapture
    process_return_code: Annotated[int, Field(ge=-255, le=255)] | None
    signal: Annotated[int, Field(ge=1, le=64)] | None = None
    cpu_microseconds: Annotated[int, Field(ge=0)] | None
    wall_microseconds: Annotated[int, Field(ge=0)] | None
    backend_outcome: Literal["completed", "handled", "crash", "timeout", "forbidden",
                             "import_violation", "output_cap", "resource_cap", "infra_invalid"]
    flags: Annotated[tuple[TransportFlag, ...], Field(max_length=9)] = ()

    @model_validator(mode="after")
    def unique_flags(self) -> Self:
        if len(self.flags) != len(set(self.flags)):
            raise ValueError("duplicate backend resource flags")
        return self


class StagedTransportPin(FrozenModel):
    path: str
    sha256: Sha256
    byte_length: Annotated[int, Field(ge=1, le=1048576)]


class CandidateTransportExpectation(FrozenModel):
    plan_sha256: Sha256
    case_sha256: Sha256
    candidate_sha256: Sha256
    staged: Annotated[tuple[StagedTransportPin, ...], Field(min_length=8, max_length=8)]
    allowed_return_codes: Annotated[tuple[Annotated[int, Field(ge=0, le=255)], ...], Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def closed_scope(self) -> Self:
        if len({pin.path for pin in self.staged}) != 8 or {pin.path for pin in self.staged} != SDK_PATHS:
            raise ValueError("exact eight-file staged closure required")
        if tuple(sorted(set(self.allowed_return_codes))) != self.allowed_return_codes or self.allowed_return_codes[0] != 0:
            raise ValueError("sorted unique native return declaration required")
        return self


class LogicalOrdinary(FrozenModel):
    output_present: bool
    output_bytes: bytes | None
    stdout: bytes
    stderr: bytes
    return_code: Annotated[int, Field(ge=0, le=255)]

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.output_present != (self.output_bytes is not None):
            raise ValueError("logical output presence mismatch")
        if len(self.output_bytes or b"") + len(self.stdout) + len(self.stderr) > NATIVE_CAP:
            raise ValueError("logical ordinary aggregate cap")
        return self


class TransportDecode(FrozenModel):
    status: Literal["decoded", "fault", "rejected"]
    sidecar: CandidateSidecar | None = None
    expected: CandidateTransportExpectation | None = None
    guest_status: Literal["returned", "candidate_fault", "adapter_fault"] | None = None
    guest_fault: str | None = None
    logical: LogicalOrdinary | None = None
    retained_control_sha256: Sha256 | None = None
    decoded_logical_sha256: Sha256 | None = None
    sidecar_sha256: Sha256 | None = None
    issues: tuple[str, ...] = ()
    conformance_gap: Literal["candidate_control_capture_policy_unresolved"] = "candidate_control_capture_policy_unresolved"
    evidence_mode: Literal["not_run"] = "not_run"


def capture_control(raw: bytes, *, complete: bool = True) -> ControlCapture:
    if type(raw) is not bytes or type(complete) is not bool:
        raise TypeError("exact raw capture bytes/EOF fact required")
    return ControlCapture(data=raw[:CONTROL_CAP], observed_bytes=len(raw),
                          truncated=len(raw) > CONTROL_CAP, complete=complete)


def capture_physical(raw: bytes, *, complete: bool = True) -> PhysicalCapture:
    if type(raw) is not bytes or type(complete) is not bool:
        raise TypeError("exact physical capture bytes/EOF fact required")
    return PhysicalCapture(data=raw[:NATIVE_CAP], observed_bytes=len(raw),
                           truncated=len(raw) > NATIVE_CAP, complete=complete)


class _FrameRefusal(ValueError):
    pass


def _need(condition, reason):
    if not condition:
        raise _FrameRefusal(reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate_frame_key")
        result[key] = value
    return result


def _integer(text):
    _need(re.fullmatch(r"-?[0-9]{1,20}", text) is not None, "frame_integer_limit")
    return int(text)


def _no_float(_text):
    raise _FrameRefusal("frame_float_or_constant")


def _json(raw):
    text = raw.decode("ascii")
    quoted = escaped = False
    depth = count = 0
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            _need(depth <= 4, "frame_depth")
        elif character in "]}":
            depth -= 1
            _need(depth >= 0, "frame_depth")
        elif character in ",:":
            count += 1
            _need(count <= 4096, "frame_item_limit")
    _need(depth == 0 and not quoted, "partial_frame")
    value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                       parse_float=_no_float, parse_constant=_no_float)
    _need(_canonical(value) == raw, "noncanonical_or_trailing_frame")
    return value


def _hex(value):
    _need(type(value) is str and len(value) <= 2 * NATIVE_CAP and len(value) % 2 == 0
          and re.fullmatch(r"[0-9a-f]*", value) is not None, "logical_hex")
    return bytes.fromhex(value)


def _frame(value, expected):
    keys = {"abi", "status", "fault", "case_sha256", "candidate_sha256", "staged", "ordinary",
            "semantics", "runtime_verified"}
    _need(type(value) is dict and set(value) == keys, "frame_keys")
    _need(value["abi"] == "m10-run-case-v1" and value["semantics"] == "construction_hypothesis"
          and value["runtime_verified"] is False, "frame_markers")
    status, fault = value["status"], value["fault"]
    _need(type(status) is str and status in {"returned", "candidate_fault", "adapter_fault"}, "guest_status")
    faults = {"candidate_fault": {"candidate_load", "candidate_exception", "runtime_fault", "output_cap", "invalid_candidate_return"},
              "adapter_fault": {"adapter_setup", "case_protocol", "staging", "sdk_load"}}
    _need((status == "returned" and fault is None) or
          (status != "returned" and type(fault) is str and fault in faults[status]), "guest_fault")
    for key, wanted in (("case_sha256", expected.case_sha256), ("candidate_sha256", expected.candidate_sha256)):
        _need((status == "adapter_fault" and value[key] is None) or value[key] == wanted, "guest_scope_pin")
    staged = value["staged"]
    pins = {pin.path: {"sha256": pin.sha256, "byte_length": pin.byte_length} for pin in expected.staged}
    _need(type(staged) is dict and set(staged) <= set(pins)
          and (status == "adapter_fault" or set(staged) == set(pins)), "staged_closure")
    for name, pin in staged.items():
        _need(type(pin) is dict and set(pin) == {"sha256", "byte_length"}
              and type(pin["sha256"]) is str and type(pin["byte_length"]) is int
              and pin == pins[name], "staged_pin")
    if status != "returned":
        _need(value["ordinary"] is None, "fault_has_ordinary")
        return status, fault, None
    ordinary = value["ordinary"]
    _need(type(ordinary) is dict and set(ordinary) == {"output", "stdout", "stderr", "return_code"}, "ordinary_keys")
    output = ordinary["output"]
    _need(type(output) is dict and set(output) == {"present", "data"}
          and type(output["present"]) is bool, "logical_presence")
    if output["present"]:
        data = _hex(output["data"])
    else:
        _need(output["data"] is None, "logical_presence")
        data = None
    _need(type(ordinary["return_code"]) is int and 0 <= ordinary["return_code"] <= 255, "logical_return_type")
    stdout, stderr = _hex(ordinary["stdout"]), _hex(ordinary["stderr"])
    _need(len(data or b"") + len(stdout) + len(stderr) <= NATIVE_CAP, "logical_ordinary_cap")
    return status, None, LogicalOrdinary(output_present=output["present"], output_bytes=data,
        stdout=stdout, stderr=stderr, return_code=ordinary["return_code"])


def decode_candidate_transport(sidecar: CandidateSidecar, *, expected: CandidateTransportExpectation) -> TransportDecode:
    """Pure untrusted decode only. Raw facts never come from guest JSON."""
    retained = scope = logical = guest_status = guest_fault = None
    issues = []
    try:
        retained = exact(sidecar, CandidateSidecar)
        scope = exact(expected, CandidateTransportExpectation)
    except Exception:
        return TransportDecode(status="rejected", sidecar=retained, issues=("transport_dto_invalid",))
    if retained.plan_sha256 != scope.plan_sha256:
        issues.append("sidecar_plan_pin")
    for label, capture in (("control", retained.control), ("stdout", retained.physical_stdout), ("stderr", retained.physical_stderr)):
        if capture.truncated:
            issues.append(label + "_capture_truncated")
        if not capture.complete:
            issues.append(label + "_capture_incomplete")
    physical_count = (retained.control.observed_bytes + retained.physical_stdout.observed_bytes
                      + retained.physical_stderr.observed_bytes)
    if physical_count > NATIVE_CAP:
        issues.append("native_physical_output_budget_exceeded")
    if retained.flags or retained.signal is not None or retained.backend_outcome != "completed":
        issues.append("backend_fault_facts")
    if retained.cpu_microseconds is None or retained.wall_microseconds is None:
        issues.append("resource_measurement_missing")
    elif retained.cpu_microseconds > 5000000 or retained.wall_microseconds > 10000000:
        issues.append("backend_time_budget_exceeded")
    try:
        _need(bool(retained.control.data), "missing_control_frame")
        value = _json(retained.control.data)
        guest_status, guest_fault, logical = _frame(value, scope)
        wanted_exit = {"returned": 0, "candidate_fault": 2, "adapter_fault": 3}[guest_status]
        if guest_status == "returned" and (retained.physical_stdout.observed_bytes or retained.physical_stderr.observed_bytes):
            issues.append("unexpected_physical_channels")
        if retained.process_return_code != wanted_exit:
            issues.append("physical_process_exit_mismatch")
        if logical is not None and logical.return_code not in scope.allowed_return_codes:
            issues.append("logical_return_undeclared")
    except _FrameRefusal as error:
        issues.append(str(error))  # Adapter-owned fixed code, never a foreign exception.
    except (ValueError, TypeError, UnicodeError, RecursionError):
        issues.append("malformed_control_frame")
    return TransportDecode(status="rejected" if issues else "decoded" if logical is not None else "fault",
        sidecar=retained, expected=scope, guest_status=guest_status, guest_fault=guest_fault,
        logical=logical, retained_control_sha256=sha256(retained.control.data),
        decoded_logical_sha256=sha256(canonical_json(logical)) if logical is not None else None,
        sidecar_sha256=sha256(canonical_json(retained)), issues=tuple(issues))
