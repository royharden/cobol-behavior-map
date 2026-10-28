"""Evidence declarations are integrity-bearing data, never authenticated facts."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from .base import ArtifactRef, FrozenModel, Identifier, Sha256, canonical_json, sha256

EvidenceMode = Literal["not_run", "static", "fixture", "actual"]
Outcome = Literal["not_run", "completed", "handled", "crash", "timeout", "forbidden",
                  "import_violation", "output_cap", "resource_cap", "infra_invalid"]
DivergenceClass = Literal["record_count", "padding", "sign", "scale", "last_place/truncation",
                          "last_place/rounding", "size_error", "value", "alpha", "unknown"]


class ExecutionPins(FrozenModel):
    compiler_version: str
    compiler_sha256: Sha256
    compiler_config_sha256: Sha256
    runtime_config_sha256: Sha256
    image_sha256: Sha256
    libcob_sha256: Sha256
    default_conf_sha256: Sha256
    generator_sha256: Sha256
    shim_sha256: Sha256


class EvidenceBinding(FrozenModel):
    mode: EvidenceMode = "not_run"
    runtime_receipt: ArtifactRef | None = None
    pins: ExecutionPins | None = None
    admission_authority: ArtifactRef | None = None

    def missing_actual(self) -> tuple[str, ...]:
        missing = []
        if self.mode != "actual": missing.append("actual_mode_required")
        if self.runtime_receipt is None: missing.append("runtime_receipt_missing")
        if self.pins is None: missing.append("execution_pins_missing")
        if self.admission_authority is None: missing.append("admission_authority_missing")
        return tuple(missing)


class CaseBundle(FrozenModel):
    input_present: bool
    records: Annotated[tuple[bytes, ...], Field(max_length=64)]
    case_sha256: Sha256

    @model_validator(mode="after")
    def bind_bytes(self) -> Self:
        if not self.input_present and self.records:
            raise ValueError("missing input cannot have records")
        if any(not r or len(r) > 8192 for r in self.records):
            raise ValueError("case record bounds")
        if any(any(b < 32 or b > 126 for b in r) for r in self.records):
            raise ValueError("external records require printable ASCII without LF/CR framing bytes")
        preimage = b"M10-CASE-v1\0" + bytes([self.input_present]) + len(self.records).to_bytes(4, "big")
        preimage += b"".join(len(r).to_bytes(4, "big") + r for r in self.records)
        if sha256(preimage) != self.case_sha256:
            raise ValueError("case byte hash mismatch")
        return self

    def file_bytes(self) -> bytes | None:
        return b"".join(r + b"\n" for r in self.records) if self.input_present else None


class ObservedFile(FrozenModel):
    present: bool
    data: bytes | None

    @model_validator(mode="after")
    def presence(self) -> Self:
        if self.present != (self.data is not None):
            raise ValueError("absent file has no bytes; present-empty has b''")
        return self


class OrdinaryObservation(FrozenModel):
    output: ObservedFile
    stdout: bytes
    stderr: bytes
    return_code: Annotated[int, Field(ge=0, le=255)]

    def byte_digest(self) -> str:
        return sha256(canonical_json(self))


class ExecutionObservation(FrozenModel):
    task_id: Identifier
    program_id: Identifier
    source_sha256: Sha256
    case_sha256: Sha256
    candidate_sha256: Sha256 | None = None
    ordinary: OrdinaryObservation | None = None
    outcome: Outcome = "not_run"
    allowed_return_codes: tuple[Annotated[int, Field(ge=0, le=255)], ...] = (0,)
    evidence: EvidenceBinding = Field(default_factory=EvidenceBinding)
    trace_artifact: ArtifactRef | None = None

    @model_validator(mode="after")
    def completed_payload(self) -> Self:
        if len(set(self.allowed_return_codes)) != len(self.allowed_return_codes) or not self.allowed_return_codes:
            raise ValueError("declared return codes must be nonempty and unique")
        if self.outcome in ("completed", "handled"):
            if self.ordinary is None or self.ordinary.return_code not in self.allowed_return_codes:
                raise ValueError("completed/handled outcome requires declared ordinary return")
        return self


class ByteDifference(FrozenModel):
    channel: Literal["output_presence", "output", "stdout", "stderr", "return_code", "context", "outcome"]
    classification: DivergenceClass = "unknown"
    first_offset: Annotated[int, Field(ge=0)] | None = None
    field_name: str | None = None
    expected_sha256: Sha256 | None = None
    actual_sha256: Sha256 | None = None
    expected_bytes: bytes | None = None
    actual_bytes: bytes | None = None
    detail: str = ""
    basis: Literal["structural", "byte_heuristic"] = "structural"


class ComparisonResult(FrozenModel):
    status: Literal["pending", "match", "mismatch", "infra_invalid", "candidate_failure"] = "pending"
    equal: bool | None = None
    differences: tuple[ByteDifference, ...] = ()
    issues: tuple[str, ...] = ()

    @model_validator(mode="after")
    def no_implicit_pass(self) -> Self:
        if (self.status == "match") != (self.equal is True):
            raise ValueError("only explicit match may have equal=True")
        if self.status == "match" and (self.issues or self.differences):
            raise ValueError("match cannot contain missing evidence or differences")
        return self
