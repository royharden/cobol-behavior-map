"""Immutable claims inputs and future, explicitly admitted oracle interfaces."""
from typing import Annotated, Iterable, Literal, Protocol, Self

from pydantic import Field, model_validator

from cobolmap.contracts import (
    ArtifactRef, CaseBundle, ExecutionObservation, FieldRef, FrozenModel,
    Identifier, LiteralValue, MapField, Sha256,
)


class FieldBinding(FrozenModel):
    field: FieldRef
    value: LiteralValue


class CaseCandidate(FrozenModel):
    case: CaseBundle
    boundary: bool
    inputs: tuple[FieldBinding, ...]
    task_id: Identifier
    program_id: Identifier
    source_sha256: Sha256
    partition: Literal["dev", "heldout", "verification"]
    provenance: ArtifactRef
    trusted_decoded_inputs: bool = False
    input_decoding_authority: ArtifactRef | None = None
    input_layouts: tuple[MapField, ...] = ()


class FieldWitness(FrozenModel):
    """Explicit source-bound lexical text or external DISPLAY field observation."""
    binding: FieldBinding
    channel: Literal["output", "stdout", "stderr"]
    byte_start: Annotated[int, Field(ge=0)]
    byte_end: Annotated[int, Field(ge=0)]
    encoding: Literal["lexical_ascii", "display"]
    layout: MapField
    record_start: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def output_span(self) -> Self:
        if self.binding.field.scope != "output" or self.byte_end < self.byte_start:
            raise ValueError("output field and ordered observation span required")
        return self


class OracleWitness(FrozenModel):
    observation: ExecutionObservation
    outputs: tuple[FieldBinding, ...]
    fields: tuple[FieldWitness, ...]


class ClaimEvaluation(FrozenModel):
    """Static relation evaluation, never an execution or empirical claim."""
    status: Literal["satisfied", "violated", "guard_false", "untestable"]
    guard_satisfied: bool | None = None
    issues: tuple[str, ...] = ()


class ClaimCounterexample(FrozenModel):
    candidate: CaseCandidate
    witness: OracleWitness
    minimization: Literal["not_run", "best_found"] = "not_run"


class ClaimResult(FrozenModel):
    claim_id: Identifier
    status: Literal["not_run", "pending", "untestable", "supported_on_N", "refuted"]
    evidence_mode: Literal["not_run", "actual"] = "not_run"
    supported_cases: Annotated[int, Field(ge=0, le=50)] = 0
    oracle_calls: Annotated[int, Field(ge=0, le=50)] = 0
    proposals: Annotated[int, Field(ge=0, le=1000)] = 0
    boundary_observed: bool = False
    witnesses: tuple[OracleWitness, ...] = ()
    counterexample: ClaimCounterexample | None = None
    issues: tuple[str, ...] = ()
    universal_validity: Literal[False] = False

    @model_validator(mode="after")
    def empirical_status(self) -> Self:
        if self.status in ("supported_on_N", "refuted") and self.evidence_mode != "actual":
            raise ValueError("empirical claim requires actual evidence")
        if self.status == "supported_on_N" and (
            self.supported_cases < 10 or not self.boundary_observed or self.issues
            or self.counterexample is not None or len(self.witnesses) != self.supported_cases
        ):
            raise ValueError("finite support threshold/boundary/witness requirements")
        if (self.status == "refuted") != (self.counterexample is not None):
            raise ValueError("refutation requires explicit witnessed counterexample")
        return self


class Oracle(Protocol):
    """Future caller-supplied adapter; this package supplies no execution provider."""
    def __call__(self, candidate: CaseCandidate, /) -> OracleWitness: ...


class Minimizer(Protocol):
    """Propose smaller dev cases; search rechecks every proposal through the oracle."""
    def __call__(self, candidate: CaseCandidate, /) -> Iterable[CaseCandidate]: ...
