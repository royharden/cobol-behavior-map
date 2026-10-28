"""Loop-only reduction data/protocols; hashes/booleans are not authenticity."""
from dataclasses import dataclass
from typing import Protocol

from cobolmap.contracts import ArtifactRef, CaseBundle, ExecutionObservation, ExecutionPins, MapField


@dataclass(frozen=True)
class ObservationPair:
    oracle: ExecutionObservation
    candidate: ExecutionObservation


@dataclass(frozen=True)
class LoopContext:
    task_id: str
    program_id: str
    source: bytes
    source_sha256: str
    candidate_sha256: str
    original_loop_hashes: frozenset[str]
    input_fields: tuple[MapField, ...]
    output_fields: tuple[MapField, ...] = ()
    oracle_pins: ExecutionPins | None = None
    candidate_pins: ExecutionPins | None = None
    admission_authority: ArtifactRef | None = None
    callback_authority: ArtifactRef | None = None
    admitted: bool = False
    trusted_loop_context: bool = False
    trusted_callback: bool = False
    partition: str = "loop"

    def __post_init__(self):
        if type(self.source) is not bytes:
            raise TypeError("Exact source bytes required")
        object.__setattr__(self, "original_loop_hashes", frozenset(self.original_loop_hashes))
        object.__setattr__(self, "input_fields", tuple(self.input_fields))
        object.__setattr__(self, "output_fields", tuple(self.output_fields))


class BoundedMismatchOracle(Protocol):
    """Future isolated adapter must actually enforce the supplied remaining bound.

    hard_timeout is an externally authenticated capability, not a self-grant.
    This package never launches an oracle/candidate or provides an adapter.
    """
    hard_timeout: bool

    def evaluate(self, case: CaseBundle, *, timeout_seconds: float,
                 context: LoopContext) -> ObservationPair: ...


@dataclass(frozen=True)
class ReductionStep:
    parent_case_sha256: str
    derivative_case_sha256: str
    reason: str
    witness: ObservationPair


@dataclass(frozen=True)
class ReductionResult:
    status: str
    origin_case_sha256: str | None = None
    case: CaseBundle | None = None
    witness: ObservationPair | None = None
    lineage: tuple[ReductionStep, ...] = ()
    proposals: int = 0
    callback_calls: int = 0
    elapsed_seconds: float = 0.0
    issues: tuple[str, ...] = ()
    minimization: str = "not_run"
    outbound_feedback_compatible: bool = False
    universal_minimum: bool = False

    def __post_init__(self):
        object.__setattr__(self, "lineage", tuple(self.lineage))
        object.__setattr__(self, "issues", tuple(self.issues))
        if self.outbound_feedback_compatible is not False or self.universal_minimum is not False:
            raise ValueError("No feedback compatibility or universal minimum is established")

    @property
    def derivative_case_sha256(self) -> str | None:
        return self.case.case_sha256 if self.case is not None else None

    def feedback_payload(self):
        """Local witnesses/lineage may not be put on the model feedback wire."""
        raise ValueError("derivative_feedback_pending: local lineage stays off wire")
