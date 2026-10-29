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


def _retained_pair(pair: ObservationPair, case_sha256: str | None) -> tuple:
    """Check local structure, without authenticating observations or execution."""
    if type(pair) is not ObservationPair:
        raise TypeError("Exact retained observation pair required")
    for observation in (pair.oracle, pair.candidate):
        if type(observation) is not ExecutionObservation:
            raise TypeError("Exact retained execution observation required")
        ExecutionObservation.model_validate(observation.model_dump())
        if observation.case_sha256 != case_sha256:
            raise ValueError("Retained observation case hash mismatch")
    if ((pair.oracle.task_id, pair.oracle.program_id, pair.oracle.source_sha256)
            != (pair.candidate.task_id, pair.candidate.program_id,
                pair.candidate.source_sha256)):
        raise ValueError("Retained observation scope mismatch")
    return tuple((observation.task_id, observation.program_id,
                  observation.source_sha256, observation.candidate_sha256,
                  observation.evidence.pins, observation.evidence.admission_authority,
                  observation.allowed_return_codes)
                 for observation in (pair.oracle, pair.candidate))


def _retained_case(case: CaseBundle, case_sha256: str | None) -> None:
    if type(case) is not CaseBundle:
        raise TypeError("Exact retained case bundle required")
    CaseBundle.model_validate(case.model_dump())
    if case.case_sha256 != case_sha256:
        raise ValueError("Retained case hash mismatch")


@dataclass(frozen=True)
class ReductionStep:
    """Local retained bytes; absent case fields provide no derivation proof."""
    parent_case_sha256: str
    derivative_case_sha256: str
    reason: str
    witness: ObservationPair
    parent_case: CaseBundle | None = None
    derivative_case: CaseBundle | None = None

    def __post_init__(self):
        if self.parent_case_sha256 == self.derivative_case_sha256:
            raise ValueError("Retained reduction must change the case hash")
        if self.parent_case is not None:
            _retained_case(self.parent_case, self.parent_case_sha256)
        if self.derivative_case is not None:
            _retained_case(self.derivative_case, self.derivative_case_sha256)
        _retained_pair(self.witness, self.derivative_case_sha256)


@dataclass(frozen=True)
class ReductionResult:
    """Local custody and structural consistency never authenticate execution."""
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
    origin_case: CaseBundle | None = None
    origin_witness: ObservationPair | None = None

    def __post_init__(self):
        object.__setattr__(self, "lineage", tuple(self.lineage))
        object.__setattr__(self, "issues", tuple(self.issues))
        if self.outbound_feedback_compatible is not False or self.universal_minimum is not False:
            raise ValueError("No feedback compatibility or universal minimum is established")
        if self.origin_case is not None:
            _retained_case(self.origin_case, self.origin_case_sha256)
        scope = None
        if self.origin_witness is not None:
            scope = _retained_pair(self.origin_witness, self.origin_case_sha256)
        if self.case is not None:
            _retained_case(self.case, self.case.case_sha256)
        if self.witness is not None:
            if self.case is None:
                raise ValueError("Final witness requires its case")
            final_scope = _retained_pair(self.witness, self.case.case_sha256)
            if scope is not None and final_scope != scope:
                raise ValueError("Final witness scope differs from the origin")
            scope = final_scope
        if len(self.lineage) > 100:
            raise ValueError("Retained lineage exceeds proposal bound")
        parent_hash, parent_case = self.origin_case_sha256, self.origin_case
        seen = {parent_hash}
        for step in self.lineage:
            if type(step) is not ReductionStep:
                raise TypeError("Exact retained reduction step required")
            if step.parent_case_sha256 != parent_hash:
                raise ValueError("Retained lineage is not contiguous with its origin")
            if step.derivative_case_sha256 in seen:
                raise ValueError("Retained lineage repeats a case hash")
            if (parent_case is not None and step.parent_case is not None
                    and step.parent_case != parent_case):
                raise ValueError("Retained parent bytes differ from previous case")
            step_scope = _retained_pair(step.witness, step.derivative_case_sha256)
            if scope is not None and step_scope != scope:
                raise ValueError("Retained witness scope differs from the result")
            scope = step_scope
            seen.add(step.derivative_case_sha256)
            parent_hash, parent_case = step.derivative_case_sha256, step.derivative_case
        if self.lineage:
            last = self.lineage[-1]
            if self.case is None or self.case.case_sha256 != parent_hash:
                raise ValueError("Final case is not the last retained derivative")
            if parent_case is not None and self.case != parent_case:
                raise ValueError("Final bytes differ from the last retained derivative")
            if self.witness != last.witness:
                raise ValueError("Final witness is not the last retained witness")
        elif self.case is not None:
            if self.origin_case_sha256 is not None and self.case.case_sha256 != self.origin_case_sha256:
                raise ValueError("Changed final case requires retained lineage")
            if self.origin_case is not None and self.case != self.origin_case:
                raise ValueError("Unchanged final bytes differ from the origin")
            if self.origin_witness is not None and self.witness != self.origin_witness:
                raise ValueError("Unchanged final witness differs from the origin")

    @property
    def derivative_case_sha256(self) -> str | None:
        return self.case.case_sha256 if self.case is not None else None

    def feedback_payload(self):
        """Local witnesses/lineage may not be put on the model feedback wire."""
        raise ValueError("derivative_feedback_pending: local lineage stays off wire")
