"""Normalized trace declarations; none authenticates its own provenance.

An admitted caller must authenticate every observation, normalization receipt,
and framing approval outside this package. No raw compiler format is defined.
"""
from typing import Literal, Protocol

from cobolmap.contracts import (
    ArtifactRef, ExecutionObservation, ExecutionPins, FrozenModel, Identifier,
    Sha256, SourcePointer,
)
from cobolmap.parse.models import ProgramIR


class TraceEvent(FrozenModel):
    kind: Literal["paragraph", "statement"]
    paragraph: str
    pointer: SourcePointer


class TraceCase(FrozenModel):
    untraced: ExecutionObservation
    traced: ExecutionObservation
    events: tuple[TraceEvent, ...]
    raw_trace: bytes
    framing: ArtifactRef
    normalization_receipt: ArtifactRef
    statement_identity: bool = False


class TraceContext(FrozenModel):
    """Trusted control-plane input, never populated from trace/observation data.

    trusted_normalized asserts external authentication of each supplied receipt
    binding exact raw trace, framing, source, events and statement-identity flag.
    These switches do not implement authentication or confer admission.
    """
    task_id: Identifier
    program_id: Identifier
    # Entire expected scored-case scope, not merely the records supplied today.
    trusted_case_hashes: frozenset[Sha256]
    expected_untraced_pins: ExecutionPins | None = None
    expected_traced_pins: ExecutionPins | None = None
    admission_authority: ArtifactRef | None = None
    approved_framing: ArtifactRef | None = None
    admitted: bool = False
    trusted_context: bool = False
    trusted_normalized: bool = False


class CoverageResult(FrozenModel):
    status: Literal["not_run", "pending", "invalid", "complete"] = "not_run"
    evidence_mode: Literal["not_run", "actual"] = "not_run"
    paragraph_numerator: int | None = None
    paragraph_denominator: int | None = None
    statement_numerator: int | None = None
    statement_denominator: int | None = None
    paragraph_hits: tuple[str, ...] = ()
    unreached_paragraphs: tuple[str, ...] = ()
    statement_hits: tuple[SourcePointer, ...] = ()
    unreached_statements: tuple[SourcePointer, ...] = ()
    issues: tuple[str, ...] = ()


class TraceDecoder(Protocol):
    """Externally approved adapter; coverage never calls this protocol.

    A caller must authenticate framing/normalization and separate ordinary
    channels before constructing TraceCase. No stripping of stderr is implied.
    """

    def decode(self, raw_trace: bytes, *, framing: ArtifactRef,
               program: ProgramIR) -> tuple[TraceEvent, ...]: ...
