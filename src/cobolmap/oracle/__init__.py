"""Admitted callback/provenance interfaces only; no execution backend supplied."""
from .minimize import minimize_loop
from .minimize_models import (
    BoundedMismatchOracle, LoopContext, ObservationPair, ReductionResult, ReductionStep,
)
from .trace import coverage
from .trace_models import CoverageResult, TraceCase, TraceContext, TraceDecoder, TraceEvent

__all__ = ["minimize_loop", "ObservationPair", "LoopContext", "BoundedMismatchOracle",
           "ReductionResult", "ReductionStep", "coverage", "TraceCase", "TraceContext",
           "TraceEvent", "TraceDecoder", "CoverageResult"]
