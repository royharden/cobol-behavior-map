"""Public product model facade. All construction remains runtime-unverified."""
from .base import (ArtifactRef, DecimalText, FrozenModel, Identifier, Sha256,
                   SourcePointer, canonical_json, sha256)
from .claim_models import (Claim, ClaimValue, FieldComparison, FieldRef, FieldValue,
                           LinearTerm, LinearValue, LiteralValue, OutputEquality, ScalarOperand)
from .maps import BehaviorMap, ControlEdge, Effect, Hazard, HazardId, MapField, MapParagraph
from .evidence import (ByteDifference, CaseBundle, ComparisonResult, DivergenceClass,
                       EvidenceBinding, EvidenceMode, ExecutionObservation, ExecutionPins,
                       ObservedFile, OrdinaryObservation, Outcome)
from .study import (Arm, CandidateAttempt, CounterexampleFeedback, CountOnlyFeedback,
                    FeedbackContext, FeedbackPacket, InitialFeedback, LoopWitness,
                    ProgramManifest, RunPlan, RunResult, TaskBinding)
from .feedback import feedback_json

__all__ = [
    "ArtifactRef", "DecimalText", "FrozenModel", "Identifier", "Sha256", "SourcePointer",
    "canonical_json", "sha256", "Claim", "ClaimValue", "FieldComparison", "FieldRef",
    "FieldValue", "LinearTerm", "LinearValue", "LiteralValue", "OutputEquality", "ScalarOperand",
    "BehaviorMap", "ControlEdge", "Effect", "Hazard", "HazardId", "MapField", "MapParagraph",
    "ByteDifference", "CaseBundle", "ComparisonResult", "DivergenceClass", "EvidenceBinding",
    "EvidenceMode", "ExecutionObservation", "ExecutionPins", "ObservedFile", "OrdinaryObservation",
    "Outcome", "Arm", "CandidateAttempt", "CounterexampleFeedback", "CountOnlyFeedback",
    "FeedbackContext", "FeedbackPacket", "InitialFeedback", "LoopWitness", "ProgramManifest",
    "RunPlan", "RunResult", "TaskBinding", "feedback_json",
]
