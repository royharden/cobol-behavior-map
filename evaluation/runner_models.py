"""DEV-only fixture control declarations, never efficacy/billing observations."""
from dataclasses import dataclass
from typing import Literal
from cobolmap.contracts import (CandidateAttempt, CounterexampleFeedback, CountOnlyFeedback,
                                InitialFeedback, RunResult, TaskBinding)
from cobolmap.providers import LeakagePolicy, ProviderRequest, ProviderResult, ScriptedMock
from cobolmap.providers.adapters import PayloadFormat, PreparedPayload
from .schedule import CallSlot, SampleState
from .prereg import PreregReport


@dataclass(frozen=True)
class FixtureCallPlan:
    slot: CallSlot
    policy: LeakagePolicy
    format: PayloadFormat


@dataclass(frozen=True)
class FixtureLoopControl:
    """Caller-authored simulated count, NEVER an actual oracle measurement."""
    arm: Literal["C", "D", "R"]
    attempt: int
    candidate_sha256: str | None
    failures: int | None
    counterexample: CounterexampleFeedback | None = None
    count_only: CountOnlyFeedback | None = None


@dataclass(frozen=True)
class DevFixtureInput:
    task: TaskBinding
    model_slot: Literal["primary", "replication"]
    calls: tuple[FixtureCallPlan, ...]
    initial_b: InitialFeedback
    initial_c: InitialFeedback
    loop_hashes: frozenset[str]
    controls: tuple[FixtureLoopControl, ...]
    mock: ScriptedMock
    construction_exposure: Literal["private_source_before_admission"] = "private_source_before_admission"


@dataclass(frozen=True)
class FixtureCallTrace:
    call_id: str
    arm: str
    attempt: int
    request_sha256: str
    control_payload_sha256: str
    result: ProviderResult
    candidate: CandidateAttempt


@dataclass(frozen=True)
class FixtureControlTrace:
    task_id: str
    model_slot: str
    status: Literal["blocked", "partial", "control_complete"]
    calls: tuple[FixtureCallTrace, ...] = ()
    repair_states: tuple[SampleState, ...] = ()
    shared_c_inheritance: tuple[tuple[str, str], ...] = ()
    next_mock: ScriptedMock | None = None
    issues: tuple[str, ...] = ()
    evidence_mode: Literal["fixture"] = "fixture"
    processing_mode: Literal["dev_fixture_control"] = "dev_fixture_control"
    count_provenance: Literal["caller_scripted_control_not_measurement"] = "caller_scripted_control_not_measurement"
    construction_exposure: Literal["private_source_before_admission"] = "private_source_before_admission"
    dispatch_allowed: Literal[False] = False
    actual_efficacy: None = None
    actual_cost_usd: None = None
    study_complete: Literal[False] = False


@dataclass(frozen=True)
class ArmPreparation:
    status: Literal["blocked", "prepared"]
    request: ProviderRequest | None = None
    payload: PreparedPayload | None = None
    issues: tuple[str, ...] = ()
    control_payload_sha256: str | None = None


@dataclass(frozen=True)
class BlockedStudyReport:
    result: RunResult
    preregistration: PreregReport | None
    dispatch_allowed: Literal[False] = False
    backend_status: Literal["backend_unverified"] = "backend_unverified"
