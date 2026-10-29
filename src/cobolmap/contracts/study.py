"""Task/study declarations: unsigned inputs do not authorize execution."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from .base import ArtifactRef, DecimalText, FrozenModel, Identifier, Sha256, SourcePointer, sha256
from .claim_models import Claim
from .evidence import CaseBundle, DivergenceClass, EvidenceMode, OrdinaryObservation
from .maps import BehaviorMap

Arm = Literal["A", "B", "C", "D", "R"]


class ProgramManifest(FrozenModel):
    program_id: Identifier
    family_id: Identifier
    split: Literal["dev", "heldout"]
    source: ArtifactRef
    input_fields: ArtifactRef
    output_fields: ArtifactRef
    allowed_return_codes: tuple[Annotated[int, Field(ge=0, le=255)], ...]
    provenance: ArtifactRef | None = None
    license_authority: ArtifactRef | None = None
    evidence_mode: EvidenceMode = "not_run"
    admission_status: Literal["pending"] = "pending"

    @model_validator(mode="after")
    def declared_codes(self) -> Self:
        if (not self.allowed_return_codes or self.allowed_return_codes[0] != 0
                or tuple(sorted(set(self.allowed_return_codes))) != self.allowed_return_codes):
            raise ValueError("return codes must be sorted unique including zero")
        return self


class TaskBinding(FrozenModel):
    task_id: Identifier
    program_id: Identifier
    family_id: Identifier
    split: Literal["dev", "heldout"]
    panel: Literal["unchanged", "change"]
    original: ArtifactRef
    oracle_source: ArtifactRef
    change: ArtifactRef | None = None
    paired_recipe_index: ArtifactRef | None = None

    @model_validator(mode="after")
    def panel_binding(self) -> Self:
        if self.panel == "unchanged" and (self.change is not None or self.original.sha256 != self.oracle_source.sha256):
            raise ValueError("unchanged source/edit binding")
        if self.panel == "change" and (self.change is None or self.original.sha256 == self.oracle_source.sha256):
            raise ValueError("changed task requires separate source and raw edit artifact")
        return self


class CandidateAttempt(FrozenModel):
    task_id: Identifier
    arm: Arm
    attempt: Annotated[int, Field(ge=0, le=3)]
    candidate_sha256: Sha256 | None = None
    code: str | None = None
    model_id: str | None = None
    call_id: str | None = None
    shared_c_call_id: str | None = None
    evidence_mode: EvidenceMode = "not_run"
    status: Literal["not_run", "generated", "refused", "invalid", "failed"] = "not_run"
    known_usd: DecimalText | None = None
    reserved_unknown_usd: DecimalText | None = None

    @model_validator(mode="after")
    def candidate_bytes(self) -> Self:
        if self.code is not None and (self.candidate_sha256 is None or sha256(self.code.encode("utf-8")) != self.candidate_sha256):
            raise ValueError("candidate text/hash mismatch")
        if self.status == "generated" and self.code is None:
            raise ValueError("generated status needs actual candidate text")
        if self.status == "not_run" and (self.known_usd is not None or self.reserved_unknown_usd is not None):
            raise ValueError("not_run candidate cannot have measured billing")
        if any(value is not None and value.startswith("-") for value in (self.known_usd, self.reserved_unknown_usd)):
            raise ValueError("negative candidate cost")
        if self.evidence_mode == "actual" and self.status == "generated" and self.arm != "A":
            if not self.model_id or not self.model_id.strip() or not self.call_id or not self.call_id.strip():
                raise ValueError("actual model candidate requires exact model/call identity")
        return self


class LoopWitness(FrozenModel):
    case_id: Identifier
    case: CaseBundle
    oracle: OrdinaryObservation
    candidate: OrdinaryObservation
    classification: DivergenceClass
    first_offset: Annotated[int, Field(ge=0)] | None = None
    field_name: str | None = None
    pointers: tuple[SourcePointer, ...] = ()
    minimization: Literal["not_run", "best_found"] = "not_run"

    @model_validator(mode="after")
    def actual_divergence(self) -> Self:
        if self.oracle == self.candidate:
            raise ValueError("equal ordinary observations are not a counterexample")
        return self


class FeedbackContext(FrozenModel):
    source_sha256: Sha256
    source_text: str
    shim_api: str
    request_text: str
    behavior_map: BehaviorMap | None = None
    previous_candidate: CandidateAttempt | None = None
    diagnostic: str | None = None

    @model_validator(mode="after")
    def source_binding(self) -> Self:
        if sha256(self.source_text.encode("utf-8")) != self.source_sha256:
            raise ValueError("feedback source hash mismatch")
        if self.behavior_map is not None and self.behavior_map.source_sha256 != self.source_sha256:
            raise ValueError("feedback map/source mismatch")
        return self


class CounterexampleFeedback(FrozenModel):
    kind: Literal["counterexample"] = "counterexample"
    task_id: Identifier
    arm: Literal["D"] = "D"
    attempt: Annotated[int, Field(ge=1, le=3)]
    context: FeedbackContext
    witness: LoopWitness | None = None

    @model_validator(mode="after")
    def repair_context(self) -> Self:
        previous = self.context.previous_candidate
        if self.context.behavior_map is None or previous is None:
            raise ValueError("D requires shared C context and previous attempt")
        if previous.task_id != self.task_id or previous.arm not in ("C", "D"):
            raise ValueError("D cannot receive another task/arm repair")
        if self.witness is None and (not self.context.diagnostic or previous.status not in ("invalid", "refused", "failed")):
            raise ValueError("D needs a real loop witness or an explicit failed-candidate diagnostic")
        return self

    def assert_loop_membership(self, loop_hashes: frozenset[str]) -> None:
        if self.witness is None:
            return
        if self.witness.case.case_sha256 not in loop_hashes:
            raise ValueError("feedback_case_not_in_loop")
        if any(p.source_sha256 != self.context.source_sha256 for p in self.witness.pointers):
            raise ValueError("feedback foreign source pointer")
        previous = self.context.previous_candidate
        if previous is not None and previous.task_id != self.task_id:
            raise ValueError("feedback foreign task candidate")
        if previous is not None and previous.arm not in ("C", "D"):
            raise ValueError("D cannot receive another arm's repair")


class CountOnlyFeedback(FrozenModel):
    kind: Literal["count_only"] = "count_only"
    task_id: Identifier
    arm: Literal["R"] = "R"
    attempt: Annotated[int, Field(ge=1, le=3)]
    context: FeedbackContext
    failed_cases: Annotated[int, Field(ge=0)]
    loop_cases: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def count_only(self) -> Self:
        if self.failed_cases > self.loop_cases:
            raise ValueError("feedback failure count exceeds loop size")
        previous = self.context.previous_candidate
        if previous is None or self.context.behavior_map is None:
            raise ValueError("R requires shared C context and previous attempt")
        if previous is not None and previous.task_id != self.task_id:
            raise ValueError("feedback foreign task candidate")
        if previous is not None and previous.arm not in ("C", "R"):
            raise ValueError("R cannot receive another arm's repair")
        return self


class InitialFeedback(FrozenModel):
    kind: Literal["initial"] = "initial"
    task_id: Identifier
    arm: Literal["B", "C"]
    context: FeedbackContext

    @model_validator(mode="after")
    def arm_context(self) -> Self:
        if self.context.previous_candidate is not None:
            raise ValueError("initial B/C context cannot contain repair history")
        if (self.arm == "B" and self.context.behavior_map is not None
                or self.arm == "C" and self.context.behavior_map is None):
            raise ValueError("B/C map-access contract")
        return self


FeedbackPacket = Annotated[InitialFeedback | CounterexampleFeedback | CountOnlyFeedback,
                           Field(discriminator="kind")]


class RunPlan(FrozenModel):
    run_id: Identifier
    mode: Literal["replay", "oracle", "live"] = "replay"
    tasks: tuple[TaskBinding, ...] = ()
    model_ids: tuple[str, ...] = ()
    pins: tuple[ArtifactRef, ...] = ()
    authorization: ArtifactRef | None = None
    go_record: ArtifactRef | None = None
    budget_authorization: ArtifactRef | None = None
    maximum_calls: Annotated[int, Field(ge=0, le=1346)] = 1346
    max_input_tokens: Annotated[int, Field(ge=1, le=6000)] = 6000
    max_output_tokens: Annotated[int, Field(ge=1, le=2500)] = 2500
    samples_per_task: Literal[1] = 1
    arms: tuple[Arm, ...] = ("A", "B", "C", "D", "R")
    construction_exposure: Literal["private_source_before_admission"] = "private_source_before_admission"

    @model_validator(mode="after")
    def unique_schedule(self) -> Self:
        if type(self.samples_per_task) is not int:
            raise ValueError("integer sample count required")
        if len({t.task_id for t in self.tasks}) != len(self.tasks):
            raise ValueError("duplicate task")
        if len(self.arms) != 5 or set(self.arms) != {"A", "B", "C", "D", "R"}:
            raise ValueError("required arms cannot be cut")
        return self

    def missing_authority(self) -> tuple[str, ...]:
        missing = []
        if not self.tasks: missing.append("task_schedule_missing")
        if not self.pins: missing.append("pins_missing")
        if self.authorization is None: missing.append("authorization_missing")
        if self.mode != "replay" and self.go_record is None: missing.append("p2_go_missing")
        if self.mode == "live":
            if len(set(self.model_ids)) != 2 or any(not m.strip() for m in self.model_ids): missing.append("two_exact_model_ids_required")
            if self.budget_authorization is None: missing.append("budget_authorization_missing")
        return tuple(missing)


class RunResult(FrozenModel):
    run_id: Identifier
    evidence_mode: EvidenceMode = "not_run"
    processing_mode: Literal["not_run", "replay", "oracle", "live"] = "not_run"
    status: Literal["not_run", "pending", "partial", "completed", "failed"] = "not_run"
    scheduled: Annotated[int, Field(ge=0)] | None = None
    passed: Annotated[int, Field(ge=0)] | None = None
    failed: Annotated[int, Field(ge=0)] | None = None
    refused: Annotated[int, Field(ge=0)] | None = None
    known_usd: DecimalText | None = None
    reserved_unknown_usd: DecimalText | None = None
    d_minus_c: DecimalText | None = None
    d_minus_r: DecimalText | None = None
    observations: tuple[ArtifactRef, ...] = ()
    issues: tuple[str, ...] = ()

    @model_validator(mode="after")
    def measured_result(self) -> Self:
        if self.status == "not_run" and any(x is not None for x in (self.passed, self.failed, self.refused,
                self.known_usd, self.reserved_unknown_usd, self.d_minus_c, self.d_minus_r)):
            raise ValueError("not_run metrics must be null")
        if self.status == "completed" and (not self.observations or self.evidence_mode not in ("actual", "fixture")):
            raise ValueError("completed result requires explicit observed evidence mode/references")
        if self.status == "completed" and any(x is None for x in (self.scheduled, self.passed, self.failed, self.refused)):
            raise ValueError("completed result requires explicit scheduled/outcome counts")
        if self.status == "completed" and self.passed + self.failed + self.refused != self.scheduled:
            raise ValueError("completed counts must account for all scheduled tasks")
        if any(value is not None and value.startswith("-") for value in (self.known_usd, self.reserved_unknown_usd)):
            raise ValueError("negative run cost")
        if self.scheduled is not None and all(x is not None for x in (self.passed, self.failed, self.refused)):
            if self.passed + self.failed + self.refused > self.scheduled:
                raise ValueError("result counts exceed schedule")
        return self
