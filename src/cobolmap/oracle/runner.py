"""Future authenticated isolated-boundary orchestration, never a host executor."""
from typing import Annotated, Literal, Protocol, Self
from pydantic import Field, model_validator
from cobolmap.contracts import (
    ArtifactRef, EvidenceBinding, ExecutionObservation, FrozenModel, ObservedFile,
    Identifier, OrdinaryObservation, Outcome, Sha256,
)
from .isolation import BackendConformance
from .pins import exact
from .requests import CandidateRequest, ExecutionPlan, OracleRequest, prepare_request

Flag = Literal["cpu", "wall", "memory", "pids", "scratch", "output", "forbidden", "import", "signal"]


class PhaseResult(FrozenModel):
    phase: Literal["compile", "run"]
    outcome: Outcome
    output: ObservedFile
    stdout: Annotated[bytes, Field(max_length=1048576)]
    stderr: Annotated[bytes, Field(max_length=1048576)]
    return_code: Annotated[int, Field(ge=-255, le=255)]
    cpu_microseconds: Annotated[int, Field(ge=0)]
    wall_microseconds: Annotated[int, Field(ge=0)]
    flags: Annotated[tuple[Flag, ...], Field(max_length=9)] = ()

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.outcome == "not_run" or len(set(self.flags)) != len(self.flags):
            raise ValueError("actual bounded phase result required")
        if self.output.data is not None and len(self.output.data) > 1048576:
            raise ValueError("backend must retain capped output and mark output cap")
        return self


class TraceNormalization(FrozenModel):
    raw_stderr: ArtifactRef
    framing: ArtifactRef
    receipt: ArtifactRef
    ordinary: OrdinaryObservation


class RawExecution(FrozenModel):
    plan_sha256: Sha256
    backend_id: Identifier
    execution_id: Identifier
    runtime_receipt: ArtifactRef
    phases: Annotated[tuple[PhaseResult, ...], Field(min_length=1, max_length=2)]
    normalization: TraceNormalization | None = None


class RunnerResult(FrozenModel):
    status: Literal["pending", "invalid", "observed"]
    plan: ExecutionPlan | None = None
    raw: RawExecution | None = None
    observation: ExecutionObservation | None = None
    issues: tuple[str, ...] = ()
    # No transport authority or reusable caller-controlled authorized flag.


class TrustedBackend(Protocol):
    def execute(self, plan: ExecutionPlan) -> RawExecution: ...


class ResultAuthority(Protocol):
    def verify_result(self, *, plan: ExecutionPlan, conformance: BackendConformance,
                      result: RawExecution) -> None: ...
    def verify_trace(self, *, plan: ExecutionPlan, result: RawExecution,
                     normalization: TraceNormalization) -> None: ...


class PreparationAuthority(ResultAuthority, Protocol):
    """Externally designated dev/probe permission, not P2 study admission."""
    def verify_preparation(self, *, plan: ExecutionPlan,
                           conformance: BackendConformance) -> None: ...


class StudyAuthority(ResultAuthority, Protocol):
    """Externally designated P2/admission and candidate-containment authority."""
    def verify_study(self, *, plan: ExecutionPlan,
                     conformance: BackendConformance) -> None: ...


def _verified(result) -> None:
    if result is not None:
        raise ValueError("authority must raise on rejection and return exactly None")


def _phase_fault(phase: PhaseResult, plan: ExecutionPlan) -> str | None:
    flags = set(phase.flags)
    if len(phase.stdout) + len(phase.stderr) + len(phase.output.data or b"") > plan.policy.output_bytes:
        flags.add("output")
    if phase.wall_microseconds > plan.policy.wall_microseconds:
        flags.add("wall")
    if phase.cpu_microseconds > plan.policy.cpu_microseconds:
        flags.add("cpu")
    if "forbidden" in flags:
        return "forbidden"
    if "import" in flags:
        return "import_violation"
    if "output" in flags:
        return "output_cap"
    if "wall" in flags or "cpu" in flags:
        return "timeout"
    if flags - {"signal"}:
        return "resource_cap"
    if "signal" in flags or phase.return_code < 0:
        return "crash"
    if phase.outcome not in {"completed", "handled"}:
        return phase.outcome
    return None


def _assemble(plan: ExecutionPlan, raw: RawExecution, authority) -> ExecutionObservation:
    request = plan.request
    phases = raw.phases
    if plan.role == "oracle":
        if phases[0].phase != "compile":
            raise ValueError("oracle must retain compiler phase first")
        compile_failed = (_phase_fault(phases[0], plan) is not None
                          or phases[0].return_code != 0)
        if compile_failed:
            if len(phases) != 1:
                raise ValueError("run after failed compilation is invalid")
        elif len(phases) != 2 or phases[1].phase != "run":
            raise ValueError("successful compilation requires actual run phase")
    elif len(phases) != 1 or phases[0].phase != "run":
        raise ValueError("candidate receives run phase only")
    else:
        compile_failed = False
    phase = phases[-1]
    fault = _phase_fault(phase, plan)
    if (sum(p.cpu_microseconds for p in phases) > plan.policy.cpu_microseconds
            or sum(p.wall_microseconds for p in phases) > plan.policy.wall_microseconds):
        fault = fault or "timeout"
    if sum(len(p.stdout) + len(p.stderr) + len(p.output.data or b"") for p in phases) > plan.policy.output_bytes:
        fault = fault or "output_cap"
    if compile_failed:
        fault = "infra_invalid"
    if phase.return_code not in request.allowed_return_codes:
        fault = fault or "crash"
    # Oracle/compiler faults are instrument-invalid, never a candidate failure.
    outcome = "infra_invalid" if plan.role == "oracle" and fault else fault
    ordinary = None
    trace_ref = None
    is_trace = type(request) is OracleRequest and request.trace
    if raw.normalization is not None and not is_trace:
        raise ValueError("normalization supplied for non-trace request")
    if not fault:
        ordinary = OrdinaryObservation(output=phase.output, stdout=phase.stdout,
                                       stderr=phase.stderr, return_code=phase.return_code)
        if is_trace:
            normalized = raw.normalization
            if normalized is None or normalized.framing != request.toolchain.trace_framing:
                raise ValueError("approved trace framing/normalization required")
            normalized.raw_stderr.check_bytes(phase.stderr)
            if (normalized.ordinary.output != phase.output
                    or normalized.ordinary.stdout != phase.stdout
                    or normalized.ordinary.return_code != phase.return_code):
                raise ValueError("trace normalization changed non-trace channels")
            if (len(normalized.ordinary.stderr) + len(normalized.ordinary.stdout)
                    + len(normalized.ordinary.output.data or b"") > plan.policy.output_bytes):
                raise ValueError("normalized ordinary channels exceed output cap")
            _verified(authority.verify_trace(plan=plan, result=raw, normalization=normalized))
            ordinary, trace_ref = normalized.ordinary, normalized.raw_stderr
        outcome = "completed" if ordinary.return_code == 0 else "handled"
    return ExecutionObservation(
        task_id=request.task.task_id, program_id=request.task.program_id,
        source_sha256=request.task.original.sha256, case_sha256=request.case.case_sha256,
        candidate_sha256=request.candidate.ref.sha256 if type(request) is CandidateRequest else None,
        ordinary=ordinary, outcome=outcome, allowed_return_codes=request.allowed_return_codes,
        evidence=EvidenceBinding(mode="actual", runtime_receipt=raw.runtime_receipt,
            pins=request.toolchain.pins,
            admission_authority=request.authorization if request.purpose == "study" else None),
        trace_artifact=trace_ref)


def run_request(request: OracleRequest | CandidateRequest, *, backend: TrustedBackend | None = None,
                conformance: BackendConformance | None = None,
                preparation_authority: PreparationAuthority | None = None,
                study_authority: StudyAuthority | None = None) -> RunnerResult:
    """Future boundary only. No backend/authority implementation is shipped.

    Trusted control plane must authenticate the injected authority itself and its
    conformance/receipt validation. A None-returning arbitrary object is no proof.
    """
    plan = None
    raw = None
    try:
        plan = prepare_request(request)
        if backend is None or conformance is None:
            return RunnerResult(status="pending", plan=plan, issues=("backend_conformance_missing",))
        conformance = exact(conformance, BackendConformance)
        from cobolmap.contracts import canonical_json, sha256
        if (conformance.role != plan.role
                or conformance.image_sha256 != plan.request.toolchain.pins.image_sha256
                or conformance.policy_sha256 != sha256(canonical_json(plan.policy))):
            raise ValueError("unsupported/mismatched backend conformance")
        if (plan.role == "candidate" and plan.request.purpose == "study"
                and conformance.hostile_fixture_receipt is None):
            raise ValueError("study candidate requires authenticated hostile-fixture conformance")
        authority = preparation_authority if plan.request.purpose == "preparation" else study_authority
        if authority is None:
            return RunnerResult(status="pending", plan=plan, issues=("purpose_authority_missing",))
        if plan.request.purpose == "preparation":
            _verified(authority.verify_preparation(plan=plan, conformance=conformance))
        else:
            _verified(authority.verify_study(plan=plan, conformance=conformance))
        received = backend.execute(plan)
        # Retain a structurally valid raw record even if later binding/auth fails.
        raw = exact(received, RawExecution)
        if raw.plan_sha256 != plan.plan_sha256 or raw.backend_id != conformance.backend_id:
            raise ValueError("backend result belongs to different request/backend")
        _verified(authority.verify_result(plan=plan, conformance=conformance, result=raw))
        observation = _assemble(plan, raw, authority)
        return RunnerResult(status="observed", plan=plan, raw=raw, observation=observation)
    except Exception as error:
        # No exception message forwarding: backend diagnostics can contain secrets.
        return RunnerResult(status="invalid", plan=plan, raw=raw,
                            issues=("boundary_refused:" + type(error).__name__,))


class ConsistencyReport(FrozenModel):
    status: Literal["pending", "invalid", "consistent"]
    records: tuple[RunnerResult, ...]
    issues: tuple[str, ...]


class ConsistencyAuthority(Protocol):
    """Authenticate all retained runtime/trace records and their designated authority."""
    def verify_records(self, *, records: tuple[RunnerResult, ...]) -> None: ...


def check_consistency(records: tuple[RunnerResult, ...], *,
                      authority: ConsistencyAuthority | None = None) -> ConsistencyReport:
    """Retain every measurement. Never compare changed source to original as equal."""
    if type(records) is not tuple or len(records) > 4096:
        raise ValueError("bounded tuple of retained runner results required")
    retained = tuple(exact(record, RunnerResult) for record in records)
    issues = []
    groups = {}
    executions = set()
    receipts = set()
    for index, record in enumerate(retained):
        observation, plan = record.observation, record.plan
        if (record.status != "observed" or record.issues or observation is None or plan is None
                or record.raw is None or plan.role != "oracle"
                or observation.outcome not in {"completed", "handled"}
                or observation.ordinary is None):
            issues.append(f"quarantined:{index}")
            continue
        # Rebind structure to canonical plan, never substitute a candidate outcome.
        expected = prepare_request(plan.request)
        if (plan != expected or record.raw.plan_sha256 != plan.plan_sha256
                or observation.task_id != plan.request.task.task_id
                or observation.program_id != plan.request.task.program_id
                or observation.source_sha256 != plan.request.task.original.sha256
                or observation.case_sha256 != plan.request.case.case_sha256
                or observation.candidate_sha256 is not None
                or observation.evidence.pins != plan.request.toolchain.pins
                or observation.evidence.mode != "actual"
                or observation.evidence.admission_authority != (
                    plan.request.authorization if plan.request.purpose == "study" else None)
                or observation.evidence.runtime_receipt != record.raw.runtime_receipt):
            issues.append(f"binding_invalid:{index}")
            continue
        identity = (record.raw.backend_id, record.raw.execution_id)
        receipt = record.raw.runtime_receipt.sha256
        if identity in executions or receipt in receipts:
            issues.append(f"duplicate_execution:{index}")
            continue
        executions.add(identity)
        receipts.add(receipt)
        key = (plan.request.task, plan.request.case.case_sha256,
               plan.request.purpose, plan.request.authorization)
        groups.setdefault(key, []).append((index, record))
    for group in groups.values():
        first = group[0][1]
        untraced = sum(not record.plan.request.trace for _, record in group)
        if untraced < 2:
            issues.append(f"repeat_untraced_missing:{group[0][0]}")
        for index, record in group[1:]:
            if (record.observation.ordinary != first.observation.ordinary
                    or record.observation.allowed_return_codes != first.observation.allowed_return_codes
                    or record.plan.request.toolchain.pins != first.plan.request.toolchain.pins):
                issues.append(f"ordinary_or_pin_mismatch:{index}")
    if issues:
        return ConsistencyReport(status="invalid", records=retained, issues=tuple(issues))
    if not groups or authority is None:
        return ConsistencyReport(status="pending", records=retained,
                                 issues=("consistency_authority_or_records_missing",))
    try:
        _verified(authority.verify_records(records=retained))
    except Exception as error:
        return ConsistencyReport(status="invalid", records=retained,
                                 issues=("consistency_auth_refused:" + type(error).__name__,))
    return ConsistencyReport(status="consistent", records=retained, issues=())
