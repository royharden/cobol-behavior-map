"""Pure schedule and candidate-selection transitions, never provider execution."""
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Literal

from cobolmap.contracts import CandidateAttempt, RunPlan, TaskBinding


class ScheduleError(ValueError):
    pass


@dataclass(frozen=True)
class CallSlot:
    call_id: str
    task_id: str
    model_slot: Literal['primary', 'replication']
    model_id: str | None
    arm: str
    attempt: int
    shared_c_call_id: str | None = None
    sample: int = 1


@dataclass(frozen=True)
class Schedule:
    tasks: tuple[TaskBinding, ...]
    calls: tuple[CallSlot, ...]
    smoke_slots: tuple[str, str]
    maximum_calls: int = 1346
    dispatch_allowed: bool = False


def validate_tasks(tasks: tuple[TaskBinding, ...]) -> None:
    if len(tasks) != 84 or len({t.task_id for t in tasks}) != 84:
        raise ScheduleError('full unique 48 dev / 36 heldout task frame required')
    for split, programs in (('dev', 4), ('heldout', 3)):
        subset = [t for t in tasks if t.split == split]
        families = {t.family_id for t in subset}
        if len(families) != 6:
            raise ScheduleError('six precommitted families per split required')
        for family in families:
            members = [t for t in subset if t.family_id == family]
            by_panel = [{t.program_id for t in members if t.panel == p}
                        for p in ('unchanged', 'change')]
            if by_panel[0] != by_panel[1] or len(by_panel[0]) != programs:
                raise ScheduleError('paired panels must cover every family program')
            if len(members) != programs * 2:
                raise ScheduleError('duplicate family/program/panel')
    dev = {t.program_id for t in tasks if t.split == 'dev'}
    held = {t.program_id for t in tasks if t.split == 'heldout'}
    if dev & held:
        raise ScheduleError('program crosses split')
    for split in ('dev', 'heldout'):
        ids = [t.program_id for t in tasks if t.split == split and t.panel == 'unchanged']
        if len(ids) != len(set(ids)):
            raise ScheduleError('program reused across families')


def build_schedule(plan: RunPlan) -> Schedule:
    """Describe every maximum paid slot; empty approved model slots stay empty."""
    validate_tasks(plan.tasks)
    if plan.maximum_calls != 1346 or plan.max_input_tokens != 6000 or plan.max_output_tokens != 2500:
        raise ScheduleError('study caps are immutable')
    if len(plan.model_ids) not in (0, 2) or (plan.model_ids and
            (len(set(plan.model_ids)) != 2 or any(not m.strip() for m in plan.model_ids))):
        raise ScheduleError('zero pending or two distinct declared model IDs required')
    def identity(task: str, model_slot: str, arm: str, attempt: int) -> str:
        # Length framing prevents delimiter collisions in arbitrary identifiers.
        fields = (plan.run_id, task, model_slot, arm, str(attempt))
        raw = b''.join(len(f.encode()).to_bytes(4, 'big') + f.encode() for f in fields)
        return sha256(raw).hexdigest()
    calls = []
    for task in sorted(plan.tasks, key=lambda t: t.task_id):
        for index, model_slot in enumerate(('primary', 'replication')):
            model = plan.model_ids[index] if plan.model_ids else None
            shared = identity(task.task_id, model_slot, 'C', 0)
            for arm, attempts in (('B', (0,)), ('C', (0,)), ('D', (1, 2, 3)), ('R', (1, 2, 3))):
                for attempt in attempts:
                    calls.append(CallSlot(identity(task.task_id, model_slot, arm, attempt),
                                          task.task_id, model_slot, model, arm, attempt,
                                          shared if arm in ('D', 'R') else None))
    smoke = tuple(identity('smoke', slot, 'B', 0) for slot in ('primary', 'replication'))
    return Schedule(plan.tasks, tuple(calls), smoke)


@dataclass(frozen=True)
class SampleState:
    task_id: str
    arm: Literal['D', 'R']
    shared_c: CandidateAttempt
    attempts: tuple[CandidateAttempt, ...] = ()
    loop_failures: tuple[int | None, ...] = ()
    stopped: str | None = None
    verification_disclosed: bool = False

    @property
    def selected(self) -> CandidateAttempt:
        return self.attempts[-1] if self.attempts else self.shared_c


def fork_shared_c(candidate: CandidateAttempt) -> tuple[SampleState, SampleState]:
    if candidate.arm != 'C' or candidate.attempt != 0 or not candidate.call_id or candidate.status == 'not_run':
        raise ScheduleError('exact initial C attempt/call identity required, including refusals')
    return tuple(SampleState(candidate.task_id, arm, candidate) for arm in ('D', 'R'))


def record_loop(state: SampleState, failures: int | None) -> SampleState:
    """Record trusted loop-only measurement; missing measurement halts as unavailable."""
    if state.verification_disclosed or state.stopped or len(state.loop_failures) != len(state.attempts):
        raise ScheduleError('loop transition out of order or selection closed')
    if failures is not None and (type(failures) is not int or not 0 <= failures <= 32):
        raise ScheduleError('loop failure count outside 0..32')
    if failures == 0 and state.selected.status != 'generated':
        raise ScheduleError('refused/invalid candidate cannot pass the loop')
    stop = 'measurement_unavailable' if failures is None else 'loop_pass' if failures == 0 else None
    if len(state.attempts) == 3 and stop is None:
        stop = 'maximum_repairs'
    return replace(state, loop_failures=state.loop_failures + (failures,), stopped=stop)


def append_repair(state: SampleState, candidate: CandidateAttempt) -> SampleState:
    if state.verification_disclosed or state.stopped or len(state.loop_failures) != len(state.attempts) + 1:
        raise ScheduleError('repair requires measured failed loop and open selection')
    number = len(state.attempts) + 1
    if number > 3 or candidate.arm != state.arm or candidate.task_id != state.task_id or candidate.attempt != number:
        raise ScheduleError('repair task/arm/attempt drift')
    if (candidate.shared_c_call_id != state.shared_c.call_id or not candidate.call_id
            or candidate.model_id != state.shared_c.model_id
            or candidate.call_id in {a.call_id for a in (state.shared_c,) + state.attempts}):
        raise ScheduleError('shared C/model/call identity drift or replay')
    if candidate.status == 'not_run':
        raise ScheduleError('missing provider attempt cannot become a repair result')
    prior = (state.shared_c,) + state.attempts
    repeat = candidate.candidate_sha256 is not None and any(
        a.candidate_sha256 == candidate.candidate_sha256 for a in prior)
    return replace(state, attempts=state.attempts + (candidate,), stopped='repeated_candidate' if repeat else None)


def disclose_verification(state: SampleState) -> SampleState:
    if state.verification_disclosed or state.stopped is None:
        raise ScheduleError('select using loop policy before one-shot verification')
    return replace(state, verification_disclosed=True)
