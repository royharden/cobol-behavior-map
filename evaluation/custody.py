"""Validate future supplied custody metadata, never emit seals or appoint custodians."""
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re


@dataclass(frozen=True)
class CustodyEvent:
    sequence: int
    previous_sha256: str | None
    event_sha256: str
    commitment_sha256: str
    action: str
    task_id: str | None = None
    call_id: str | None = None
    candidate_sha256: str | None = None
    result: str | None = None
    candidate_independent_infra: bool = False


@dataclass(frozen=True)
class CustodyReport:
    state: str
    completed_tasks: tuple[str, ...]
    resumable_never_sent: tuple[str, ...]
    unresolved_sent: tuple[str, ...]
    head_sha256: str | None
    authenticity: str = 'unverified'
    dispatch_allowed: bool = False


def validate_chain(events: tuple[CustodyEvent, ...], *, commitment_sha256: str,
                   expected_tasks: tuple[str, ...]) -> CustodyReport:
    """A valid local chain proves consistency, never independent custody/authentication."""
    if re.fullmatch('[0-9a-f]{64}', commitment_sha256) is None:
        raise ValueError('exact commitment hash required')
    if not expected_tasks or len(set(expected_tasks)) != len(expected_tasks):
        raise ValueError('closed unique expected task frame required')
    phase, previous = 'unsealed', None
    calls, candidates, attempts, completed = {}, {}, {}, set()
    seen_hashes = set()
    expected = set(expected_tasks)
    for number, event in enumerate(events, 1):
        if type(event.sequence) is not int or event.sequence != number or event.previous_sha256 != previous:
            raise ValueError('custody reorder or missing predecessor')
        if event.commitment_sha256 != commitment_sha256 or event.event_sha256 in seen_hashes:
            raise ValueError('commit drift or duplicate event')
        data = asdict(event)
        del data['event_sha256']
        digest = sha256(json.dumps(data, sort_keys=True, separators=(',', ':'),
                                  ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        if event.event_sha256 != digest:
            raise ValueError('custody event hash mismatch')
        global_transition = {'sealed': ('unsealed', 'sealed'), 'scheduled': ('sealed', 'scheduled'),
                             'running': ('scheduled', 'running'), 'completed': ('running', 'completed')}
        if event.action in global_transition:
            before, after = global_transition[event.action]
            if (phase != before or any(v is not None for v in
                    (event.task_id, event.call_id, event.candidate_sha256, event.result))
                    or event.candidate_independent_infra):
                raise ValueError('invalid global custody transition')
            if after == 'completed' and (completed != expected or any(v in ('sent', 'unknown') for v in calls.values())):
                raise ValueError('incomplete task frame or unresolved send')
            phase = after
        elif event.action == 'burned':
            if phase in ('unsealed', 'burned') or any(v is not None for v in
                    (event.task_id, event.call_id, event.candidate_sha256, event.result)) or event.candidate_independent_infra:
                raise ValueError('invalid burn transition')
            phase = 'burned'
        else:
            if phase != 'running' or event.task_id not in expected or event.task_id in completed:
                raise ValueError('replayed task or task outside running committed frame')
            task = event.task_id
            if event.action in ('reserved', 'sent', 'unknown', 'settled', 'not_sent'):
                if task in candidates and event.action in ('reserved', 'sent'):
                    raise ValueError('verification disclosure permanently closes model generation')
                if not event.call_id or event.candidate_sha256 is not None or event.result is not None or event.candidate_independent_infra:
                    raise ValueError('closed call transition shape required')
                key = (task, event.call_id)
                if event.action == 'reserved':
                    if any(k[1] == event.call_id for k in calls) or any(v in ('sent', 'unknown') for v in calls.values()):
                        raise ValueError('call replay or unresolved send globally halts')
                    calls[key] = 'reserved'
                else:
                    prior = calls.get(key)
                    allowed = {'sent': ('reserved',), 'unknown': ('sent',),
                               'settled': ('sent', 'unknown'), 'not_sent': ('reserved',)}
                    if prior not in allowed[event.action] or (event.action == 'sent' and any(v in ('sent', 'unknown') for v in calls.values())):
                        raise ValueError('call is not eligible; sent/unknown IDs never resume')
                    calls[key] = event.action
            elif event.action == 'verification':
                if any(owner == task and state in ('sent', 'unknown') for (owner, _), state in calls.items()):
                    raise ValueError('resolve sent liability before task verification completes')
                if (event.call_id is not None or not event.candidate_sha256
                        or re.fullmatch('[0-9a-f]{64}', event.candidate_sha256) is None
                        or event.result not in ('valid', 'infra_invalid')):
                    raise ValueError('closed verification shape required')
                if task in candidates and candidates[task] != event.candidate_sha256:
                    raise ValueError('verification disclosure forbids regeneration/replacement')
                if task in attempts and attempts[task] != 'infra_invalid':
                    raise ValueError('only first valid verification retained')
                if event.result == 'infra_invalid' and not event.candidate_independent_infra:
                    raise ValueError('infra reexecution requires observed candidate-independent fault')
                if event.result == 'valid' and event.candidate_independent_infra:
                    raise ValueError('valid result cannot declare infra fault')
                candidates[task] = event.candidate_sha256
                attempts[task] = event.result
                if event.result == 'valid':
                    completed.add(task)
            else:
                raise ValueError('unknown custody action')
        previous = digest
        seen_hashes.add(digest)
    return CustodyReport(phase, tuple(sorted(completed)),
                         tuple(sorted(call for (_, call), state in calls.items() if state == 'reserved')),
                         tuple(sorted(call for (_, call), state in calls.items() if state in ('sent', 'unknown'))), previous)
