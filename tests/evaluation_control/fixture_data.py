"""Disclosed builder-authored DEV control data; no cases or observations executed.

All response labels are deliberately noncode. Hashes below declare synthetic
original32 membership only, never sealed/admitted partitions or measurements.
"""
import json
from dataclasses import replace

from cobolmap.contracts import (ArtifactRef, BehaviorMap, CandidateAttempt,
    CounterexampleFeedback, CountOnlyFeedback, FeedbackContext, InitialFeedback,
    TaskBinding, sha256)
from cobolmap.providers import LeakagePolicy, ScriptEntry, ScriptedMock
from evaluation.arms import prepare_arm
from evaluation.prompts import (build_fixture_initial_prompt,
    build_fixture_counterexample_prompt, build_fixture_count_prompt)
from evaluation.runner_models import DevFixtureInput, FixtureCallPlan, FixtureLoopControl
from evaluation.schedule import CallSlot


SOURCE = 'BUILDER SYNTHETIC DEV CONTEXT -- NOT A COBOL PROGRAM\n'
SHIM = 'BUILDER SYNTHETIC SHIM DESCRIPTION -- NO RUNTIME AVAILABLE'
DIAGNOSTIC = 'BUILDER SCRIPTED REFUSAL DIAGNOSTIC -- NOT A COMPILER RESULT'
# Fixed native-shaped unit identifiers: no canonical schedule provenance claimed.
IDS = {
    ('B', 0): 'c_' + '1' * 62, ('C', 0): 'c_' + '2' * 62,
    ('D', 1): 'c_' + '3' * 62, ('D', 2): 'c_' + '4' * 62,
    ('D', 3): 'c_' + '5' * 62, ('R', 1): 'c_' + '6' * 62,
    ('R', 2): 'c_' + '7' * 62, ('R', 3): 'c_' + '8' * 62,
}
LOOP_HASHES = frozenset(sha256(f'BUILDER SYNTHETIC ORIGINAL32 DECLARATION {i}'.encode())
                        for i in range(32))


def candidate(arm, number, *, status='generated', text=None):
    """Expected native DTO for a caller script, never returned model truth."""
    if status == 'generated' and text is None:
        text = f'BUILDER NONCODE FIXTURE LABEL [{arm}:{number}]'
    return CandidateAttempt(task_id='builder_dev_control', arm=arm, attempt=number,
        code=text, candidate_sha256=sha256(text.encode()) if text is not None else None,
        call_id=IDS[arm, number],
        shared_c_call_id=IDS['C', 0] if arm in ('D', 'R') else None,
        evidence_mode='fixture', status=status)


def response(item):
    message = {'role': 'assistant', 'content': item.code}
    if item.status == 'refused':
        message['refusal'] = 'BUILDER SCRIPTED REFUSAL'
    if item.status == 'failed':
        return b'{"error":{"message":"BUILDER SCRIPTED FAILURE"}}'
    return json.dumps({'choices': [{'message': message, 'finish_reason': 'stop'}]},
                      sort_keys=True).encode()


def fixture_unit(*, c_pass=False, d_statuses=('generated',),
                 d_failures=(0,), r_texts=None, r_failures=(0,)):
    """Build eight slots and just the explicit finite scripts to be consumed.

    Generated-C failed-loop D witnesses are deliberately absent: no ordinary
    observation or fabricated compiler output is constructed for that path.
    """
    raw = SOURCE.encode()
    original = ArtifactRef(path='builder-context.txt', sha256=sha256(raw), byte_length=len(raw))
    task = TaskBinding(task_id='builder_dev_control', program_id='builder_program',
        family_id='builder_family', split='dev', panel='unchanged',
        original=original, oracle_source=original)
    behavior = BehaviorMap(source_sha256=original.sha256, filename=original.path)
    base = dict(source_sha256=original.sha256, source_text=SOURCE, shim_api=SHIM, request_text='')
    b = InitialFeedback(task_id=task.task_id, arm='B', context=FeedbackContext(**base))
    c = InitialFeedback(task_id=task.task_id, arm='C',
                        context=FeedbackContext(**base, behavior_map=behavior))
    b_candidate = candidate('B', 0)
    c_candidate = candidate('C', 0, status='generated' if c_pass else 'refused')
    ds = () if c_pass else tuple(candidate('D', i, status=status)
                               for i, status in enumerate(d_statuses, 1))
    if r_texts is None:
        r_texts = tuple(f'BUILDER NONCODE FIXTURE R LABEL [{i}]' for i in range(1, len(r_failures) + 1))
    rs = () if c_pass else tuple(candidate('R', i, text=text) for i, text in enumerate(r_texts, 1))
    packets = {('B', 0): b, ('C', 0): c}
    controls = {}
    for arm, items, failures in (('D', ds, d_failures), ('R', rs, r_failures)):
        previous = c_candidate
        for item in items:
            context = FeedbackContext(**base, behavior_map=behavior, previous_candidate=previous,
                diagnostic=DIAGNOSTIC if previous.status in ('refused', 'failed', 'invalid') else None)
            packet = (CounterexampleFeedback(task_id=task.task_id, attempt=item.attempt, context=context)
                      if arm == 'D' else CountOnlyFeedback(task_id=task.task_id,
                          attempt=item.attempt, context=context, failed_cases=(32 if previous.arm == 'C'
                              else failures[previous.attempt - 1]), loop_cases=32))
            packets[arm, item.attempt] = packet
            key = (previous.arm, previous.attempt)
            old = controls.get(key, FixtureLoopControl(*key, previous.candidate_sha256,
                32 if previous.arm == 'C' else failures[previous.attempt - 1]))
            controls[key] = replace(old, **{'counterexample' if arm == 'D' else 'count_only': packet})
            controls[arm, item.attempt] = FixtureLoopControl(arm, item.attempt,
                item.candidate_sha256, failures[item.attempt - 1])
            previous = item
    if c_pass:
        controls['C', 0] = FixtureLoopControl('C', 0, c_candidate.candidate_sha256, 0)
    calls = []
    for key, call_id in IDS.items():
        arm, number = key
        slot = CallSlot(call_id, task.task_id, 'primary', None, arm, number,
                        IDS['C', 0] if arm in ('D', 'R') else None)
        packet = packets.get(key)
        # Unused slots retain the initial C context allowlist; they are never sent.
        if packet is None:
            wrapper = build_fixture_initial_prompt(c, task=task, loop_hashes=LOOP_HASHES)
        elif arm in ('B', 'C'):
            wrapper = build_fixture_initial_prompt(packet, task=task, loop_hashes=LOOP_HASHES)
        else:
            builder = build_fixture_counterexample_prompt if arm == 'D' else build_fixture_count_prompt
            wrapper = builder(packet, task=task, loop_hashes=LOOP_HASHES, call_id=call_id,
                shared_c_call_id=IDS['C', 0], expected_previous_call_id=packet.context.previous_candidate.call_id)
        policy = LeakagePolicy(task_id=task.task_id, original_source_sha256=original.sha256,
            loop_hashes=LOOP_HASHES,
            allowed_context_hashes=frozenset(p.sha256 for m in wrapper.messages for p in m.parts))
        calls.append(FixtureCallPlan(slot, policy, 'openai_chat'))
    lookup = {(call.slot.arm, call.slot.attempt): call for call in calls}
    entries = []
    for item in (b_candidate, c_candidate) + ds + rs:
        prepared = prepare_arm(lookup[item.arm, item.attempt], packets[item.arm, item.attempt],
                               task=task, loop_hashes=LOOP_HASHES, fixture_control=True)
        if prepared.status != 'prepared':
            raise AssertionError(('native_fixture_preparation_failed', prepared.issues))
        entries.append(ScriptEntry(call_id=item.call_id,
            request_sha256=prepared.request.request_sha256(), format='openai_chat',
            raw_response_json=response(item)))
    return DevFixtureInput(task, 'primary', tuple(calls), b, c, LOOP_HASHES,
                           tuple(controls.values()), ScriptedMock(entries=tuple(entries)))
