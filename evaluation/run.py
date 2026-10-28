"""P11 DEV fixture-control coordinator. Real study execution is default-blocked.

No source/fixture/script data is supplied here. Nothing reads hidden artifacts,
executes candidate text, invokes an oracle, settles paid facts or sends a request.
"""
from cobolmap.contracts import (CandidateAttempt, CounterexampleFeedback, CountOnlyFeedback,
                                RunResult, sha256)
from cobolmap.contracts.derivation import revalidate_closed
from cobolmap.providers import ScriptedMock, ScriptEntry
from .arms import prepare_arm
from .prereg import Preregistration, validate_prereg
from .runner_models import (BlockedStudyReport, DevFixtureInput, FixtureCallTrace,
                            FixtureControlTrace)
from .runner_validation import validate_unit
from .schedule import fork_shared_c, record_loop, append_repair


def run_study(registration: Preregistration) -> BlockedStudyReport:
    """Expose missing real gates; there is deliberately no execution/activation port."""
    if type(registration) is not Preregistration:
        raise ValueError("exact_preregistration_required")
    report = None
    issues = ("actual_isolated_backend_absent", "actual_authority_and_P2_unverified",
              "no_live_transport", "backend_unverified")
    try:
        report = validate_prereg(registration)
        issues += report.issues
    except (ValueError, TypeError, AttributeError) as exc:
        issues += ("preregistration_refused:" + type(exc).__name__,)
    result = RunResult(run_id=registration.run_plan.run_id, evidence_mode="not_run",
                       processing_mode="not_run", status="not_run", issues=tuple(dict.fromkeys(issues)))
    return BlockedStudyReport(result, report)


def run_dev_fixture(unit: DevFixtureInput) -> FixtureControlTrace:
    """Consume explicit caller scripts/counts using native selection transitions.

    Counts are ONLY simulated control declarations. Never comparator input,
    actual measurement, authentic derivation, verification or paid billing facts.
    Missing inputs halt; this API does not resume/retry/regenerate call identities.
    """
    validate_unit(unit)
    calls, states, inheritance = [], [], ()
    mock = revalidate_closed(unit.mock, ScriptedMock, extra_types=(ScriptedMock, ScriptEntry))
    slots = {(x.slot.arm, x.slot.attempt): x for x in unit.calls}
    controls = {(x.arm, x.attempt): x for x in unit.controls}

    def finish(*issues):
        return FixtureControlTrace(unit.task.task_id, unit.model_slot,
            "control_complete" if not issues else "partial" if calls else "blocked",
            tuple(calls), tuple(states), inheritance, mock, tuple(issues))

    def attempt(arm, number, packet):
        nonlocal mock
        call = slots[arm, number]
        prepared = prepare_arm(call, packet, task=unit.task, loop_hashes=unit.loop_hashes,
                               fixture_control=True)
        if prepared.status != "prepared":
            return None, prepared.issues
        if mock.position >= len(mock.entries):
            return None, ("caller_script_missing",)
        if mock.entries[mock.position].format != call.format:
            return None, ("script_wire_format_mismatch",)
        result, following = mock.respond(prepared.request)
        if following.position != mock.position + 1:
            return None, ("script_missing_mismatched_or_malformed",)
        if result.provenance != "fixture" or result.sent is not False or result.cost_usd is not None:
            return None, ("fixture_result_cannot_claim_sent_or_billed",)
        status = "generated" if result.status == "success" and result.text and result.text.strip() else (
                 "invalid" if result.status == "success" else "refused" if result.status == "refused" else "failed")
        code = result.text if status == "generated" else None
        candidate = CandidateAttempt(task_id=unit.task.task_id, arm=arm, attempt=number,
                    candidate_sha256=sha256(code.encode("utf-8")) if code is not None else None,
                    code=code, model_id=call.slot.model_id, call_id=call.slot.call_id,
                    shared_c_call_id=call.slot.shared_c_call_id, evidence_mode="fixture", status=status)
        mock = following
        calls.append(FixtureCallTrace(call.slot.call_id, arm, number, prepared.request.request_sha256(),
                                      prepared.control_payload_sha256, result, candidate))
        return candidate, ()

    for arm, packet in (("B", unit.initial_b), ("C", unit.initial_c)):
        candidate, issues = attempt(arm, 0, packet)
        if issues: return finish(*issues)
        if arm == "C": shared_c = candidate
    states = list(fork_shared_c(shared_c))
    inheritance = (("D", shared_c.call_id), ("R", shared_c.call_id))
    # Both arms start from the exact same C object, including source/refusal.
    initial = controls.get(("C", 0))
    if initial is None or initial.candidate_sha256 != shared_c.candidate_sha256:
        return finish("shared_C_scripted_control_missing_or_mismatched")
    try:
        states = [record_loop(state, initial.failures) for state in states]
    except ValueError as exc:
        return finish("invalid_shared_C_control:" + type(exc).__name__)
    if initial.failures is None:
        return finish("scripted_loop_control_unavailable_not_measurement")
    for index in range(2):
        state = states[index]
        while state.stopped is None:
            previous = state.selected
            control = controls.get((previous.arm, previous.attempt))
            if control is None or control.candidate_sha256 != previous.candidate_sha256:
                return finish("scripted_loop_control_missing_or_mismatched")
            cls = CounterexampleFeedback if state.arm == "D" else CountOnlyFeedback
            raw_packet = control.counterexample if state.arm == "D" else control.count_only
            if type(raw_packet) is not cls:
                return finish("caller_typed_repair_feedback_missing")
            try:
                packet = revalidate_closed(raw_packet, cls)
                context = packet.context
                base = unit.initial_c.context
                if (context.previous_candidate != previous or packet.task_id != unit.task.task_id
                        or packet.attempt != len(state.attempts) + 1
                        or context.source_text != base.source_text or context.shim_api != base.shim_api
                        or context.request_text != base.request_text or context.behavior_map != base.behavior_map):
                    return finish("repair_packet_drift_from_selected_candidate_or_original_context")
                if state.arm == "R" and (packet.loop_cases != 32 or packet.failed_cases != control.failures):
                    return finish("R_scripted_count_projection_mismatch")
                if state.arm == "D" and packet.witness is not None and packet.witness.case.case_sha256 not in unit.loop_hashes:
                    return finish("fixture_counts_cannot_authorize_derivative_witness")
            except ValueError as exc:
                return finish("repair_packet_refused:" + type(exc).__name__)
            candidate, issues = attempt(state.arm, len(state.attempts) + 1, packet)
            if issues: return finish(*issues)
            try:
                state = append_repair(state, candidate)
                states[index] = state
                if state.stopped is not None:
                    break
                measured = controls.get((state.arm, candidate.attempt))
                if measured is not None and measured.candidate_sha256 != candidate.candidate_sha256:
                    return finish("scripted_control_candidate_mismatch")
                failures = None if measured is None else measured.failures
                state = record_loop(state, failures)
                states[index] = state
                if failures is None:
                    return finish("scripted_loop_control_unavailable_not_measurement")
            except ValueError as exc:
                return finish("native_selection_transition_refused:" + type(exc).__name__)
    # Selected is the last native allowed attempt (or shared C); verification is
    # never read/disclosed or used to choose among prior candidates here.
    return finish()
