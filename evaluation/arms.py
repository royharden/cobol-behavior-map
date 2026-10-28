"""Typed arm preparation only. No parallel prompts, candidate or model execution."""
from cobolmap.contracts import (CandidateAttempt, CounterexampleFeedback, CountOnlyFeedback,
                                InitialFeedback, TaskBinding, canonical_json, sha256)
from cobolmap.contracts.derivation import revalidate_closed
from cobolmap.providers import ProviderRequest, prepare_payload, validate_payload
from .runner_models import ArmPreparation, FixtureCallPlan


def prepare_arm(call: FixtureCallPlan, packet, *, task: TaskBinding, loop_hashes: frozenset[str],
                fixture_control: bool = False, admitted: bool = False,
                derivative=None, derivative_authority=None,
                run_plan_sha256=None, prices_sha256=None,
                input_tokens=None, token_count_receipt=None) -> ArmPreparation:
    """Use only canonical DL4 builders. Missing fixture/derivative seam blocks.

    Fixture control never asserts actual admission. Optional actual derivation
    stays local and cannot be satisfied by scripted counts. No transport exists.
    """
    try:
        from . import prompts
    except ImportError:
        return ArmPreparation("blocked", issues=("canonical_DL4_prompt_module_missing",))
    if type(fixture_control) is not bool or type(admitted) is not bool:
        raise ValueError("explicit_boolean_mode_required")
    if fixture_control and (admitted or derivative is not None or derivative_authority is not None):
        return ArmPreparation("blocked", issues=("fixtures_cannot_supply_actual_admission_or_derivation",))
    if type(call) is not FixtureCallPlan:
        raise ValueError("exact_native_call_plan_required")
    cls = {"B": InitialFeedback, "C": InitialFeedback,
           "D": CounterexampleFeedback, "R": CountOnlyFeedback}.get(call.slot.arm)
    if cls is None or type(packet) is not cls:
        return ArmPreparation("blocked", issues=("exact_arm_packet_required",))
    packet = revalidate_closed(packet, cls)
    if packet.arm != call.slot.arm or packet.task_id != call.slot.task_id:
        return ArmPreparation("blocked", issues=("packet_slot_identity_mismatch",))
    if call.slot.arm in ("D", "R") and packet.attempt != call.slot.attempt:
        return ArmPreparation("blocked", issues=("packet_slot_attempt_mismatch",))
    name = ("initial" if call.slot.arm in ("B", "C") else
            "counterexample" if call.slot.arm == "D" else "count")
    builder = getattr(prompts, "build_" + ("fixture_" if fixture_control else "") + name + "_prompt", None)
    if not callable(builder):
        return ArmPreparation("blocked", issues=("canonical_DL4_fixture_prompt_capability_missing" if fixture_control
                                                   else "canonical_DL4_prompt_capability_missing",))
    args = dict(task=task, loop_hashes=loop_hashes, max_payload_bytes=call.policy.max_payload_bytes)
    if not fixture_control:
        args["admitted"] = admitted
    if call.slot.arm in ("D", "R"):
        args.update(call_id=call.slot.call_id, shared_c_call_id=call.slot.shared_c_call_id,
                    expected_previous_call_id=packet.context.previous_candidate.call_id)
    if derivative is not None or derivative_authority is not None:
        if call.slot.arm != "D":
            return ArmPreparation("blocked", issues=("derivative_D_only",))
        args.update(derivative=derivative, derivative_authority=derivative_authority)
    try:
        built = builder(packet, **args)
        if fixture_control:
            wrapper_type = getattr(prompts, "FixturePrompt", None)
            if wrapper_type is None or type(built) is not wrapper_type:
                return ArmPreparation("blocked", issues=("exact_canonical_fixture_wrapper_required",))
            if built.admitted is not False or built.transport_authorized is not False:
                return ArmPreparation("blocked", issues=("fixture_wrapper_authority_forbidden",))
            if (call.slot.model_id is not None or run_plan_sha256 is not None
                    or prices_sha256 is not None or input_tokens is not None or token_count_receipt is not None
                    or call.policy.context_authority is not None or call.policy.token_count_receipt is not None):
                return ArmPreparation("blocked", issues=("fixture_model_price_or_actual_authority_forbidden",))
            messages = built.messages
        else:
            messages = built
        request = ProviderRequest(call_id=call.slot.call_id, task_id=call.slot.task_id,
                                  arm=call.slot.arm, attempt=call.slot.attempt,
                                  messages=messages, model_id=call.slot.model_id,
                                  shared_c_call_id=call.slot.shared_c_call_id,
                                  run_plan_sha256=run_plan_sha256, prices_sha256=prices_sha256,
                                  input_tokens=input_tokens, token_count_receipt=token_count_receipt)
        local = dict(derivative=derivative, derivative_authority=derivative_authority,
                     feedback=packet if derivative is not None else None)
        checked = validate_payload(request, call.policy, require_actual_context=not fixture_control, **local)
        if checked.status != "checked":
            return ArmPreparation("blocked", issues=checked.issues)
        if fixture_control:
            # Neutral no-model request goes ONLY to ScriptedMock. Never construct a
            # provider wire/model/price envelope or convert fixture admission.
            return ArmPreparation("prepared", request=request,
                                  control_payload_sha256=sha256(canonical_json(request)))
        payload = prepare_payload(request, call.format, policy=call.policy, **local)
        if payload.status != "prepared":
            return ArmPreparation("blocked", issues=payload.issues)
        return ArmPreparation("prepared", request, payload)
    except Exception as exc:
        return ArmPreparation("blocked", issues=("arm_preparation_refused:" + type(exc).__name__,))


def build_a_source(task: TaskBinding, program, *, change_raw: bytes | None = None) -> CandidateAttempt:
    """Generate A text from supplied DEV IR/edit only; never import/run that text."""
    import json
    from cobolmap.parse.models import ProgramIR
    from cobolmap.translate import translate
    task = revalidate_closed(task, TaskBinding, extra_types=(TaskBinding,))
    if task.split != "dev" or type(program) is not ProgramIR:
        raise ValueError("DEV_native_IR_required")
    source = program.source.encode("utf-8")
    task.original.check_bytes(source)
    if program.source_sha256 != task.original.sha256 or program.filename != task.original.path:
        raise ValueError("A_original_IR_source_binding_mismatch")
    change = None
    if task.panel == "change":
        if type(change_raw) is not bytes or task.change is None:
            raise ValueError("exact_raw_change_required")
        task.change.check_bytes(change_raw)
        def pairs(items):
            out = {}
            for key, value in items:
                if key in out: raise ValueError("duplicate_change_key")
                out[key] = value
            return out
        def forbidden(_): raise ValueError("nonfinite_or_float_change_forbidden")
        change = json.loads(change_raw, object_pairs_hook=pairs, parse_float=forbidden, parse_constant=forbidden)
        if type(change) is not dict:
            raise ValueError("native_change_mapping_required")
    elif change_raw is not None:
        raise ValueError("unchanged_A_has_no_edit")
    generated = translate(program, change)
    if generated.original_source_sha256 != task.original.sha256:
        raise ValueError("generated_A_source_binding_mismatch")
    return CandidateAttempt(task_id=task.task_id, arm="A", attempt=0,
                            candidate_sha256=sha256(generated.code.encode("utf-8")),
                            code=generated.code, evidence_mode="static", status="generated")
