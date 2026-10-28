"""Closed supplied DEV control inputs; no IO, schedule generation or authority."""
import re
from cobolmap.contracts import InitialFeedback, TaskBinding
from cobolmap.contracts.derivation import revalidate_closed
from cobolmap.providers import ScriptedMock, ScriptEntry
from cobolmap.providers.models import ContextPart, Message, LeakagePolicy
from .runner_models import DevFixtureInput, FixtureCallPlan, FixtureLoopControl
from .schedule import CallSlot


def validate_unit(unit: DevFixtureInput) -> None:
    if type(unit) is not DevFixtureInput or unit.construction_exposure != "private_source_before_admission":
        raise ValueError("exact_dev_fixture_input_required")
    task = revalidate_closed(unit.task, TaskBinding, extra_types=(TaskBinding,))
    if task.split != "dev" or unit.model_slot not in ("primary", "replication"):
        raise ValueError("DEV_only_fixture_control")
    if (type(unit.calls) is not tuple or len(unit.calls) != 8
            or type(unit.controls) is not tuple or type(unit.loop_hashes) is not frozenset
            or len(unit.loop_hashes) != 32
            or any(type(h) is not str or not re.fullmatch(r"[0-9a-f]{64}", h) for h in unit.loop_hashes)):
        raise ValueError("immutable_native_slots_original32_controls_required")
    expected = {("B", 0), ("C", 0), *( (a, n) for a in ("D", "R") for n in (1, 2, 3))}
    seen, ids, models = set(), set(), set()
    c_id = None
    for call in unit.calls:
        if type(call) is not FixtureCallPlan or type(call.slot) is not CallSlot:
            raise ValueError("exact_native_call_slot_required")
        slot = call.slot
        if (type(slot.arm) is not str or type(slot.attempt) is not int
                or type(slot.task_id) is not str or type(slot.model_slot) is not str
                or type(slot.call_id) is not str or type(slot.sample) is not int
                or (slot.model_id is not None and type(slot.model_id) is not str)
                or (slot.shared_c_call_id is not None and type(slot.shared_c_call_id) is not str)):
            raise ValueError("closed_native_slot_scalars_required")
        key = slot.arm, slot.attempt
        if (key not in expected or key in seen or slot.task_id != task.task_id
                or slot.model_slot != unit.model_slot or type(slot.sample) is not int or slot.sample != 1
                or type(slot.attempt) is not int or slot.call_id in ids):
            raise ValueError("slot_task_arm_sample_or_identity_drift")
        if type(slot.call_id) is not str or not re.fullmatch(r"c_[0-9a-f]{62}", slot.call_id):
            raise ValueError("native_call_id_revision_m10_call_id_v2_required")
        if call.format not in ("openai_chat", "anthropic_messages"):
            raise ValueError("explicit_supported_wire_format_required")
        policy = revalidate_closed(call.policy, LeakagePolicy,
                                   extra_types=(LeakagePolicy, ContextPart, Message))
        if (policy.task_id != task.task_id or policy.original_source_sha256 != task.original.sha256
                or policy.loop_hashes != unit.loop_hashes or not policy.allowed_context_hashes
                or policy.context_authority is not None or policy.token_count_receipt is not None):
            raise ValueError("fixture_context_policy_and_allowlist_required")
        seen.add(key)
        ids.add(slot.call_id)
        if slot.model_id is not None:
            raise ValueError("fixture_model_authority_must_be_unset")
        models.add(slot.model_id)
        if key == ("C", 0): c_id = slot.call_id
    if seen != expected or len(models) != 1:
        raise ValueError("complete_native_unit_slots_same_model_required")
    for call in unit.calls:
        if call.slot.shared_c_call_id != (c_id if call.slot.arm in ("D", "R") else None):
            raise ValueError("native_shared_C_identity_drift")
    b = revalidate_closed(unit.initial_b, InitialFeedback)
    c = revalidate_closed(unit.initial_c, InitialFeedback)
    if (b.arm != "B" or c.arm != "C" or b.task_id != task.task_id or c.task_id != task.task_id
            or b.context.source_text != c.context.source_text
            or b.context.shim_api != c.context.shim_api
            or b.context.request_text != c.context.request_text):
        raise ValueError("equal_initial_task_source_shim_change_required")
    controls = set()
    for item in unit.controls:
        if type(item) is not FixtureLoopControl:
            raise ValueError("exact_fixture_control_required")
        if type(item.arm) is not str or type(item.attempt) is not int:
            raise ValueError("closed_control_identity_required")
        key = item.arm, item.attempt
        if (key not in {("C", 0), *((a, n) for a in ("D", "R") for n in (1, 2, 3))}
                or key in controls or type(item.attempt) is not int
                or (item.failures is not None and (type(item.failures) is not int or not 0 <= item.failures <= 32))):
            raise ValueError("duplicate_or_invalid_control")
        if item.candidate_sha256 is not None and (type(item.candidate_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", item.candidate_sha256)):
            raise ValueError("control_candidate_hash_malformed")
        if (item.arm == "D" and item.count_only is not None
                or item.arm == "R" and item.counterexample is not None):
            raise ValueError("control_cross_arm_feedback_forbidden")
        controls.add(key)
    revalidate_closed(unit.mock, ScriptedMock, extra_types=(ScriptedMock, ScriptEntry))
