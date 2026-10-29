"""Complete neutral payload checks before future accounting/transport; never sends."""
from cobolmap.contracts import (canonical_json, sha256, CounterexampleFeedback,
                                DerivativeAuthority, DerivativeEvidence, feedback_json)
from cobolmap.contracts.derivation import (authenticate_derivative, revalidate_closed,
                                          validate_derivative, wire_json)
from .models import ContextPart, Message, LeakagePolicy, PreflightResult, ProviderRequest


def validate_payload(request: ProviderRequest, policy: LeakagePolicy, *,
                     require_actual_context: bool = True,
                     derivative: DerivativeEvidence | None = None,
                     derivative_authority: DerivativeAuthority | None = None,
                     feedback: CounterexampleFeedback | None = None) -> PreflightResult:
    request, policy = closed_request_policy(request, policy)
    issues = []
    derivative_hash = None
    if derivative is not None or derivative_authority is not None or feedback is not None:
        try:
            packet, local = derivative_request_binding(request, policy, feedback, derivative)
            feedback_json(packet, loop_hashes=policy.loop_hashes, admitted=True,
                          max_payload_bytes=policy.max_payload_bytes, derivative=local,
                          derivative_authority=derivative_authority)
            derivative_hash = local.final_case.case_sha256
        except Exception:
            issues.append("derivative_local_proof_or_authority_refused")
    if request.task_id != policy.task_id:
        issues.append("policy_task_mismatch")
    if not request.messages or any(not message.parts for message in request.messages):
        issues.append("empty_messages")
    original = []
    for message in request.messages:
        for part in message.parts:
            if part.task_id != request.task_id:
                issues.append("other_task_context")
            if policy.allowed_context_hashes and part.sha256 not in policy.allowed_context_hashes:
                issues.append("context_not_in_authorized_allowlist")
            if part.kind == "original_source": original.append(part.sha256)
            if part.kind == "loop_witness":
                if request.arm != "D" or (part.case_sha256 not in policy.loop_hashes
                                           and part.case_sha256 != derivative_hash):
                    issues.append("loop_witness_not_permitted")
            if request.arm == "B" and part.kind == "map":
                issues.append("B_cannot_receive_map")
            if request.arm == "R" and part.kind == "loop_witness":
                issues.append("R_cannot_receive_counterexample")
            if request.arm in ("B", "C") and part.kind in ("previous_candidate", "diagnostic", "loop_witness", "counts"):
                issues.append("initial_context_contains_repair_data")
            if request.arm != "R" and part.kind == "counts":
                issues.append("count_feedback_wrong_arm")
    if original != [policy.original_source_sha256]:
        issues.append("exactly_one_bound_original_source_required")
    kinds = [part.kind for m in request.messages for part in m.parts]
    if "shim_api" not in kinds:
        issues.append("equal_access_shim_api_missing")
    if request.arm in ("C", "D", "R") and "map" not in kinds:
        issues.append("map_context_missing")
    if request.arm in ("D", "R") and "previous_candidate" not in kinds:
        issues.append("previous_candidate_context_missing")
    if kinds.count("loop_witness") > 1:
        issues.append("at_most_one_loop_witness")
    if request.arm == "R" and kinds.count("counts") != 1:
        issues.append("exactly_one_count_feedback_required")
    raw = canonical_json(request)
    if len(raw) > policy.max_payload_bytes:
        issues.append("payload_byte_limit_never_truncate")
    # Scan both decoded strings and final serialized representation. This is a
    # secondary fingerprint interlock; no fingerprint list proves absence of leaks.
    contents = tuple(p.text for m in request.messages for p in m.parts) + (raw.decode("utf-8"),)
    if any(not fingerprint for fingerprint in policy.prohibited_fingerprints):
        issues.append("empty_canary_fingerprint")
    if any(fingerprint in text for fingerprint in policy.prohibited_fingerprints for text in contents):
        issues.append("prohibited_payload_fingerprint")
    if request.input_tokens is not None and request.input_tokens > request.max_input_tokens:
        issues.append("input_token_cap")
    if issues:
        return PreflightResult(status="refused", request_sha256=request.request_sha256(), issues=tuple(dict.fromkeys(issues)))
    missing = []
    if require_actual_context:
        if request.model_id is None: missing.append("model_pin_missing")
        if request.run_plan_sha256 is None: missing.append("run_plan_pin_missing")
        if request.prices_sha256 is None: missing.append("price_pin_missing")
        if request.input_tokens is None: missing.append("exact_token_count_missing")
        if (request.token_count_receipt is None or policy.token_count_receipt is None
                or request.token_count_receipt != policy.token_count_receipt):
            missing.append("token_count_receipt_missing_or_different")
        if policy.context_authority is None: missing.append("context_authority_missing")
        if not policy.allowed_context_hashes: missing.append("authorized_context_allowlist_missing")
        if policy.canary_policy_receipt is None: missing.append("canary_policy_receipt_missing")
        if request.arm == "D" and len(policy.loop_hashes) != 32:
            missing.append("full_loop_partition_required")
    return PreflightResult(status="pending" if missing else "checked", request_sha256=request.request_sha256(),
                           payload_sha256=sha256(raw), issues=tuple(missing))


_PROVIDER_TYPES = (ContextPart, Message, ProviderRequest, LeakagePolicy)


def closed_request_policy(request, policy):
    return (revalidate_closed(request, ProviderRequest, extra_types=_PROVIDER_TYPES),
            revalidate_closed(policy, LeakagePolicy, extra_types=_PROVIDER_TYPES))


def derivative_request_binding(request, policy, packet, local):
    """Match the exact single witness/context projection, never generic model dumps."""
    request, policy = closed_request_policy(request, policy)
    packet, local = validate_derivative(packet, local, policy.loop_hashes)
    if (request.arm != "D" or request.task_id != packet.task_id
            or request.attempt != packet.attempt
            or policy.original_source_sha256 != packet.context.source_sha256):
        raise ValueError("derivative_request_scope_mismatch")
    previous = packet.context.previous_candidate
    inherited_c = previous.call_id if previous.arm == "C" else previous.shared_c_call_id
    if (not inherited_c or request.shared_c_call_id != inherited_c
            or request.attempt != previous.attempt + 1
            or request.model_id != previous.model_id):
        raise ValueError("derivative_previous_candidate_call_mismatch")
    context = packet.context
    expected = {"original_source": context.source_text,
                "map": wire_json(context.behavior_map).decode("utf-8"),
                "shim_api": context.shim_api, "structured_change": context.request_text,
                "previous_candidate": wire_json(previous).decode("utf-8"),
                "loop_witness": wire_json(packet.witness).decode("utf-8")}
    if context.diagnostic is not None:
        expected["diagnostic"] = context.diagnostic
    seen = set()
    for message in request.messages:
        for part in message.parts:
            if part.kind == "instruction":
                continue  # Still covered by allowlist/canaries/external full-wire authority.
            if part.kind in seen or part.kind not in expected or part.text != expected[part.kind]:
                raise ValueError("derivative_exact_context_projection_required")
            if part.kind == "loop_witness" and part.case_sha256 != local.final_case.case_sha256:
                raise ValueError("derivative_final_case_pin_mismatch")
            seen.add(part.kind)
    if seen != set(expected):
        raise ValueError("derivative_context_projection_missing")
    return packet, local


def authenticate_derivative_wire(request, policy, packet, local, authority, wire_sha256):
    """Recheck exact bindings and authenticate BOTH feedback and final wire digests."""
    packet, local = derivative_request_binding(request, policy, packet, local)
    authenticate_derivative(packet, local, policy.loop_hashes, authority,
                            request=request, wire_sha256=wire_sha256)
