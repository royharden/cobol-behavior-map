"""Ledger facade bridge. No database/backend implementation or transport exists here."""
from collections.abc import Mapping
from typing import Any, Literal, Protocol
import re

from cobolmap.contracts import ArtifactRef, FrozenModel, sha256
from cobolmap.providers.adapters import PreparedPayload, prepare_payload
from cobolmap.providers.models import LeakagePolicy, ProviderRequest, ProviderResult
from cobolmap.providers.payload import validate_payload
from cobolmap.shared.callledger import CostBounds


class LedgerPort(Protocol):
    def reserve(self, call_id, arm, task, sample, attempt, est_usd, *, bounds=None): ...
    def mark_sent(self, call_id): ...
    def settle(self, call_id, status, usage, cost_or_none): ...
    def mark_unknown(self, call_id, reason): ...
    def link_shared_c(self, call_id, arm, task, sample): ...
    def report(self) -> Mapping[str, Any]: ...


class ApprovalArtifacts(FrozenModel):
    approval: ArtifactRef | None = None
    go_record: ArtifactRef | None = None
    conformance: ArtifactRef | None = None
    price_approval: ArtifactRef | None = None
    token_count: ArtifactRef | None = None
    call_binding: ArtifactRef | None = None
    settlement: ArtifactRef | None = None
    never_sent: ArtifactRef | None = None

    def missing_dispatch(self) -> tuple[str, ...]:
        return tuple(name + "_missing" for name in ("approval", "go_record", "conformance",
                     "price_approval", "token_count", "call_binding") if getattr(self, name) is None)


class AuthorityBoundary(Protocol):
    """Trusted injected verifier, NOT deserializable approval data or a boolean.

    Implementations must authenticate external approvals/P2/conformance, full
    schedule/price/fee liability, exact final wire token count, context allowlist,
    and immutable run/call-ID -> request hash binding across restart/concurrency.
    No implementation is supplied by this package. Methods raise on any gap.
    """
    def verify_dispatch(self, request: ProviderRequest, payload: PreparedPayload,
                        policy: LeakagePolicy, bounds: CostBounds, estimate_usd: str,
                        artifacts: ApprovalArtifacts, report: Mapping[str, Any]) -> None: ...
    def verify_settlement(self, request: ProviderRequest, result: ProviderResult,
                          artifacts: ApprovalArtifacts) -> None: ...
    def verify_never_sent(self, request: ProviderRequest, artifacts: ApprovalArtifacts) -> None: ...


class BridgeResult(FrozenModel):
    call_id: str
    request_sha256: str
    status: Literal["pending", "refused", "reserved", "sent_marker", "recorded", "unknown"]
    issues: tuple[str, ...] = ()
    provider_result: ProviderResult | None = None
    transport_authorized: Literal[False] = False


class AccountingBridge:
    """Source-only lifecycle integration. Never constructs a Ledger or sends data.

    Caller owns durable raw response/proof artifacts and the actual external
    verifier. Report flags, reservations and these return records are NOT authority.
    All current native Ledger reports block prepare/mark_sent as unverified.
    """
    def __init__(self, ledger: LedgerPort, *, authority: AuthorityBoundary | None = None):
        self.ledger = ledger
        self.authority = authority

    @staticmethod
    def _result(request: ProviderRequest, status: str, *issues: str,
                result: ProviderResult | None = None) -> BridgeResult:
        return BridgeResult(call_id=request.call_id, request_sha256=request.request_sha256(),
                            status=status, issues=tuple(issues), provider_result=result)

    def _report(self) -> Mapping[str, Any]:
        report = self.ledger.report()
        if not isinstance(report, Mapping) or not isinstance(report.get("calls"), Mapping):
            raise ValueError("ledger_report_shape")
        return report

    @staticmethod
    def _call(report: Mapping[str, Any], request: ProviderRequest) -> Mapping[str, Any]:
        call = report["calls"].get(request.call_id)
        if not isinstance(call, Mapping) or not isinstance(call.get("args"), Mapping):
            raise ValueError("reserved_call_missing")
        args = call["args"]
        if any(args.get(key) != value for key, value in (
                ("call_id", request.call_id), ("arm", request.arm), ("task", request.task_id),
                ("sample", request.sample), ("attempt", request.attempt))):
            raise ValueError("immutable_call_identity_mismatch")
        bounds = args.get("bounds")
        if not isinstance(bounds, Mapping) or bounds.get("model_id") != request.model_id:
            raise ValueError("reserved_model_mismatch")
        return call

    def prepare(self, request: ProviderRequest, payload: PreparedPayload, policy: LeakagePolicy, *,
                estimate_usd: str | None = None, bounds: CostBounds | None = None,
                artifacts: ApprovalArtifacts | None = None) -> BridgeResult:
        checked = validate_payload(request, policy, require_actual_context=True)
        if checked.status != "checked":
            return self._result(request, checked.status, *checked.issues)
        expected = prepare_payload(request, payload.format, policy=policy)
        if (payload.status != "prepared" or expected.status != "prepared"
                or payload.request_sha256 != request.request_sha256()
                or payload.payload_json != expected.payload_json or payload.payload_sha256 != expected.payload_sha256):
            return self._result(request, "refused", "final_wire_payload_mismatch")
        if payload.payload_json is None or len(payload.payload_json) > policy.max_payload_bytes:
            return self._result(request, "refused", "final_wire_byte_limit")
        if estimate_usd is None or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?", estimate_usd):
            return self._result(request, "pending", "canonical_estimate_missing")
        if bounds is None or not isinstance(bounds, CostBounds) or not bounds.complete:
            return self._result(request, "pending", "complete_token_fee_bounds_required")
        if (bounds.model_id != request.model_id or bounds.input_tokens != request.max_input_tokens
                or bounds.output_tokens != request.max_output_tokens):
            return self._result(request, "refused", "request_price_bounds_mismatch")
        if (bounds.cache_read_tokens > bounds.input_tokens or bounds.cache_write_tokens > bounds.input_tokens
                or bounds.reasoning_tokens > bounds.output_tokens):
            return self._result(request, "refused", "category_bound_exceeds_total_token_cap")
        report = self._report()
        # Positive report preconditions are only accounting declarations. Even a
        # future conformant facade cannot replace the external verifier below.
        if report.get("backend_status") != "backend_verified" or report.get("dispatch_allowed") is not True:
            return self._result(request, "pending", "ledger_backend_unverified_or_dispatch_blocked")
        if report.get("halt_reasons"):
            return self._result(request, "refused", "global_accounting_halt")
        plan = report.get("plan")
        if (not isinstance(plan, Mapping) or plan.get("run_plan_sha256") != request.run_plan_sha256
                or plan.get("prices_sha256") != request.prices_sha256
                or request.model_id not in plan.get("model_ids", ())):
            return self._result(request, "refused", "frozen_price_plan_mismatch")
        if request.shared_c_call_id is not None:
            shared = report["calls"].get(request.shared_c_call_id)
            args = shared.get("args") if isinstance(shared, Mapping) else None
            shared_bounds = args.get("bounds") if isinstance(args, Mapping) else None
            if (not isinstance(shared, Mapping) or shared.get("was_sent") is not True
                    or shared.get("state") != "settled" or shared.get("cost_usd") is None
                    or not isinstance(args, Mapping) or args.get("arm") != "C"
                    or args.get("task") != request.task_id or args.get("sample") != request.sample
                    or not isinstance(shared_bounds, Mapping) or shared_bounds.get("model_id") != request.model_id):
                return self._result(request, "refused", "shared_C_same_model_task_sample_settled_identity_required")
        if artifacts is None or artifacts.missing_dispatch() or self.authority is None:
            return self._result(request, "pending", "authenticated_external_authority_unavailable")
        if artifacts.token_count != request.token_count_receipt:
            return self._result(request, "refused", "exact_wire_token_receipt_mismatch")
        try:
            if self.authority.verify_dispatch(request, payload, policy, bounds, estimate_usd, artifacts, report) is not None:
                raise ValueError("verifier must authenticate or raise, never return an approval boolean")
        except Exception:
            return self._result(request, "refused", "external_authority_refused")
        if request.call_id in report["calls"]:
            existing = self._call(report, request)
            if existing.get("state") != "reserved" or existing.get("was_sent") is not False:
                return self._result(request, "refused", "sent_unknown_or_terminal_id_never_reused")
        # Native reserve atomically enforces immutable arguments, headroom, global
        # unknown liability and exact same-ID replay; no new ID is generated here.
        self.ledger.reserve(request.call_id, request.arm, request.task_id, request.sample,
                            request.attempt, estimate_usd, bounds=bounds)
        if request.shared_c_call_id is not None:
            self.ledger.link_shared_c(request.shared_c_call_id, request.arm, request.task_id, request.sample)
        return self._result(request, "reserved")

    def mark_sent(self, request: ProviderRequest, payload: PreparedPayload, policy: LeakagePolicy, *,
                  estimate_usd: str | None = None, bounds: CostBounds | None = None,
                  artifacts: ApprovalArtifacts | None = None) -> BridgeResult:
        reserved = self.prepare(request, payload, policy, estimate_usd=estimate_usd, bounds=bounds, artifacts=artifacts)
        if reserved.status != "reserved":
            return reserved
        call = self._call(self._report(), request)
        if call.get("state") != "reserved" or call.get("was_sent") is not False:
            return self._result(request, "refused", "only_never_sent_reserved_id_allowed")
        self.ledger.mark_sent(request.call_id)
        # Bookkeeping intent only. There is deliberately no transport invocation.
        return self._result(request, "sent_marker", "bookkeeping_is_not_transport_authority")

    def mark_unknown(self, request: ProviderRequest, reason: str) -> BridgeResult:
        if not reason:
            raise ValueError("unknown reason required")
        call = self._call(self._report(), request)
        if call.get("was_sent") is True:
            self.ledger.mark_unknown(request.call_id, reason)
        else:
            # An externally reported possibly-sent outcome without a marker is an
            # accounting fault. Native settle preserves liability and halts rather
            # than manufacturing a free not_sent event or retrying another ID.
            self.ledger.settle(request.call_id, "malformed", None, None)
        return self._result(request, "unknown", reason)

    def settle(self, request: ProviderRequest, result: ProviderResult, *,
               artifacts: ApprovalArtifacts | None = None) -> BridgeResult:
        if result.provenance != "provider_declared":
            return self._result(request, "refused", "fixture_or_unrun_result_cannot_settle_paid_ledger", result=result)
        call = self._call(self._report(), request)
        if (result.call_id != request.call_id or result.request_sha256 != request.request_sha256()
                or result.model_id != request.model_id):
            marked = self.mark_unknown(request, "response_call_request_model_binding_mismatch")
            return self._result(request, marked.status, *marked.issues, result=result)
        if result.status == "not_sent":
            if (call.get("was_sent") is not False or result.sent is not False or result.cost_usd != "0"
                    or artifacts is None or artifacts.never_sent is None or self.authority is None):
                return self._result(request, "pending", "authenticated_never_sent_zero_charge_proof_required", result=result)
            try:
                if self.authority.verify_never_sent(request, artifacts) is not None:
                    raise ValueError("boolean/data is not authenticated never-sent proof")
            except Exception:
                return self._result(request, "refused", "never_sent_proof_refused", result=result)
            outcome = self.ledger.settle(request.call_id, "not_sent", result.usage.ledger_mapping(), "0")
            return self._result(request, "unknown" if outcome.get("state") == "unknown" else "recorded", result=result)
        if result.status == "unknown" or result.sent is not True:
            marked = self.mark_unknown(request, "provider_outcome_or_sent_state_unknown")
            return self._result(request, marked.status, *marked.issues, result=result)
        usage = result.usage.ledger_mapping()
        if (result.cost_usd is None or any(value is None for value in usage.values())
                or artifacts is None or artifacts.settlement is None or self.authority is None):
            self.ledger.settle(request.call_id, result.status, usage, None)
            return self._result(request, "unknown", "missing_actual_billing_usage_or_authentication", result=result)
        try:
            if self.authority.verify_settlement(request, result, artifacts) is not None:
                raise ValueError("boolean/data is not authenticated settlement proof")
        except Exception:
            marked = self.mark_unknown(request, "settlement_authentication_refused")
            return self._result(request, marked.status, *marked.issues, result=result)
        outcome = self.ledger.settle(request.call_id, result.status, usage, result.cost_usd)
        return self._result(request, "unknown" if outcome.get("state") == "unknown" else "recorded", result=result)
