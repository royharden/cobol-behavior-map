"""Original append-only local accounting. No provider dispatch or authority."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator
import uuid

from .models import CostBounds, LedgerError, PricePlan, normalize_usage
from .money import MoneyError, add_money, canonical_money, compare_money, subtract_money, sum_money

ZERO_HASH = "0" * 64
APPLICATION_ID = 0x4D31304C
TERMINAL = frozenset({"success", "failed", "refused", "malformed", "not_sent"})


def encoded(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise LedgerError("audit_corrupt", "Duplicate JSON key")
        result[key] = value
    return result


def _noninteger(value):
    raise LedgerError("audit_corrupt", "Noninteger JSON number in accounting event")


def decoded(value: str) -> Any:
    try:
        return json.loads(value, object_pairs_hook=_pairs, parse_float=_noninteger, parse_constant=_noninteger)
    except (ValueError, TypeError) as error:
        raise LedgerError("audit_corrupt", "Invalid event JSON") from error


def identifier(value: str) -> str:
    if type(value) is not str or not value or len(value) > 256 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise LedgerError("invalid_identity", "Nonempty bounded identifier without whitespace/control required")
    return value


def raw_declaration(value: Any, depth: int = 0) -> Any:
    """Retain malformed declarations as inert text, never coerce into money."""
    if value is None or type(value) in {str, bool}:
        return value
    if type(value) is int and value.bit_length() < 1024:
        return value
    if depth < 8 and type(value) is dict and len(value) <= 32:
        return {str(key) if type(key) in {str, int, bool} else "invalid_key": raw_declaration(item, depth + 1) for key, item in value.items()}
    if depth < 8 and type(value) in {list, tuple} and len(value) <= 32:
        return [raw_declaration(item, depth + 1) for item in value]
    if type(value).__module__ == "decimal" and type(value).__name__ == "Decimal":
        return {"declared_decimal": str(value)}
    if type(value) is float:
        return {"invalid_float": repr(value)}
    return {"invalid_type": type(value).__name__}


def _closed(value: Any, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        raise LedgerError("audit_corrupt", "Closed event payload mismatch")


class Ledger:
    """Constructor opens SQLite only when a future authorized caller invokes it.

    Accounting mutations are not paid dispatch. This original backend ALWAYS
    reports backend_unverified/dispatch_allowed=False until future conformance
    and an explicit reviewed backend activation change; metadata cannot lift it.
    """

    def __init__(self, path: str | Path, budget_usd: Any, *, plan: PricePlan | None = None):
        if str(path).startswith(("\\\\", "//")) or str(path).startswith("file:"):
            raise LedgerError("database_path", "Local filesystem database only, no network/URI paths")
        self.path = Path(path)
        self.budget = canonical_money(budget_usd)
        if plan is not None and not isinstance(plan, PricePlan):
            raise LedgerError("invalid_plan", "PricePlan required")
        self.plan = plan.as_dict() if plan is not None else None
        if self.plan and compare_money(self.plan["worst_schedule_usd"], self.budget) > 0:
            raise LedgerError("schedule_unfunded", "Full frozen schedule exceeds configured headroom")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                app_id = connection.execute("PRAGMA application_id").fetchone()[0]
                names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if app_id not in {0, APPLICATION_ID} or (app_id == 0 and names):
                    raise LedgerError("foreign_database", "Refuse unrelated or unidentified database")
                if app_id == 0:
                    connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    connection.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL, previous_sha256 TEXT NOT NULL, sha256 TEXT NOT NULL)")
                    connection.execute("CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append-only events'); END")
                    connection.execute("CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append-only events'); END")
                    self._append(connection, [], "init", {"version": 1, "budget_usd": self.budget, "plan": self.plan})
                events, state = self._read(connection)
                if state["budget_usd"] != self.budget or (self.plan is not None and state["plan"] != self.plan):
                    raise LedgerError("immutable_configuration", "No budget top-up, repricing or model-plan replacement")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), isolation_level=None, timeout=5)
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                events, state = self._read(connection)
                if state["budget_usd"] != self.budget or (self.plan is not None and state["plan"] != self.plan):
                    raise LedgerError("immutable_configuration", "Configuration differs from opened ledger")
                yield connection, events, state
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _read(self, connection):
        rows = connection.execute("SELECT seq,event_id,kind,created_at,payload,previous_sha256,sha256 FROM events ORDER BY seq").fetchall()
        events = []
        state = {"budget_usd": None, "plan": None, "calls": {}, "links": [], "expenses": {}, "faults": []}
        previous = ZERO_HASH
        for index, row in enumerate(rows, 1):
            seq, event_id, kind, created_at, payload, prior, digest = row
            if type(seq) is not int or seq != index or prior != previous:
                raise LedgerError("audit_corrupt", "Event sequence/lineage mismatch")
            event = {"seq": seq, "event_id": event_id, "kind": kind, "created_at": created_at,
                     "payload": decoded(payload), "previous_sha256": prior}
            actual = hashlib.sha256(encoded(event).encode("utf-8")).hexdigest()
            if actual != digest or payload != encoded(event["payload"]):
                raise LedgerError("audit_corrupt", "Event bytes/hash mismatch")
            self._apply(state, kind, event["payload"])
            event["sha256"] = digest
            events.append(event)
            previous = digest
        if not events or events[0]["kind"] != "init":
            raise LedgerError("audit_corrupt", "Missing unique ledger genesis")
        return events, state

    def _append(self, connection, events, kind, payload):
        event = {"seq": len(events) + 1, "event_id": uuid.uuid4().hex, "kind": kind,
                 "created_at": datetime.now(timezone.utc).isoformat(), "payload": payload,
                 "previous_sha256": events[-1]["sha256"] if events else ZERO_HASH}
        digest = hashlib.sha256(encoded(event).encode("utf-8")).hexdigest()
        connection.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)", (event["seq"], event["event_id"], kind, event["created_at"], encoded(payload), event["previous_sha256"], digest))
        event["sha256"] = digest
        return event

    @staticmethod
    def _totals(state):
        known = sum_money([call["cost_usd"] for call in state["calls"].values() if call["cost_usd"] is not None] + [expense["cost_usd"] for expense in state["expenses"].values()])
        liabilities = []
        for call in state["calls"].values():
            if call["cost_usd"] is None:
                liabilities.append(call["args"]["est_usd"])
            liabilities.extend(call["disputed_liabilities"])
        return known, sum_money(liabilities)

    @staticmethod
    def _holds(state):
        reasons = list(state["faults"])
        if state["plan"] and compare_money(add_money(state["plan"]["worst_schedule_usd"], sum_money(expense["cost_usd"] for expense in state["expenses"].values())), state["budget_usd"]) > 0:
            reasons.append("frozen_full_schedule_unfunded")
        if any(call["state"] in {"sent", "unknown"} for call in state["calls"].values()):
            reasons.append("unresolved_sent_or_unknown_outcome")
        known, reserved = Ledger._totals(state)
        if compare_money(add_money(known, reserved), state["budget_usd"]) > 0:
            reasons.append("configured_budget_exceeded")
        return sorted(set(reasons))

    def _call(self, state, call_id):
        identifier(call_id)
        if call_id not in state["calls"]:
            raise LedgerError("unknown_call", "No matching reserved ID")
        return state["calls"][call_id]

    def reserve(self, call_id, arm, task, sample, attempt, est_usd, *, bounds: CostBounds | None = None):
        identifier(call_id)
        identifier(task)
        if arm not in {"A", "B", "C", "D", "R"} or type(sample) is not int or sample != 1 or type(attempt) is not int or not 0 <= attempt <= 3:
            raise LedgerError("invalid_call", "Closed arm/k1/attempt0..3 required")
        if bounds is not None and not isinstance(bounds, CostBounds):
            raise LedgerError("invalid_bounds", "CostBounds required")
        args = {"call_id": call_id, "arm": arm, "task": task, "sample": sample, "attempt": attempt,
                "est_usd": canonical_money(est_usd), "bounds": bounds.as_dict() if bounds else None}
        with self._transaction() as (connection, events, state):
            if call_id in state["calls"]:
                if state["calls"][call_id]["args"] != args:
                    raise LedgerError("immutable_call", "Same ID cannot change arguments")
                return dict(state["calls"][call_id])
            if self._holds(state):
                raise LedgerError("ledger_halted", "Unknown outcome/accounting fault blocks new reservations")
            if state["plan"] and bounds and bounds.model_id not in state["plan"]["model_ids"]:
                raise LedgerError("model_exchange", "Model absent from frozen price plan")
            known, reserved = self._totals(state)
            if compare_money(sum_money([known, reserved, args["est_usd"]]), state["budget_usd"]) > 0:
                raise LedgerError("budget_exceeded", "Atomic reservation exceeds configured headroom")
            self._append(connection, events, "reserve", args)
            self._apply(state, "reserve", args)
            return dict(state["calls"][call_id])

    def mark_sent(self, call_id):
        """Persist intent before an external send; NEVER performs/authorizes it."""
        with self._transaction() as (connection, events, state):
            call = self._call(state, call_id)
            if call["state"] != "reserved" or call["was_sent"] or self._holds(state):
                raise LedgerError("not_dispatchable", "Only proven never-sent reserved ID without global holds")
            if not state["plan"] or not call["args"]["bounds"]:
                raise LedgerError("unbounded_price", "Frozen full-schedule plan and complete fee bounds required")
            bounds = CostBounds(**call["args"]["bounds"])
            if not bounds.complete or bounds.model_id not in state["plan"]["model_ids"] or compare_money(bounds.other_fees_usd, call["args"]["est_usd"]) > 0:
                raise LedgerError("unbounded_price", "Absent fee/token bounds forbid send marker")
            payload = {"call_id": call_id}
            self._append(connection, events, "sent", payload)
            return {"call_id": call_id, "state": "sent", "dispatch_allowed": False, "backend_status": "backend_unverified"}

    def mark_unknown(self, call_id, reason):
        if type(reason) is not str or not reason:
            raise LedgerError("invalid_reason", "Unknown reason required")
        with self._transaction() as (connection, events, state):
            call = self._call(state, call_id)
            if not call["was_sent"]:
                raise LedgerError("never_sent", "Unknown outcome requires prior sent marker")
            if call["state"] == "unknown" and call["unknown_reason"] == reason:
                return
            payload = {"call_id": call_id, "reason": reason, "raw": None}
            self._append(connection, events, "unknown", payload)

    def settle(self, call_id, status, usage, cost_or_none):
        """Record facts even over reserve/budget; missing/malformed facts halt."""
        with self._transaction() as (connection, events, state):
            call = self._call(state, call_id)
            try:
                cost = None if cost_or_none is None else canonical_money(cost_or_none)
            except (LedgerError, MoneyError, TypeError, ValueError) as error:
                payload = {"call_id": call_id, "reason": "malformed_settlement:" + str(error),
                           "raw": {"status": raw_declaration(status), "usage": raw_declaration(usage), "cost": raw_declaration(cost_or_none)}}
                self._append(connection, events, "unknown", payload)
                return {"recorded": "unknown", "dispatch_allowed": False}
            issues = []
            normalized_status = status
            if type(status) is not str or status not in TERMINAL:
                normalized_status = "malformed"
                issues.append("invalid_status")
            if normalized_status == "not_sent" and (call["was_sent"] or cost != "0"):
                normalized_status = "malformed"
                issues.append("invalid_never_sent_claim")
            try:
                normalized = normalize_usage(usage)
            except (LedgerError, TypeError, ValueError):
                normalized = normalize_usage(None)
                issues.append("invalid_usage")
            # A valid monetary fact survives malformed status/usage metadata.
            payload = {"call_id": call_id, "status": normalized_status, "usage": normalized,
                       "cost_usd": cost, "issues": issues,
                       "raw": {"status": raw_declaration(status), "usage": raw_declaration(usage)} if issues else None}
            if payload in call["settlement_history"]:
                return dict(call)
            kind = "conflict" if call["cost_usd"] is not None else "settle"
            self._append(connection, events, kind, payload)
            self._apply(state, kind, payload)
            return dict(state["calls"][call_id])

    def link_shared_c(self, call_id, arm, task, sample):
        if arm not in {"D", "R"} or type(sample) is not int or sample != 1:
            raise LedgerError("invalid_attribution", "Shared C attribution only D/R sample1")
        with self._transaction() as (connection, events, state):
            call = self._call(state, call_id)
            if call["args"]["arm"] != "C" or call["args"]["task"] != task or call["args"]["sample"] != sample:
                raise LedgerError("invalid_attribution", "Shared C task/sample mismatch")
            payload = {"call_id": call_id, "arm": arm, "task": task, "sample": sample}
            if payload not in state["links"]:
                self._append(connection, events, "link", payload)

    def record_expense(self, expense_id, cost_usd, reason):
        identifier(expense_id)
        if type(reason) is not str or not reason:
            raise LedgerError("invalid_reason", "Actual expense explanation required")
        payload = {"expense_id": expense_id, "cost_usd": canonical_money(cost_usd), "reason": reason}
        with self._transaction() as (connection, events, state):
            if expense_id in state["expenses"]:
                if state["expenses"][expense_id] != payload:
                    raise LedgerError("immutable_expense", "Existing expense cannot be replaced")
                return
            self._append(connection, events, "expense", payload)

    def report(self):
        with self._transaction() as (_, events, state):
            known, liability = self._totals(state)
            attribution = {}
            for arm in ("A", "B", "C", "D", "R"):
                ids = {key for key, call in state["calls"].items() if call["args"]["arm"] == arm}
                ids.update(link["call_id"] for link in state["links"] if link["arm"] == arm)
                attribution[arm] = {"inclusive_call_ids": sorted(ids), "known_usd": sum_money(state["calls"][key]["cost_usd"] or "0" for key in ids),
                                    "reserved_unknown_usd": sum_money([state["calls"][key]["args"]["est_usd"] for key in ids if state["calls"][key]["cost_usd"] is None] + [item for key in ids for item in state["calls"][key]["disputed_liabilities"]])}
            return {"backend_status": "backend_unverified", "dispatch_allowed": False,
                    "budget_usd": state["budget_usd"], "known_usd": known, "reserved_unknown_usd": liability,
                    "remaining_usd": subtract_money(state["budget_usd"], add_money(known, liability)),
                    "halt_reasons": self._holds(state), "plan": state["plan"], "calls": state["calls"],
                    "other_expenses": state["expenses"], "arm_inclusive": attribution,
                    "event_count": len(events), "genesis_sha256": events[0]["sha256"], "last_sha256": events[-1]["sha256"],
                    "eligibility_is_authority": False}

    def export(self, path):
        from .projection import export_jsonl
        # Same-ledger writers and exporters serialize through this DB lock.
        with self._transaction() as (_, events, __):
            return export_jsonl(Path(path), events, protected_database=self.path)

    def _apply(self, state, kind, payload):
        """Replay valid state transitions; event hash alone is insufficient."""
        if kind == "init":
            _closed(payload, {"version", "budget_usd", "plan"})
            if state["budget_usd"] is not None or type(payload["version"]) is not int or payload["version"] != 1:
                raise LedgerError("audit_corrupt", "Duplicate/wrong genesis")
            state["budget_usd"] = canonical_money(payload["budget_usd"])
            plan = payload["plan"]
            if plan is not None:
                _closed(plan, {"run_plan_sha256", "prices_sha256", "model_ids", "worst_schedule_usd"})
                plan = PricePlan(**{**plan, "model_ids": tuple(plan["model_ids"])}).as_dict()
                if compare_money(plan["worst_schedule_usd"], state["budget_usd"]) > 0:
                    raise LedgerError("audit_corrupt", "Unfunded genesis schedule")
            state["plan"] = plan
            return
        if state["budget_usd"] is None:
            raise LedgerError("audit_corrupt", "Transition before genesis")
        if kind == "reserve":
            _closed(payload, {"call_id", "arm", "task", "sample", "attempt", "est_usd", "bounds"})
            key = identifier(payload["call_id"])
            identifier(payload["task"])
            if key in state["calls"] or payload["arm"] not in {"A", "B", "C", "D", "R"} or type(payload["sample"]) is not int or payload["sample"] != 1 or type(payload["attempt"]) is not int or not 0 <= payload["attempt"] <= 3 or self._holds(state):
                raise LedgerError("audit_corrupt", "Invalid reserve transition")
            canonical_money(payload["est_usd"])
            known, liabilities = self._totals(state)
            if compare_money(sum_money([known, liabilities, payload["est_usd"]]), state["budget_usd"]) > 0:
                raise LedgerError("audit_corrupt", "Unfunded recorded reservation")
            if payload["bounds"] is not None:
                CostBounds(**payload["bounds"])
                if state["plan"] and payload["bounds"]["model_id"] not in state["plan"]["model_ids"]:
                    raise LedgerError("audit_corrupt", "Recorded model exchange")
            state["calls"][key] = {"args": payload, "state": "reserved", "was_sent": False, "cost_usd": None,
                                    "status": None, "usage": normalize_usage(None), "last_settlement": None,
                                    "unknown_reason": None, "disputed_liabilities": [], "settlement_history": []}
            return
        if kind == "expense":
            _closed(payload, {"expense_id", "cost_usd", "reason"})
            key = identifier(payload["expense_id"])
            if key in state["expenses"] or not isinstance(payload["reason"], str) or not payload["reason"]:
                raise LedgerError("audit_corrupt", "Duplicate/invalid actual expense")
            canonical_money(payload["cost_usd"])
            state["expenses"][key] = payload
            return
        key = payload.get("call_id") if type(payload) is dict else None
        call = self._call(state, key)
        if kind == "sent":
            _closed(payload, {"call_id"})
            bounds = call["args"]["bounds"]
            if call["state"] != "reserved" or call["was_sent"] or self._holds(state) or not state["plan"] or bounds is None or not CostBounds(**bounds).complete or compare_money(bounds["other_fees_usd"], call["args"]["est_usd"]) > 0:
                raise LedgerError("audit_corrupt", "Invalid sent transition")
            call["state"], call["was_sent"] = "sent", True
        elif kind == "unknown":
            _closed(payload, {"call_id", "reason", "raw"})
            if not isinstance(payload["reason"], str) or not payload["reason"]:
                raise LedgerError("audit_corrupt", "Invalid unknown reason")
            if call["cost_usd"] is not None:
                call["disputed_liabilities"].append(call["args"]["est_usd"])
                state["faults"].append("late_unknown:" + key)
            call["state"], call["unknown_reason"] = "unknown", payload["reason"]
        elif kind in {"settle", "conflict"}:
            _closed(payload, {"call_id", "status", "usage", "cost_usd", "issues", "raw"})
            if type(payload["issues"]) is not list or any(type(item) is not str for item in payload["issues"]):
                raise LedgerError("audit_corrupt", "Invalid settlement issue record")
            if payload["issues"]:
                state["faults"].append("malformed_settlement_metadata:" + key)
            if payload in call["settlement_history"]:
                raise LedgerError("audit_corrupt", "Duplicate settlement declaration")
            call["settlement_history"].append(payload)
            if payload["status"] not in TERMINAL:
                raise LedgerError("audit_corrupt", "Invalid settlement status")
            usage = normalize_usage(payload["usage"])
            cost = payload["cost_usd"]
            if cost is not None:
                canonical_money(cost)
            if payload["status"] == "not_sent" and (call["was_sent"] or cost != "0"):
                raise LedgerError("audit_corrupt", "Invalid never-sent claim")
            if kind == "conflict":
                if call["cost_usd"] is None:
                    raise LedgerError("audit_corrupt", "Conflict without previous known settlement")
                call["disputed_liabilities"].append(cost if cost is not None else call["args"]["est_usd"])
                call["state"] = "unknown"
                state["faults"].append("conflicting_settlement:" + key)
                return
            if call["cost_usd"] is not None:
                raise LedgerError("audit_corrupt", "Known settlement replacement")
            if payload["status"] != "not_sent":
                if not call["was_sent"]:
                    state["faults"].append("settlement_without_sent_marker:" + key)
                call["was_sent"] = True
            call.update(state="unknown" if cost is None else "settled", status=payload["status"], usage=usage,
                        cost_usd=cost, last_settlement=payload, unknown_reason="cost_missing" if cost is None else None)
            if cost is not None and compare_money(cost, call["args"]["est_usd"]) > 0:
                state["faults"].append("cost_exceeds_reserve:" + key)
        elif kind == "link":
            _closed(payload, {"call_id", "arm", "task", "sample"})
            if payload in state["links"] or payload["arm"] not in {"D", "R"} or call["args"]["arm"] != "C" or payload["task"] != call["args"]["task"] or type(payload["sample"]) is not int or payload["sample"] != call["args"]["sample"]:
                raise LedgerError("audit_corrupt", "Invalid shared-C link")
            state["links"].append(payload)
        else:
            raise LedgerError("audit_corrupt", "Unknown event kind")
