"""Synthetic LOCAL ledger unit diagnostics; amounts are NOT app spend.

All DB/log artifacts stay in one fresh project-local run namespace. No cleanup,
provider/account/backend/candidate/guest/authority path or external database.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
from threading import Barrier
import unittest
import uuid

from cobolmap.shared.callledger import Ledger, PricePlan, CostBounds, LedgerError
from cobolmap.shared.callledger.models import normalize_usage
from cobolmap.shared.callledger.money import canonical_money, add_money, subtract_money, MoneyError

ROOT = Path(__file__).resolve().parents[2]


def digest(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def unit_plan(worst="10", *, prices="SYNTHETIC_UNIT_PRICES"):
    # Deliberately synthetic plan commitments/model; never approved real pricing.
    return PricePlan(digest("SYNTHETIC_UNIT_RUN"), digest(prices), ("synthetic-ledger-model",), worst)


def unit_bounds(*, complete=True, model="synthetic-ledger-model"):
    return CostBounds(model, 10, 10, 0 if complete else None, 0, 0, "0", True)


def unit_usage():
    return dict(input_tokens=1, output_tokens=1, cache_read_tokens=0, cache_write_tokens=0,
                reasoning_tokens=0, other_tokens=0, reasoning_in_output=False)


class LocalLedgerDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = ROOT / ".agent-work" / "callledger-diagnostics"
        if not base.resolve().is_relative_to(ROOT):
            raise RuntimeError("diagnostic namespace escapes owned worktree")
        for item in (base, *base.parents):
            if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
                raise RuntimeError("linked diagnostic namespace refused")
            if item == ROOT: break
        base.mkdir(parents=True, exist_ok=True)
        run_id = "r6-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
        cls.run_root = base / run_id
        cls.run_root.mkdir(exist_ok=False)
        print("PRESERVED_LEDGER_RUN_ROOT=" + str(cls.run_root), flush=True)

    @classmethod
    def tearDownClass(cls):
        # Preserve originals, deliberate copies, projections and every local file.
        artifacts = []
        for path in sorted(cls.run_root.iterdir()):
            if path.is_file():
                raw = path.read_bytes()
                artifacts.append(dict(path=str(path), byte_length=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        record = dict(synthetic_currency_only=True, actual_app_spend_usd="0", run_root=str(cls.run_root), files=artifacts,
                      backend_authority=False, cleanup_performed=False)
        with (cls.run_root / "artifact_manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, indent=2)
            stream.write("\n")

    def path(self, label="unit", suffix=".sqlite", *, reserve=False):
        if re.fullmatch("[a-z0-9_-]{1,20}", label) is None:
            raise ValueError("bounded local diagnostic filename required")
        path = self.run_root / (label + "-" + uuid.uuid4().hex[:12] + suffix)
        self.assertTrue(path.resolve().is_relative_to(self.run_root.resolve()))
        self.assertFalse(path.exists(), "never overwrite a prior artifact")
        if reserve:
            with path.open("xb"): pass  # Exclusive fresh empty DB pathname only.
        return path

    def ledger(self, budget="20", worst="10", *, plan=True):
        path = self.path("ledger", reserve=True)
        frozen = unit_plan(worst) if plan else None
        return Ledger(path, budget, plan=frozen)

    def copy_db(self, ledger, label):
        target = self.path(label)
        # Native ledger closes per-operation connections. No live/WAL copy claim.
        with ledger.path.open("rb") as source, target.open("xb") as dest:
            shutil.copyfileobj(source, dest)
        return target

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(LedgerError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def reserve(self, ledger, call="unit_call", estimate="4", arm="B", attempt=0, bounds=True):
        return ledger.reserve(call, arm, "synthetic_ledger_task", 1, attempt, estimate,
                              bounds=unit_bounds() if bounds else None)

    def assert_inert(self, report):
        self.assertEqual(report["backend_status"], "backend_unverified")
        self.assertIs(report["dispatch_allowed"], False)
        self.assertIs(report["eligibility_is_authority"], False)

    def test_exact_money_independent_of_decimal_precision(self):
        """Catches float/ambient-context rounding and debt clamping."""
        with localcontext() as ctx:
            ctx.prec = 2
            self.assertEqual(add_money("0.123456789", "0.000000001"), "0.12345679")
            self.assertEqual(canonical_money(Decimal("001.2300")), "1.23")
        self.assertEqual(add_money("9" * 128, "1"), "1" + "0" * 128)
        self.assertEqual(subtract_money("1", "1.25"), "-0.25")
        self.assertEqual(canonical_money("0000.000"), "0")

    def test_money_malformed_values_never_become_zero(self):
        """Catches treating bool/float/NaN/exponent/overflow as valid declarations."""
        for value in (True, 0.1, "-1", "1e2", "NaN", Decimal("NaN"), "1" * 129, "0." + "1" * 129):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(MoneyError):
                canonical_money(value)
        self.assertEqual(canonical_money("0.10"), "0.1")

    def test_usage_and_bounds_preserve_unknown_and_strict_counts(self):
        """Catches missing categories becoming zero or bools masquerading as tokens."""
        self.assertTrue(unit_bounds().complete)
        self.assertFalse(unit_bounds(complete=False).complete)
        self.assertTrue(all(value is None for value in normalize_usage(None).values()))
        self.assertEqual(normalize_usage(unit_usage())["cache_read_tokens"], 0)
        for supplied in ({"input_tokens": True}, {"unknown_tokens": 0}):
            self.assert_code("invalid_usage", normalize_usage, supplied)
        self.assert_code("invalid_bounds", CostBounds, "synthetic-ledger-model", True, 10, 0, 0, 0, "0", True)

    def test_reservation_replay_and_configuration_are_immutable(self):
        """Catches same-ID argument drift, top-up/reprice and duplicate audit events."""
        ledger = self.ledger()
        self.reserve(ledger)
        first = ledger.report()
        self.reserve(ledger, estimate="4.00")
        self.assertEqual(ledger.report()["last_sha256"], first["last_sha256"])
        self.assert_code("immutable_call", self.reserve, ledger, estimate="5")
        reopened = Ledger(ledger.path, "020.00", plan=unit_plan())
        self.assertEqual(reopened.report()["calls"], first["calls"])
        self.assert_code("immutable_configuration", Ledger, ledger.path, "21", plan=unit_plan())
        self.assert_code("immutable_configuration", Ledger, ledger.path, "20", plan=unit_plan(prices="SYNTHETIC_OTHER_PRICES"))
        self.assertEqual(ledger.report()["event_count"], first["event_count"])
        self.assert_inert(first)

    def test_atomic_budget_and_schedule_caps_have_positive_controls(self):
        """Catches reservations exceeding headroom or accepting an unfunded full plan."""
        ledger = self.ledger("10", "10")
        self.reserve(ledger, estimate="8")
        self.assert_code("budget_exceeded", self.reserve, ledger, call="unit_second", estimate="3")
        self.assertEqual(ledger.report()["reserved_unknown_usd"], "8")
        self.assertEqual(ledger.report()["remaining_usd"], "2")
        self.assert_code("schedule_unfunded", self.ledger, "10", "11")
        self.assert_code("invalid_call", ledger.reserve, "unit_bad_sample", "B", "synthetic_ledger_task", True, 0, "1")
        self.assertEqual(len(ledger.report()["calls"]), 1)

    def test_full_schedule_holds_even_when_one_more_call_is_affordable(self):
        """Catches per-call checks bypassing frozen full-schedule plus other expenses."""
        good = self.ledger("10", "9")
        good.record_expense("unit_expense", "1", "SYNTHETIC UNIT ONLY, NOT SPEND")
        self.reserve(good, estimate="1")
        blocked = self.ledger("10", "9")
        blocked.record_expense("unit_expense", "2", "SYNTHETIC UNIT ONLY, NOT SPEND")
        self.assertIn("frozen_full_schedule_unfunded", blocked.report()["halt_reasons"])
        self.assert_code("ledger_halted", self.reserve, blocked, estimate="1")
        self.assertEqual(blocked.report()["calls"], {})

    def test_unbounded_fees_and_model_exchange_block_sent_markers(self):
        """Catches missing fee bounds or a new model enabling bookkeeping eligibility."""
        ledger = self.ledger()
        ledger.reserve("unit_partial", "B", "synthetic_ledger_task", 1, 0, "4", bounds=unit_bounds(complete=False))
        self.assert_code("unbounded_price", ledger.mark_sent, "unit_partial")
        self.assert_code("model_exchange", ledger.reserve, "unit_model", "B", "synthetic_ledger_task", 1, 0, "1", bounds=unit_bounds(model="synthetic-other-model"))
        positive = self.ledger()
        self.reserve(positive)
        marker = positive.mark_sent("unit_call")
        self.assertIs(marker["dispatch_allowed"], False)
        self.assertEqual(positive.report()["calls"]["unit_call"]["state"], "sent")
        self.assert_inert(positive.report())

    def test_sent_unknown_globally_halts_then_same_id_reconciles(self):
        """Catches resending/regenerating unknown outcomes or losing held liability."""
        ledger = self.ledger()
        self.reserve(ledger)
        ledger.mark_sent("unit_call")
        self.assert_code("ledger_halted", self.reserve, ledger, call="unit_second", estimate="1")
        self.assert_code("not_dispatchable", ledger.mark_sent, "unit_call")
        ledger.mark_unknown("unit_call", "SYNTHETIC UNIT OUTCOME UNKNOWN")
        unknown = ledger.report()
        self.assertEqual(unknown["reserved_unknown_usd"], "4")
        self.assertEqual(unknown["known_usd"], "0")
        self.assertIn("unresolved_sent_or_unknown_outcome", unknown["halt_reasons"])
        ledger.settle("unit_call", "failed", unit_usage(), "2")
        self.reserve(ledger, call="unit_second", estimate="1")
        self.assertEqual(ledger.report()["known_usd"], "2")
        self.assertEqual(ledger.report()["reserved_unknown_usd"], "1")
        self.assert_inert(ledger.report())

    def test_failed_refused_and_never_sent_settlements_are_not_free_inference(self):
        """Catches dropping failed/refused charges and falsely clearing sent holds."""
        for status in ("failed", "refused"):
            ledger = self.ledger()
            self.reserve(ledger)
            ledger.mark_sent("unit_call")
            ledger.settle("unit_call", status, unit_usage(), "1.25")
            first = ledger.report()
            ledger.settle("unit_call", status, unit_usage(), "1.25")
            self.assertEqual(ledger.report()["event_count"], first["event_count"])
            self.assertEqual(first["known_usd"], "1.25")
        never = self.ledger()
        self.reserve(never)
        never.settle("unit_call", "not_sent", None, "0")
        self.assertEqual(never.report()["reserved_unknown_usd"], "0")
        self.assertFalse(never.report()["calls"]["unit_call"]["was_sent"])
        sent = self.ledger()
        self.reserve(sent)
        sent.mark_sent("unit_call")
        sent.settle("unit_call", "not_sent", unit_usage(), "0")
        invalid = sent.report()
        self.assertEqual(invalid["calls"]["unit_call"]["status"], "malformed")
        self.assertIn("malformed_settlement_metadata:unit_call", invalid["halt_reasons"])

    def test_missing_or_malformed_cost_retains_liability_and_raw_declaration(self):
        """Catches missing/invalid billed amount being rounded, lost or made free."""
        ledger = self.ledger()
        self.reserve(ledger)
        ledger.mark_sent("unit_call")
        ledger.settle("unit_call", "success", None, None)
        self.assertEqual(ledger.report()["reserved_unknown_usd"], "4")
        ledger.settle("unit_call", "success", unit_usage(), 0.25)
        with closing(sqlite3.connect(str(ledger.path))) as connection:
            raw = json.loads(connection.execute("SELECT payload FROM events WHERE kind='unknown' ORDER BY seq DESC LIMIT 1").fetchone()[0])
        self.assertEqual(raw["raw"]["cost"], {"invalid_float": "0.25"})
        self.assertEqual(ledger.report()["known_usd"], "0")
        self.assertEqual(ledger.report()["reserved_unknown_usd"], "4")
        ledger.settle("unit_call", "success", unit_usage(), "0.25")
        self.assertEqual(ledger.report()["known_usd"], "0.25")

    def test_malformed_usage_keeps_money_and_overreserve_fault(self):
        """Catches invalid usage erasing a real declared charge or clamping excess."""
        ledger = self.ledger()
        self.reserve(ledger, estimate="1")
        ledger.mark_sent("unit_call")
        ledger.settle("unit_call", "success", {"input_tokens": True}, "1.5")
        report = ledger.report()
        self.assertEqual(report["known_usd"], "1.5")
        self.assertIn("malformed_settlement_metadata:unit_call", report["halt_reasons"])
        self.assertIn("cost_exceeds_reserve:unit_call", report["halt_reasons"])
        self.assertTrue(all(value is None for value in report["calls"]["unit_call"]["usage"].values()))
        self.assert_inert(report)

    def test_overbudget_known_fact_persists_negative_headroom(self):
        """Catches rejecting or capping a cost fact to keep a positive budget display."""
        ledger = self.ledger("10", "10")
        self.reserve(ledger, estimate="3")
        ledger.mark_sent("unit_call")
        ledger.settle("unit_call", "failed", unit_usage(), "11")
        report = ledger.report()
        self.assertEqual(report["known_usd"], "11")
        self.assertEqual(report["remaining_usd"], "-1")
        self.assertIn("configured_budget_exceeded", report["halt_reasons"])
        self.assert_code("ledger_halted", self.reserve, ledger, call="unit_second", estimate="0")

    def test_conflict_preserves_first_cost_and_full_disputed_liability(self):
        """Catches overwriting history or double-counting known charge on conflict."""
        ledger = self.ledger()
        self.reserve(ledger)
        ledger.mark_sent("unit_call")
        ledger.settle("unit_call", "success", unit_usage(), "2")
        ledger.settle("unit_call", "success", unit_usage(), "3")
        report = ledger.report()
        self.assertEqual(report["known_usd"], "2")
        self.assertEqual(report["reserved_unknown_usd"], "3")
        self.assertEqual(report["calls"]["unit_call"]["cost_usd"], "2")
        self.assertIn("conflicting_settlement:unit_call", report["halt_reasons"])
        first = report["event_count"]
        ledger.settle("unit_call", "success", unit_usage(), "3")
        self.assertEqual(ledger.report()["event_count"], first)

    def test_shared_C_zero_repair_inheritance_dedups_app_and_separates_expenses(self):
        """Catches fake repair calls, summed inclusive arms and duplicate expenses."""
        ledger = self.ledger()
        self.reserve(ledger, call="unit_C", arm="C")
        ledger.mark_sent("unit_C")
        ledger.settle("unit_C", "success", unit_usage(), "2")
        for arm in ("D", "R"):
            ledger.link_shared_c("unit_C", arm, "synthetic_ledger_task", 1)
        first = ledger.report()
        self.assertEqual(len(first["calls"]), 1)
        self.assertEqual(first["known_usd"], "2")
        for arm in ("D", "R"):
            self.assertEqual(first["arm_inclusive"][arm]["inclusive_call_ids"], ["unit_C"])
            self.assertEqual(first["arm_inclusive"][arm]["known_usd"], "2")
            ledger.link_shared_c("unit_C", arm, "synthetic_ledger_task", 1)
        self.assertEqual(ledger.report()["event_count"], first["event_count"])
        self.reserve(ledger, call="unit_D", estimate="1", arm="D", attempt=1)
        ledger.mark_sent("unit_D")
        ledger.settle("unit_D", "success", unit_usage(), "1")
        ledger.record_expense("unit_expense", "0.5", "SYNTHETIC UNIT ONLY, NOT SPEND")
        report = ledger.report()
        self.assertEqual(report["known_usd"], "3.5")
        self.assertEqual(report["arm_inclusive"]["D"]["known_usd"], "3")
        self.assertEqual(report["arm_inclusive"]["R"]["known_usd"], "2")
        ledger.record_expense("unit_expense", "0.5", "SYNTHETIC UNIT ONLY, NOT SPEND")
        self.assertEqual(ledger.report()["event_count"], report["event_count"])
        self.assert_code("immutable_expense", ledger.record_expense, "unit_expense", "0.6", "SYNTHETIC UNIT ONLY, NOT SPEND")
        self.assert_code("invalid_attribution", ledger.link_shared_c, "unit_C", "D", "synthetic_wrong_task", 1)

    def test_append_only_and_duplicate_events_refuse_on_fresh_copy(self):
        """Catches removable audit facts while retaining untouched original/copy."""
        ledger = self.ledger()
        self.reserve(ledger)
        original_hash = hashlib.sha256(ledger.path.read_bytes()).hexdigest()
        copy = self.copy_db(ledger, "trigger-copy")
        with closing(sqlite3.connect(str(copy))) as connection:
            for sql in ("UPDATE events SET payload='{}' WHERE seq=1", "DELETE FROM events WHERE seq=1",
                        "INSERT INTO events SELECT seq+100,event_id,kind,created_at,payload,previous_sha256,sha256 FROM events WHERE seq=1"):
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(sql)
                connection.rollback()
        self.assertEqual(Ledger(copy, "20", plan=unit_plan()).report()["event_count"], 2)
        self.assertEqual(hashlib.sha256(ledger.path.read_bytes()).hexdigest(), original_hash)

    def test_tampered_copy_fails_hash_replay_original_remains_usable(self):
        """Catches trusting mutable projection state or unhashed event payloads."""
        ledger = self.ledger()
        self.reserve(ledger)
        original_hash = hashlib.sha256(ledger.path.read_bytes()).hexdigest()
        copy = self.copy_db(ledger, "tampered-copy")
        with closing(sqlite3.connect(str(copy))) as connection:
            connection.execute("DROP TRIGGER events_no_update")
            connection.execute("UPDATE events SET payload='{}' WHERE seq=1")
            connection.commit()
        self.assert_code("audit_corrupt", Ledger, copy, "20", plan=unit_plan())
        self.assertEqual(hashlib.sha256(ledger.path.read_bytes()).hexdigest(), original_hash)
        self.assertEqual(Ledger(ledger.path, "20", plan=unit_plan()).report()["event_count"], 2)

    def test_projection_is_append_prefix_and_refuses_database_alias(self):
        """Catches rewritten exports, duplicate lines or clobbering SQLite itself."""
        ledger = self.ledger()
        projection = self.path("events", ".jsonl", reserve=True)
        initial = ledger.export(projection)
        prefix = projection.read_bytes()
        again = ledger.export(projection)
        self.assertEqual(again["appended"], 0)
        self.assertEqual(projection.read_bytes(), prefix)
        self.reserve(ledger)
        appended = ledger.export(projection)
        self.assertEqual(appended["appended"], 1)
        self.assertTrue(projection.read_bytes().startswith(prefix))
        lines = [json.loads(line) for line in projection.read_bytes().splitlines()]
        self.assertEqual(len(lines), initial["event_count"] + 1)
        self.assertEqual(lines[-1]["sha256"], ledger.report()["last_sha256"])
        self.assert_code("projection_path", ledger.export, ledger.path)
        self.assertEqual(ledger.report()["event_count"], len(lines))

    def test_two_concurrent_reservations_cannot_both_exceed_budget(self):
        """Catches a check-then-append race across real independent DB connections."""
        ledger = self.ledger("10", "10")
        barrier = Barrier(2)
        def reserve_one(call):
            own = Ledger(ledger.path, "10", plan=unit_plan())
            barrier.wait(timeout=10)
            try:
                self.reserve(own, call=call, estimate="6")
                return "reserved"
            except LedgerError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(reserve_one, name) for name in ("unit_race_a", "unit_race_b")]
            results = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(results), ["budget_exceeded", "reserved"])
        report = Ledger(ledger.path, "10", plan=unit_plan()).report()
        self.assertEqual(len(report["calls"]), 1)
        self.assertEqual(report["reserved_unknown_usd"], "6")
        self.assertEqual(report["remaining_usd"], "4")
        self.assert_inert(report)
