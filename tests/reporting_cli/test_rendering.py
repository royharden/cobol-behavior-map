"""In-memory SYNTHETIC reporting declarations; no execution evidence or spend.

These tests exercise presentation boundaries only. They create no observations,
receipts, candidates, schedule, compiler output, or authenticated billing data.
"""
from dataclasses import dataclass, replace
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from html.parser import HTMLParser
import json
import unittest

from cobolmap.contracts import RunResult, SourcePointer
from cobolmap.reporting.render import build_document, render_html, render_json, to_data
from evaluation.stats import AttemptCost, summarize_costs


class ParsedReport(HTMLParser):
    """Observe parsed markup, including attributes, instead of string heuristics."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)

    def handle_data(self, data):
        self.text.append(data)


class ReportingBoundaryTests(unittest.TestCase):
    def test_partial_fixture_preserves_denominator_failures_and_cost_uncertainty(self):
        result = RunResult(
            run_id="synthetic-partial", status="partial", evidence_mode="fixture",
            processing_mode="not_run", scheduled=9, passed=2, failed=3, refused=1,
            known_usd="0.0120", reserved_unknown_usd="0.0300",
            d_minus_c="-0.25", d_minus_r=None,
            issues=("SYNTHETIC counts only; three scheduled outcomes unresolved",),
        )
        payload = {"label": "SYNTHETIC fixture; amounts are not spend", "run_result": result}
        document = build_document(
            title="SYNTHETIC partial fixture", status="source_constructed",
            evidence_mode="fixture", payload=payload, issues=result.issues,
        )
        decoded = json.loads(render_json(document))
        self.assertEqual(decoded["recorded_claims"], {
            "status": "partial", "evidence_mode": "fixture", "scheduled": 9,
            "passed": 2, "failed": 3, "refused": 1, "known_usd": "0.0120",
            "reserved_unknown_usd": "0.0300", "d_minus_c": "-0.25", "d_minus_r": None,
        })
        self.assertEqual(decoded["payload"]["run_result"], result.model_dump(mode="json"))
        self.assertEqual(decoded["failures_and_issues"], list(result.issues))
        self.assertEqual(decoded["current_live_run"]["status"], "not_run")
        self.assertTrue(all(value is None for key, value in decoded["current_live_run"].items()
                            if key != "status"))

    def test_untrusted_payload_cannot_promote_live_runtime_or_authority(self):
        payload = {
            "label": "SYNTHETIC unsupported assertions, not evidence",
            "current_live_run": {"status": "completed", "passed": 999, "known_usd": "999"},
            "runtime_status": "verified", "admission_status": "go",
            "authenticity_status": "established", "custody": {"status": "verified"},
            "coverage": {"paragraph": 1.0, "statement": 1.0},
        }
        document = build_document(title="SYNTHETIC", status="source_constructed",
                                  evidence_mode="fixture", payload=payload)
        self.assertEqual(document["runtime_status"], "runtime_unverified")
        self.assertEqual(document["admission_status"], "pending")
        self.assertEqual(document["authenticity_status"], "not_established")
        self.assertEqual(document["construction_exposure"], "private_source_before_admission")
        self.assertEqual(document["custody"]["status"], "unverified")
        self.assertIsNone(document["custody"]["seal_confirmed"])
        self.assertEqual(document["coverage"]["status"], "unknown")
        self.assertIsNone(document["coverage"]["paragraph"])
        self.assertIsNone(document["coverage"]["statement"])
        self.assertTrue(all(v is None for k, v in document["current_live_run"].items() if k != "status"))
        self.assertEqual(document["payload"], payload)
        limitations = " ".join(document["limitations"]).lower()
        for boundary in ("not authentic execution", "scripted data", "never executed", "not an equivalence proof"):
            self.assertIn(boundary, limitations)

    def test_replay_processing_does_not_relabel_source_or_nested_modes(self):
        result = RunResult(run_id="synthetic-not-run", status="not_run", evidence_mode="not_run")
        document = build_document(
            title="SYNTHETIC mode projection", status="replay_recorded", evidence_mode="fixture",
            processing_mode="not_run", payload={"run_result": result},
        )
        self.assertEqual(document["processing_mode"], "replay")
        self.assertEqual(document["source_evidence_mode"], "fixture")
        self.assertEqual(document["payload"]["run_result"]["processing_mode"], "not_run")
        self.assertEqual(document["recorded_claims"]["evidence_mode"], "not_run")
        self.assertIsNone(document["recorded_claims"]["scheduled"])

    def test_hostile_title_source_labels_and_text_are_inert_parsed_text(self):
        hostile = '</pre><script>alert("SYNTHETIC")</script><img src=x onerror=alert(1)>'
        filename = 'synthetic-<svg onload=alert(1)>.cob'
        pointer = SourcePointer(source_sha256="a" * 64, filename=filename,
                                line_start=2, line_end=3, byte_start=8, byte_end=25)
        document = build_document(
            title=hostile, status="source_constructed", evidence_mode="static",
            pointers=(pointer,), issues=(hostile,),
            payload={"source": {"filename": filename, "text": hostile},
                     "source_and_candidate_text": [{"filename": hostile, "text": "javascript:alert(1)"}],
                     "url": "https://synthetic.invalid/never-fetch"},
        )
        parsed = ParsedReport()
        parsed.feed(render_html(document))
        parsed.close()
        self.assertTrue(set(parsed.tags) <= {
            "html", "head", "meta", "title", "style", "body", "header", "h1", "p",
            "section", "h2", "h3", "pre",
        })
        self.assertFalse(any(name.lower().startswith("on") or name in {"href", "src", "action"}
                             for _, name, _ in parsed.attributes))
        text = "".join(parsed.text)
        self.assertIn(hostile, text)
        self.assertIn(filename, text)
        self.assertIn("javascript:alert(1)", text)
        self.assertIn("https://synthetic.invalid/never-fetch", text)
        self.assertIn("never executed", text)
        decoded = json.loads(render_json(document))
        self.assertEqual(decoded["source_pointers"], [pointer.model_dump(mode="json")])

    def test_refusal_retains_issue_and_null_unmeasured_counts(self):
        document = build_document(
            title="SYNTHETIC refusal", status="refused", evidence_mode="not_run",
            issues=("runtime_receipt_missing", "execution_pins_missing"),
        )
        decoded = json.loads(render_json(document))
        self.assertEqual(decoded["status"], "refused")
        self.assertEqual(decoded["failures_and_issues"], ["runtime_receipt_missing", "execution_pins_missing"])
        self.assertTrue(all(value is None for value in decoded["recorded_claims"].values()))
        self.assertIsNone(decoded["current_live_run"]["scheduled"])

    def test_unknown_mode_status_and_processing_mode_are_refused(self):
        defaults = dict(title="SYNTHETIC", status="source_constructed", evidence_mode="not_run")
        for field, invalid in (("status", "completed"), ("evidence_mode", "verified"),
                               ("processing_mode", "execute")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                build_document(**(defaults | {field: invalid}))


class SerializationBoundaryTests(unittest.TestCase):
    def test_supported_values_roundtrip_without_decimal_precision_loss(self):
        class Label(Enum):
            FIXTURE = "fixture"

        @dataclass(frozen=True)
        class Declaration:
            label: Label
            amount: Decimal

        value = {"label": "SYNTHETIC; not spend", "declaration": Declaration(Label.FIXTURE, Decimal("0.0100")),
                 "scalars": (None, True, 7, 0.125, "snowman \u2603 <>&")}
        decoded = json.loads(render_json(value))
        self.assertEqual(decoded, {"label": "SYNTHETIC; not spend",
                                  "declaration": {"label": "fixture", "amount": "0.0100"},
                                  "scalars": [None, True, 7, 0.125, "snowman \u2603 <>&"]})

    def test_nonfinite_values_and_nonstring_keys_are_refused(self):
        for value in (float("nan"), float("inf"), -float("inf"), Decimal("NaN"), Decimal("Infinity")):
            with self.subTest(value=str(value)), self.assertRaises(ValueError):
                render_json({"SYNTHETIC": value})
        with self.assertRaisesRegex(ValueError, "keys must be strings"):
            to_data({1: "SYNTHETIC"})

    def test_unsupported_fraction_cost_summary_is_explicitly_refused(self):
        # No adapter exists from exact Fraction costs to the renderer's data schema.
        summary = summarize_costs((synthetic_cost(),), expected_call_ids=("synthetic-c",))
        with self.assertRaisesRegex(ValueError, "unsupported report value type: Fraction"):
            render_json({"label": "SYNTHETIC projection; not spend", "cost": summary})


def synthetic_cost():
    """Explicit SYNTHETIC charge projection; never a billing observation."""
    return AttemptCost("synthetic-c", "c" * 64, "C", "synthetic-task", "synthetic-model-slot",
                       cost_usd="0.1250", liability_status="known")


class SyntheticCostProjectionTests(unittest.TestCase):
    """Every amount and inventory here is SYNTHETIC and does not establish spend."""

    def test_shared_c_counts_once_in_total_and_in_d_and_r_without_repairs(self):
        result = summarize_costs((synthetic_cost(), synthetic_cost()), expected_call_ids=("synthetic-c",))
        self.assertEqual(result.unique_calls, 1)
        self.assertEqual(result.known_usd, Fraction(1, 8))
        self.assertEqual(result.total_usd, Fraction(1, 8))
        self.assertEqual(dict(result.inclusive_arm_usd), {
            "A": Fraction(0), "B": Fraction(0), "C": Fraction(1, 8),
            "D": Fraction(1, 8), "R": Fraction(1, 8),
        })

    def test_unknown_or_missing_inventory_never_produces_complete_total(self):
        known = synthetic_cost()
        unknown = replace(known, call_id="synthetic-b", arm="B", liability_status="reserved", cost_usd="0.20")
        vectors = (
            ((known,), None, "attempt_inventory_unknown"),
            ((known,), ("synthetic-c", "synthetic-missing"), "synthetic-missing:missing_attempt"),
            ((known, unknown), ("synthetic-c", "synthetic-b"), "synthetic-b:unresolved_liability"),
        )
        for attempts, inventory, issue in vectors:
            with self.subTest(issue=issue):
                result = summarize_costs(attempts, expected_call_ids=inventory)
                self.assertIsNone(result.total_usd)
                self.assertEqual(result.known_usd, Fraction(1, 8))
                self.assertEqual(result.status, "incomplete")
                self.assertIn(issue, result.issues)

    def test_contradictory_duplicate_cost_is_refused(self):
        known = synthetic_cost()
        with self.assertRaisesRegex(ValueError, "contradictory duplicate"):
            summarize_costs((known, replace(known, cost_usd="0.25")), expected_call_ids=("synthetic-c",))
