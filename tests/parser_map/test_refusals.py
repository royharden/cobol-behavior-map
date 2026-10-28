"""Deferred builder refusal regressions. Do not import/run under Dirty construction."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus/fixtures/parser-map/refusals"

class RefusalRegressions(unittest.TestCase):
    def test_native_refusal_cases(self):
        from cobolmap.parse import parse, ParseRefusal
        cases = json.loads((FIXTURES / "inventory.json").read_bytes())["cases"]
        self.assertGreaterEqual(len(cases), 18)
        for case in cases:
            with self.subTest(case=case["case_id"], regression=case["what_bug_this_catches"]):
                raw = (ROOT / case["source"]["path"]).read_bytes()
                with self.assertRaises(ParseRefusal) as caught:
                    parse(raw.decode("utf-8"), filename=case["logical_filename"])
                error = caught.exception
                self.assertEqual(error.code, case["expected_static_code"])
                pointer = error.span
                self.assertEqual(pointer.source_sha256, hashlib.sha256(raw).hexdigest())
                self.assertEqual(pointer.filename, case["diagnostic_filename"])
                self.assertTrue(0 <= pointer.byte_start <= pointer.byte_end <= len(raw))
                self.assertEqual(pointer.line_start, raw[:pointer.byte_start].count(b"\n") + 1)
                endpoint = pointer.byte_end - 1 if pointer.byte_end > pointer.byte_start else pointer.byte_start
                self.assertEqual(pointer.line_end, raw[:endpoint].count(b"\n") + 1)
                focus = case["failure_focus"]
                if focus is not None:
                    self.assertLess(pointer.byte_start, focus["byte_end"])
                    self.assertGreater(pointer.byte_end, focus["byte_start"])

    def test_partial_parse_code_gap(self):
        self.skipTest("SUBSET lists partial_parse, but current parser emits no such code: trailing tokens are consumed as paragraphs or fail another stage. No fabricated trigger.")
