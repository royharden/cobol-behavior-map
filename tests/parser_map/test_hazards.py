"""Future native parser/map regressions for disclosed, builder-authored sources.

Construction only: this test was not imported or run in the Dirty Mode work.
Each proposal is an authored static expectation, not an oracle result.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest


FIXTURES = Path(__file__).resolve().parents[2] / "corpus" / "fixtures" / "parser-map" / "hazards"


class HazardSourceRegressions(unittest.TestCase):
    def test_native_hazard_id_and_exact_target_span(self) -> None:
        # Deferred native calls. Import here so this source can be inspected without
        # inadvertently invoking parser/map construction during Dirty Mode.
        from cobolmap.mapping import build_map
        from cobolmap.parse import parse

        proposals = sorted(FIXTURES.glob("h*.proposal.json"))
        self.assertEqual(17, len(proposals), "one declared case per authored fixture")
        for proposal_path in proposals:
            with self.subTest(fixture=proposal_path.name):
                proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
                source_path = FIXTURES / (proposal["fixture_id"] + ".cbl")
                raw = source_path.read_bytes()
                digest = sha256(raw).hexdigest()
                self.assertEqual(proposal["source"]["raw_sha256"], digest)
                self.assertEqual(proposal["source"]["source_sha256"], digest)
                target = proposal["expected_static_hazard"]
                needle = target["at_statement"].encode("ascii")
                self.assertEqual(1, raw.count(needle), "target statement must bind uniquely")

                program = parse(raw.decode("ascii"), filename=source_path.name)
                behavior_map = build_map(program)
                self.assertEqual(digest, behavior_map.source_sha256)
                self.assertEqual(source_path.name, behavior_map.filename)
                at_target = []
                for hazard in behavior_map.hazards:
                    span = hazard.span
                    self.assertEqual(digest, span.source_sha256)
                    self.assertEqual(source_path.name, span.filename)
                    selected = raw[span.byte_start:span.byte_end]
                    self.assertTrue(selected, "hazard needs a nonempty source binding")
                    self.assertEqual(raw[:span.byte_start].count(b"\n") + 1, span.line_start)
                    self.assertEqual(raw[:span.byte_end - 1].count(b"\n") + 1, span.line_end)
                    if selected == needle and hazard.hazard_id == target["hazard_id"]:
                        at_target.append(hazard)
                self.assertEqual(
                    target["present"], bool(at_target),
                    proposal["what_bug_this_catches"],
                )


if __name__ == "__main__":
    unittest.main()
