"""Source-edit diagnostics only; no mutant validity/kills or candidate execution."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import unittest

from evaluation.mutants import MutationRefusal, mutate
from evaluation.mutant_plan import parse_candidate
from instrument_fixtures import binding, digest, literal, node, plan, source, vector


class OperatorVectors(unittest.TestCase):
    def check_edit(self, operator):
        raw, path, expected_value, original_plan = vector(operator)
        result = mutate(raw, operator, binding=binding(raw))
        expected_plan = deepcopy(original_plan)
        target = expected_plan
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = expected_value
        self.assertEqual(parse_candidate(result.changed_candidate).plan, expected_plan)
        self.assertEqual(result.target_path, path)
        self.assertNotEqual(result.changed_candidate, raw)
        self.assertEqual(result.changed_candidate, raw[:result.byte_start] + result.after + raw[result.byte_end:])
        self.assertEqual(result.before, raw[result.byte_start:result.byte_end])
        self.assertEqual(result.before_sha256, sha256(result.before).hexdigest())
        self.assertEqual(result.after_sha256, sha256(result.after).hexdigest())
        self.assertEqual(result.changed_candidate_sha256, sha256(result.changed_candidate).hexdigest())
        self.assertEqual(result.binding.parent_candidate_sha256, sha256(raw).hexdigest())
        self.assertEqual(result.status, 'not_executed')
        self.assertEqual(result.validity, 'pending_external_nonauthor_review')

    def test_m01(self): self.check_edit('M01')
    def test_m02(self): self.check_edit('M02')
    def test_m03(self): self.check_edit('M03')
    def test_m04(self): self.check_edit('M04')
    def test_m05(self): self.check_edit('M05')
    def test_m06(self): self.check_edit('M06')
    def test_m07(self): self.check_edit('M07')
    def test_m08(self): self.check_edit('M08')
    def test_m09(self): self.check_edit('M09')
    def test_m10(self): self.check_edit('M10')
    def test_m11(self): self.check_edit('M11')
    def test_m12(self): self.check_edit('M12')
    def test_m13(self): self.check_edit('M13')
    def test_m14(self): self.check_edit('M14')
    def test_m15(self): self.check_edit('M15')
    def test_m16(self): self.check_edit('M16')
    def test_m17(self): self.check_edit('M17')
    def test_m18(self): self.check_edit('M18')
    def test_m19(self): self.check_edit('M19')
    def test_m20(self): self.check_edit('M20')


class RejectionsAndLineage(unittest.TestCase):
    def test_absent_and_ambiguous_edits_refuse(self):
        absent = source(plan())
        ambiguous = source(plan([node('move', value=literal('A', 'alpha'), target='OUT'),
                                 node('move', value=literal('B', 'alpha'), target='OUT')]))
        for raw in (absent, ambiguous):
            with self.subTest(kind='absent' if raw == absent else 'ambiguous'):
                with self.assertRaisesRegex(MutationRefusal, 'exactly one'):
                    mutate(raw, 'M01', binding=binding(raw))

    def test_zero_sign_and_cosmetic_truncation_are_not_edits(self):
        for operator, text in (('M03', '0'), ('M05', '0.00'), ('M07', '2.00')):
            raw = source(plan([node('move', value=literal(text), target='N')]))
            with self.subTest(operator=operator):
                with self.assertRaisesRegex(MutationRefusal, 'exactly one'):
                    mutate(raw, operator, binding=binding(raw))

    def test_parent_source_scope_and_operator_drift_refuse(self):
        raw, _, _, _ = vector('M11')
        original = binding(raw)
        for changed in (replace(original, parent_candidate_sha256=digest('wrong-parent')),
                        replace(original, original_source_sha256=digest('wrong-original')),
                        replace(original, split='unsupported')):
            with self.subTest(binding=changed):
                with self.assertRaises(MutationRefusal):
                    mutate(raw, 'M11', binding=changed)
        with self.assertRaisesRegex(MutationRefusal, 'unknown numbered'):
            mutate(raw, 'M21', binding=original)

    def test_operator_implementation_pin_changes_without_relabeling_source(self):
        raw, _, _, _ = vector('M11')
        first = mutate(raw, 'M11', binding=binding(raw))
        second = mutate(raw, 'M11', binding=replace(binding(raw), operator_source_sha256=digest('different-operator-edition')))
        self.assertNotEqual(first.operator_sha256, second.operator_sha256)
        self.assertEqual(first.changed_candidate, second.changed_candidate)
        self.assertEqual(first.binding.original_source_sha256, second.binding.original_source_sha256)
