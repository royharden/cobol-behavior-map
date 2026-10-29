"""Missing-data and input guards for ARTIFICIAL DEV metadata, no observed data."""
from dataclasses import replace
from fractions import Fraction
import unittest

from synthetic_math_not_observed import (arm, contrast, synthetic_math_not_observed_frame,
    synthetic_math_not_observed_pair, synthetic_math_not_observed_row,
    synthetic_math_not_observed_summary)


class SyntheticMathNotObservedGuards(unittest.TestCase):
    def setUp(self):
        self.frame = synthetic_math_not_observed_frame()
        self.row = synthetic_math_not_observed_row(self.frame[0])

    def test_separately_supplied_empty_rows_keep_all_five_denominators(self):
        result = synthetic_math_not_observed_summary((), self.frame)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(len(result.issues), 120)
        for item in result.arms:
            self.assertEqual((item.scheduled, item.measured, item.unresolved), (24, 0, 24))
            self.assertIsNone(item.pass_share)
            self.assertEqual(item.outcomes, (('missing', 24),))
        for item in result.contrasts:
            self.assertEqual((item.measured_pairs, item.scheduled_pairs), (0, 24))
            self.assertIsNone(item.mean_difference)
            self.assertIsNone(item.interval_95)

    def test_missing_row_does_not_shrink_arm_denominator_or_imply_failure(self):
        rows = tuple(synthetic_math_not_observed_row(slot) for slot in self.frame[:-1])
        item = arm(synthetic_math_not_observed_summary(rows, self.frame), 'D')
        self.assertEqual((item.scheduled, item.measured, item.passed, item.failed, item.unresolved),
                         (24, 23, 23, 0, 1))
        self.assertIsNone(item.pass_share)
        self.assertEqual(dict(item.outcomes), {'missing': 1, 'pass': 23})

    def test_fixture_static_and_not_run_pass_declarations_never_become_measured(self):
        for evidence in ('fixture', 'static', 'not_run'):
            with self.subTest(untrusted_mode=evidence):
                rows = tuple(synthetic_math_not_observed_row(slot, evidence_mode=evidence) for slot in self.frame)
                result = synthetic_math_not_observed_summary(rows, self.frame)
                item = arm(result, 'D')
                self.assertEqual((item.scheduled, item.measured, item.passed, item.failed, item.unresolved),
                                 (24, 0, 0, 0, 24))
                self.assertIsNone(item.pass_share)
                self.assertEqual(item.outcomes, (('pass', 24),))
                self.assertTrue(all(c.mean_difference is None and c.interval_95 is None for c in result.contrasts))

    def test_unmeasured_outcome_enum_stays_unresolved_despite_untrusted_actual_label(self):
        for outcome in ('unavailable', 'not_run', 'infra_invalid', 'missing', 'unknown'):
            with self.subTest(untrusted_outcome=outcome):
                row = replace(self.row, outcome=outcome, verification_cases=None, passed_cases=None)
                item = arm(synthetic_math_not_observed_summary((row,), self.frame), 'D')
                self.assertEqual((item.measured, item.passed, item.failed, item.unresolved), (0, 0, 0, 24))
                self.assertIsNone(item.pass_share)

    def test_missing_pair_suppresses_family_and_mean_without_reducing_denominator(self):
        rows = synthetic_math_not_observed_pair(self.frame)[1:]
        item = contrast(synthetic_math_not_observed_summary(rows, self.frame), 'D-C')
        self.assertEqual((item.measured_pairs, item.scheduled_pairs), (23, 24))
        self.assertEqual((item.left_only_pass, item.right_only_pass), (23, 0))
        self.assertIsNone(item.family_values[0][1])
        self.assertEqual(tuple(v for _, v in item.family_values[1:]), (Fraction(1),) * 5)
        self.assertIsNone(item.mean_difference)
        self.assertIsNone(item.interval_95)

    def test_refusal_is_a_counted_failure_only_for_untrusted_actual_math_label(self):
        row = replace(self.row, outcome='refused', passed_cases=0)
        item = arm(synthetic_math_not_observed_summary((row,), self.frame), 'D')
        self.assertEqual((item.measured, item.failed, item.refused, item.unresolved), (1, 1, 1, 23))
        fixture = replace(row, evidence_mode='fixture')
        other = arm(synthetic_math_not_observed_summary((fixture,), self.frame), 'D')
        self.assertEqual((other.measured, other.failed, other.refused, other.unresolved), (0, 0, 1, 24))

    def test_wrong_family_or_program_metadata_refuses(self):
        for field in ('family_id', 'program_id'):
            with self.subTest(field=field):
                row = replace(self.row, **{field: 'synthetic_math_not_observed_wrong_identity'})
                with self.assertRaisesRegex(ValueError, 'row outside independently supplied expected frame'):
                    synthetic_math_not_observed_summary((row,), self.frame)

    def test_wrong_model_or_panel_row_refuses_instead_of_pooling(self):
        for row in (replace(self.row, model_slot='replication'), replace(self.row, panel='change')):
            with self.subTest(row=(row.model_slot, row.panel)):
                with self.assertRaisesRegex(ValueError, 'row outside independently supplied expected frame'):
                    synthetic_math_not_observed_summary((row,), self.frame)

    def test_unexpected_task_and_unknown_arm_refuse(self):
        with self.assertRaisesRegex(ValueError, 'row outside independently supplied expected frame'):
            synthetic_math_not_observed_summary((replace(self.row, task_id='synthetic_math_not_observed_extra'),), self.frame)
        with self.assertRaisesRegex(ValueError, 'OutcomeRow with scheduled arm required'):
            synthetic_math_not_observed_summary((replace(self.row, arm='Z'),), self.frame)

    def test_duplicate_row_refuses_even_when_values_agree(self):
        with self.assertRaisesRegex(ValueError, 'duplicate task/arm observation'):
            synthetic_math_not_observed_summary((self.row, self.row), self.frame)

    def test_duplicate_expected_slot_refuses_before_denominator_selection(self):
        with self.assertRaisesRegex(ValueError, 'duplicate expected task slot'):
            synthetic_math_not_observed_summary((), self.frame + (self.frame[0],))

    def test_incomplete_or_extra_family_frame_refuses(self):
        for expected in (self.frame[:-1], self.frame[:20],
                         self.frame + (replace(self.frame[0], task_id='synthetic_math_not_observed_extra',
                             program_id='synthetic_math_not_observed_extra_program', family_id='synthetic_math_not_observed_seventh'),)):
            with self.subTest(frame_size=len(expected)):
                with self.assertRaisesRegex(ValueError, 'expected frame must contain six families'):
                    synthetic_math_not_observed_summary((), expected)

    def test_program_family_drift_and_duplicate_program_within_family_refuse(self):
        drift = (replace(self.frame[4], program_id=self.frame[0].program_id),)
        with self.assertRaisesRegex(ValueError, 'program family drift'):
            synthetic_math_not_observed_summary((), self.frame[:4] + drift + self.frame[5:])
        duplicate_program = replace(self.frame[1], program_id=self.frame[0].program_id)
        with self.assertRaisesRegex(ValueError, 'expected frame must contain six families'):
            synthetic_math_not_observed_summary((), (self.frame[0], duplicate_program) + self.frame[2:])

    def test_empty_or_invalid_expected_metadata_refuses(self):
        for slot in (replace(self.frame[0], family_id=''), replace(self.frame[0], split='invalid'),
                     replace(self.frame[0], panel='invalid')):
            with self.subTest(slot=slot):
                with self.assertRaises(ValueError):
                    synthetic_math_not_observed_summary((), (slot,) + self.frame[1:])

    def test_explicit_selectors_are_required_and_unavailable_model_frame_refuses(self):
        for selectors in ({'split': 'invalid'}, {'panel': 'invalid'}, {'model_slot': ''},
                          {'model_slot': 'synthetic_math_not_observed_absent'}):
            with self.subTest(selectors=selectors):
                with self.assertRaises(ValueError):
                    synthetic_math_not_observed_summary((), self.frame, **selectors)

    def test_supplied_other_panel_and_model_metadata_is_not_pooled(self):
        replication = synthetic_math_not_observed_frame(model_slot='replication')
        change = synthetic_math_not_observed_frame(panel='change')
        expected = self.frame + replication + change
        rows = tuple(synthetic_math_not_observed_row(slot) for slot in replication + change)
        selected = synthetic_math_not_observed_summary(rows, expected)
        self.assertEqual((arm(selected, 'D').scheduled, arm(selected, 'D').measured), (24, 0))
        self.assertEqual(len(selected.issues), 120)

    def test_unknown_evidence_and_outcome_enums_refuse(self):
        for row in (replace(self.row, evidence_mode='accepted'), replace(self.row, outcome='probably_pass')):
            with self.subTest(row=(row.evidence_mode, row.outcome)):
                with self.assertRaises(ValueError):
                    synthetic_math_not_observed_summary((row,), self.frame)

    def test_malformed_dummy_counts_refuse_including_bool_float_and_out_of_range(self):
        for changes in ({'verification_cases': True}, {'passed_cases': 128.0},
                        {'verification_cases': -1}, {'verification_cases': 129},
                        {'verification_cases': None}, {'passed_cases': 127},
                        {'verification_cases': 127, 'passed_cases': 128},
                        {'outcome': 'fail', 'passed_cases': 128}):
            with self.subTest(dummy_counts=changes):
                with self.assertRaises(ValueError):
                    synthetic_math_not_observed_summary((replace(self.row, **changes),), self.frame)

    def test_non_native_row_and_frame_carriers_refuse(self):
        with self.assertRaisesRegex(ValueError, 'OutcomeRow with scheduled arm required'):
            synthetic_math_not_observed_summary(({'synthetic_math_not_observed': 'row'},), self.frame)
        with self.assertRaisesRegex(ValueError, 'expected frame requires nonempty TaskSlot metadata'):
            synthetic_math_not_observed_summary((), ({'synthetic_math_not_observed': 'frame'},))

    def test_sparse_processing_leaves_inputs_immutable_and_means_absent(self):
        rows = (self.row,)
        before = (self.frame, rows)
        result = synthetic_math_not_observed_summary(rows, self.frame)
        self.assertEqual((self.frame, rows), before)
        self.assertTrue(all(item.mean_difference is None and item.interval_95 is None
                            for item in result.contrasts))
