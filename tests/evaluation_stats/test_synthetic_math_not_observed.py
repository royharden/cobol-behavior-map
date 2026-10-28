"""Native rational math on UNTRUSTED enum declarations, not empirical efficacy."""
from dataclasses import replace
from fractions import Fraction
import random
import unittest

from evaluation.stats import _percentile
from synthetic_math_not_observed import (FAMILIES, arm, contrast,
    synthetic_math_not_observed_frame, synthetic_math_not_observed_mixed,
    synthetic_math_not_observed_row, synthetic_math_not_observed_summary)


class SyntheticMathNotObservedComplete(unittest.TestCase):
    """Exactly three complete calls, each using native 5 x 10000 draws.

    The results are in-memory mathematical fixture results only. They are never
    exported as actual study/report rows or claimed as real observations.
    """
    @classmethod
    def setUpClass(cls):
        cls.frame = synthetic_math_not_observed_frame()
        cls.rows = synthetic_math_not_observed_mixed(cls.frame)
        cls.random_before = random.getstate()
        cls.mixed = synthetic_math_not_observed_summary(cls.rows, cls.frame)
        cls.repeated = synthetic_math_not_observed_summary(tuple(reversed(cls.rows)), tuple(reversed(cls.frame)))
        cls.equal = synthetic_math_not_observed_summary(tuple(replace(row, outcome='pass', passed_cases=128)
                                                           for row in cls.rows), cls.frame)
        cls.random_after = random.getstate()

    def test_untrusted_enum_input_returns_only_math_complete_without_authentication(self):
        self.assertEqual(self.mixed.status, 'complete')
        self.assertEqual(self.mixed.issues, ())
        self.assertEqual((self.mixed.split, self.mixed.panel, self.mixed.model_slot), ('dev', 'unchanged', 'primary'))
        self.assertEqual(self.mixed.interpretation,
                         'descriptive; effective n=6; sampling variability unmeasured')

    def test_arm_denominator_means_and_exact_rational_types(self):
        for name, count in (('A', 0), ('B', 24), ('C', 12), ('D', 24), ('R', 24)):
            with self.subTest(arm=name):
                item = arm(self.mixed, name)
                self.assertEqual((item.scheduled, item.measured, item.passed, item.failed, item.unresolved),
                                 (24, 24, count, 24-count, 0))
                self.assertEqual(item.pass_share, Fraction(count, 24))
                self.assertIsInstance(item.pass_share, Fraction)

    def test_d_minus_c_family_weights_mean_and_pair_inventory(self):
        item = contrast(self.mixed, 'D-C')
        self.assertEqual(item.family_values, tuple((family, Fraction(int(index >= 3)))
                                                   for index, family in enumerate(FAMILIES)))
        self.assertEqual(item.mean_difference, Fraction(1, 2))
        self.assertEqual((item.measured_pairs, item.scheduled_pairs, item.left_only_pass, item.right_only_pass),
                         (24, 24, 12, 0))

    def test_d_minus_r_equal_contrast_is_exact_zero(self):
        item = contrast(self.mixed, 'D-R')
        self.assertEqual(item.mean_difference, Fraction(0))
        self.assertEqual(item.interval_95, (Fraction(0), Fraction(0)))
        self.assertEqual((item.left_only_pass, item.right_only_pass), (0, 0))

    def test_c_minus_b_negative_sign_and_discordances(self):
        item = contrast(self.mixed, 'C-B')
        self.assertEqual(item.mean_difference, Fraction(-1, 2))
        self.assertEqual((item.left_only_pass, item.right_only_pass), (0, 12))
        self.assertEqual(item.family_values, tuple((family, Fraction(-int(index >= 3)))
                                                   for index, family in enumerate(FAMILIES)))

    def test_d_minus_b_and_d_minus_a_keep_declared_direction(self):
        self.assertEqual(contrast(self.mixed, 'D-B').mean_difference, Fraction(0))
        a = contrast(self.mixed, 'D-A')
        self.assertEqual(a.mean_difference, Fraction(1))
        self.assertEqual(a.interval_95, (Fraction(1), Fraction(1)))
        self.assertEqual((a.left_only_pass, a.right_only_pass), (24, 0))

    def test_native_bootstrap_seed_draw_count_and_known_binomial_bounds(self):
        self.assertEqual(self.mixed.bootstrap_draws, 10000)
        self.assertEqual(self.mixed.bootstrap_seed, 20261027)
        # Six resampled 0/1 family values, three of each. The 2.5/97.5%
        # tails lie at one and five successes out of six, respectively.
        self.assertEqual(contrast(self.mixed, 'D-C').interval_95, (Fraction(1, 6), Fraction(5, 6)))
        self.assertEqual(contrast(self.mixed, 'C-B').interval_95, (Fraction(-5, 6), Fraction(-1, 6)))

    def test_seeded_native_results_are_repeatable_under_input_permutation(self):
        self.assertEqual(self.mixed, self.repeated)
        self.assertEqual(self.random_before, self.random_after)

    def test_equal_all_pass_fixture_has_zero_width_zero_contrasts(self):
        self.assertEqual(self.equal.status, 'complete')
        for item in self.equal.arms:
            self.assertEqual(item.pass_share, Fraction(1))
        for item in self.equal.contrasts:
            self.assertEqual(item.mean_difference, Fraction(0))
            self.assertEqual(item.interval_95, (Fraction(0), Fraction(0)))

    def test_math_processing_does_not_mutate_frame_or_untrusted_rows(self):
        self.assertEqual(self.frame, synthetic_math_not_observed_frame())
        self.assertEqual(self.rows, synthetic_math_not_observed_mixed(self.frame))
        self.assertTrue(all(row.evidence_mode == 'actual' for row in self.rows))


class SyntheticMathNotObservedPercentiles(unittest.TestCase):
    def test_exact_interpolation_at_quarter_between_two_endpoints(self):
        self.assertEqual(_percentile([Fraction(-1, 3), Fraction(2, 3)], Fraction(1, 4)), Fraction(-1, 12))

    def test_endpoints_and_middle_are_preserved(self):
        values = [Fraction(-3), Fraction(-1), Fraction(2), Fraction(7)]
        self.assertEqual(_percentile(values, Fraction(0)), Fraction(-3))
        self.assertEqual(_percentile(values, Fraction(1)), Fraction(7))
        self.assertEqual(_percentile(values, Fraction(1, 2)), Fraction(1, 2))

    def test_singleton_and_equal_zero_do_not_introduce_float_error(self):
        self.assertEqual(_percentile([Fraction(1, 7)], Fraction(39, 40)), Fraction(1, 7))
        self.assertEqual(_percentile([Fraction(0)] * 4, Fraction(1, 40)), Fraction(0))

    def test_rational_tail_interpolation_leaves_sorted_input_unchanged(self):
        values = [Fraction(0), Fraction(1, 3), Fraction(1)]
        before = values[:]
        self.assertEqual(_percentile(values, Fraction(1, 40)), Fraction(1, 60))
        self.assertEqual(values, before)
