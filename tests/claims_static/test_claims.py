"""Builder synthetic STATIC relations/lexical layouts, never oracle evidence.

No search/callback/candidate/observation/witness/receipt/empirical support creation.
"""
from decimal import Inexact, Rounded, ROUND_DOWN, ROUND_UP, localcontext
import hashlib
import unittest

from cobolmap.claims.evaluator import evaluate_claim
from cobolmap.claims.fields import display_matches, validate_decoded_value, validate_layout
from cobolmap.claims.models import ClaimResult, FieldBinding
from cobolmap.contracts import (
    Claim, FieldComparison, FieldRef, FieldValue, LinearTerm, LinearValue, LiteralValue,
    MapField, OutputEquality, SourcePointer,
)

FILENAME = "builder-layout.cbl"


def pointer(raw, filename=FILENAME):
    return SourcePointer(source_sha256=hashlib.sha256(raw).hexdigest(), filename=filename,
        line_start=1, line_end=1, byte_start=0, byte_end=len(raw.rstrip(b"\n")))


def ref(name, scope="input"):
    return FieldRef(scope=scope, name=name)


def literal(text, category="decimal"):
    return LiteralValue(value_type=category, value=text)


def binding(name, text, scope="input", category="decimal"):
    return FieldBinding(field=ref(name, scope), value=literal(text, category))


def claim(expected=None, guard=(), target="Y"):
    return Claim(claim_id="builder_static_claim", span=pointer(b"builder static declaration only\n"),
        guard=tuple(guard), assertion=OutputEquality(field=ref(target, "output"),
            expected=literal("0") if expected is None else expected))


def comparison(name, operator, right):
    return FieldComparison(left=ref(name), comparator=operator, right=right)


def linear(coefficient="1", constant="0", scale=1, rounding="nearest_ties_away"):
    return LinearValue(terms=(LinearTerm(field=ref("X"), coefficient=coefficient),),
                       constant=constant, scale=scale, rounding=rounding)


def numeric_layout(*, name="PRICE", scope="output", signed=True, declaration=None):
    pic = "S9(2)V9(1)" if signed else "9(2)V9(1)"
    text = declaration or ("05 " + name + " PIC " + pic + (" SIGN LEADING SEPARATE" if signed else "") + ".\n")
    raw = text.encode("ascii")
    layout = MapField(name=name, pic=pic, usage="DISPLAY", sign="leading_separate" if signed else "none",
        offset=0, width=4 if signed else 3, scale=1, digits=3, storage=scope,
        span=pointer(raw), record_name="BUILDER-REC")
    return raw, layout


def alpha_layout():
    raw = b"05 TITLE PIC X(3).\n"
    return raw, MapField(name="TITLE", pic="X(3)", usage="DISPLAY", sign="none", offset=4,
        width=3, scale=0, digits=0, storage="output", span=pointer(raw), record_name="BUILDER-REC")


class StaticClaimVectors(unittest.TestCase):
    def evaluated(self, declaration, inputs=(), outputs=(), status="satisfied"):
        result = evaluate_claim(declaration, tuple(inputs), tuple(outputs))
        self.assertEqual(result.status, status, result.issues)
        self.assertEqual(declaration.status, "untested")
        self.assertEqual(declaration.evidence_mode, "static")
        return result

    def test_all_six_guard_comparators_less_equal_and_greater_controls(self):
        truth = {"=": (False, True, False), "!=": (True, False, True), "<": (True, False, False),
                 "<=": (True, True, False), ">": (False, False, True), ">=": (False, True, True)}
        for operator, outcomes in truth.items():
            for value, holds in zip(("2", "3", "4"), outcomes):
                with self.subTest(operator=operator, value=value):
                    declaration = claim(guard=(comparison("X", operator, literal("3")),))
                    result = self.evaluated(declaration, (binding("X", value),),
                        (binding("Y", "0", "output"),), "satisfied" if holds else "guard_false")
                    self.assertIs(result.guard_satisfied, holds)

    def test_conjunction_and_field_operand_are_observable_not_expression_strings(self):
        declaration = claim(guard=(comparison("X", ">=", literal("1")),
                                   comparison("X", "<", FieldValue(field=ref("LIMIT")))))
        self.evaluated(declaration, (binding("X", "2"), binding("LIMIT", "3")), (binding("Y", "0", "output"),))
        self.evaluated(declaration, (binding("X", "3"), binding("LIMIT", "3")), (), "guard_false")

    def test_false_guard_is_distinct_from_missing_assertion_data(self):
        declaration = claim(guard=(comparison("X", "=", literal("0")),))
        false = self.evaluated(declaration, (binding("X", "1"),), (), "guard_false")
        missing = self.evaluated(declaration, (binding("X", "0"),), (), "untestable")
        self.assertFalse(false.guard_satisfied)
        self.assertIsNone(missing.guard_satisfied)
        self.assertIn("missing_or_unobservable_field:output:Y", missing.issues[0])

    def test_eager_guard_resolution_refuses_missing_later_conjunct_after_false(self):
        declaration = claim(guard=(comparison("X", "=", literal("0")), comparison("UNKNOWN", ">", literal("0"))))
        result = self.evaluated(declaration, (binding("X", "1"),), (), "untestable")
        self.assertIn("input:UNKNOWN", result.issues[0])

    def test_eager_guard_mixed_type_after_false_is_untestable(self):
        declaration = claim(guard=(comparison("X", "=", literal("0")), comparison("TEXT", ">", literal("0"))))
        result = self.evaluated(declaration, (binding("X", "1"), binding("TEXT", "A", category="alpha")), (), "untestable")
        self.assertIn("mixed_field_types", result.issues[0])

    def test_unobservable_output_guard_does_not_become_false(self):
        guard = FieldComparison(left=ref("UNSEEN", "output"), comparator="=", right=literal("1"))
        self.evaluated(claim(guard=(guard,)), (), (), "untestable")

    def test_duplicate_input_and_output_bindings_refuse_even_if_values_equal(self):
        declaration = claim()
        for inputs, outputs in (((binding("X", "1"), binding("X", "1")), (binding("Y", "0", "output"),)),
                                ((), (binding("Y", "0", "output"), binding("Y", "0", "output")))):
            result = self.evaluated(declaration, inputs, outputs, "untestable")
            self.assertIn("ambiguous_or_wrong_scope_binding", result.issues[0])

    def test_wrong_scope_bindings_are_not_silently_reclassified(self):
        for inputs, outputs in (((binding("Y", "0", "output"),), ()),
                                ((), (binding("X", "0", "input"),))):
            self.evaluated(claim(), inputs, outputs, "untestable")

    def test_same_name_across_scopes_remains_two_distinct_fields(self):
        declaration = claim(FieldValue(field=ref("X")), target="X")
        self.evaluated(declaration, (binding("X", "5"),), (binding("X", "5", "output"),))
        self.evaluated(declaration, (binding("X", "5"),), (binding("X", "4", "output"),), "violated")

    def test_missing_expected_field_and_mixed_assertion_types_are_untestable(self):
        self.evaluated(claim(FieldValue(field=ref("MISSING"))), (), (binding("Y", "0", "output"),), "untestable")
        self.evaluated(claim(literal("1")), (), (binding("Y", "1", "output", "alpha"),), "untestable")

    def test_numeric_literal_equality_is_value_based_alpha_stays_lexical(self):
        self.evaluated(claim(literal("001.30")), (), (binding("Y", "1.3", "output"),))
        self.evaluated(claim(literal("A ", "alpha")), (), (binding("Y", "A", "output", "alpha"),), "violated")
        self.evaluated(claim(literal("A ", "alpha")), (), (binding("Y", "A ", "output", "alpha"),))

    def test_alpha_code_spelling_is_data_and_not_evaluated(self):
        text = "__import__('NOT-A-REAL-MODULE')"
        self.evaluated(claim(literal(text, "alpha")), (), (binding("Y", text, "output", "alpha"),))

    def test_alpha_guard_order_is_lexical_not_padded_numeric_coercion(self):
        declaration = claim(guard=(comparison("CODE", ">", literal("A", "alpha")),))
        self.evaluated(declaration, (binding("CODE", "A ", category="alpha"),), (binding("Y", "0", "output"),))
        self.evaluated(declaration, (binding("CODE", "A", category="alpha"),), (), "guard_false")

    def test_linear_weighted_half_ties_and_truncation_both_signs(self):
        for value, rounded, truncated in (("2.5", "1.3", "1.2"), ("-2.5", "-1.3", "-1.2")):
            for mode, correct, incorrect in (("nearest_ties_away", rounded, truncated),
                                             ("truncate_toward_zero", truncated, rounded)):
                with self.subTest(value=value, mode=mode):
                    declaration = claim(linear(coefficient="0.5", rounding=mode))
                    self.evaluated(declaration, (binding("X", value),), (binding("Y", correct, "output"),))
                    self.evaluated(declaration, (binding("X", value),), (binding("Y", incorrect, "output"),), "violated")

    def test_linear_near_ties_scale_zero_and_constant_only(self):
        for value, expected in (("1.24", "1.2"), ("1.26", "1.3"), ("-1.24", "-1.2"), ("-1.26", "-1.3")):
            self.evaluated(claim(linear()), (binding("X", value),), (binding("Y", expected, "output"),))
        for constant, expected in (("2.5", "3"), ("-2.5", "-3")):
            expression = LinearValue(terms=(), constant=constant, scale=0, rounding="nearest_ties_away")
            self.evaluated(claim(expression), (), (binding("Y", expected, "output"),))

    def test_linear_multiple_terms_and_ambient_decimal_traps_are_irrelevant(self):
        expression = LinearValue(terms=(LinearTerm(field=ref("X"), coefficient="1"),
            LinearTerm(field=ref("Z"), coefficient="1")), constant="0", scale=2, rounding="truncate_toward_zero")
        for precision, mode in ((1, ROUND_DOWN), (2, ROUND_UP), (28, ROUND_DOWN)):
            with localcontext() as ambient:
                ambient.prec, ambient.rounding = precision, mode
                ambient.traps[Inexact] = ambient.traps[Rounded] = True
                self.evaluated(claim(expression), (binding("X", "0.1"), binding("Z", "0.2")), (binding("Y", "0.30", "output"),))
                for value, expected in (("1234567890123456.785", "1234567890123456.79"),
                                        ("-1234567890123456.785", "-1234567890123456.79")):
                    self.evaluated(claim(linear(scale=2)), (binding("X", value),), (binding("Y", expected, "output"),))

    def test_linear_signed_coefficients_and_nonzero_constant_are_exact(self):
        expression = LinearValue(terms=(LinearTerm(field=ref("X"), coefficient="0.5"),
            LinearTerm(field=ref("Z"), coefficient="-2")), constant="0.05", scale=2, rounding="nearest_ties_away")
        inputs = (binding("X", "0.4"), binding("Z", "0.075"))
        self.evaluated(claim(expression), inputs, (binding("Y", "0.10", "output"),))
        self.evaluated(claim(expression), inputs, (binding("Y", "0.09", "output"),), "violated")

    def test_linear_alpha_operand_and_alpha_target_refuse(self):
        self.evaluated(claim(linear()), (binding("X", "A", category="alpha"),), (binding("Y", "0", "output"),), "untestable")
        self.evaluated(claim(linear()), (binding("X", "1"),), (binding("Y", "1", "output", "alpha"),), "untestable")

    def test_closed_dsl_unknown_kinds_operators_fields_and_types_refuse(self):
        declaration = claim()
        value = declaration.model_dump()
        value["assertion"]["expected"] = dict(kind="python", expression="call()")
        with self.assertRaises(ValueError):
            Claim.model_validate(value)
        with self.assertRaises(ValueError):
            Claim(**dict(declaration.model_dump(), executable="not allowed"))
        with self.assertRaises(ValueError):
            comparison("X", "<>", literal("0"))
        with self.assertRaises(ValueError):
            FieldRef(scope="working", name="X")
        with self.assertRaises(ValueError):
            OutputEquality(field=ref("X"), expected=literal("0"))

    def test_literal_and_linear_decimal_contracts_have_no_float_or_expression_escape(self):
        for value in ("+1", "1e2", " 1", "NaN", "1+1"):
            with self.assertRaises(ValueError):
                literal(value)
        with self.assertRaises(ValueError):
            literal("bad\nalpha", "alpha")
        for changes in (dict(coefficient=0.5), dict(coefficient="1e2")):
            with self.assertRaises(ValueError):
                LinearTerm(field=ref("X"), **changes)
        for changes in (dict(scale=5), dict(rounding="bankers"), dict(constant="0+1")):
            with self.assertRaises(ValueError):
                LinearValue(**dict(linear().model_dump(), **changes))

    def test_static_results_do_not_satisfy_default_empirical_thresholds(self):
        declaration = claim(literal("1"))
        for value, status in (("1", "satisfied"), ("2", "violated")):
            self.evaluated(declaration, (), (binding("Y", value, "output"),), status)
        untouched = ClaimResult(claim_id=declaration.claim_id, status="not_run")
        self.assertEqual((untouched.oracle_calls, untouched.supported_cases), (0, 0))
        self.assertFalse(untouched.universal_validity)
        for status in ("supported_on_N", "refuted"):
            with self.assertRaises(ValueError):
                ClaimResult(claim_id=declaration.claim_id, status=status)


class StaticFieldVectors(unittest.TestCase):
    def test_display_layout_resolves_actual_declaration_bytes_and_scope(self):
        raw, layout = numeric_layout()
        validate_layout(layout, ref("PRICE", "output"), raw, FILENAME)
        for field in (ref("MISSING", "output"), ref("PRICE", "input")):
            with self.assertRaisesRegex(ValueError, "field_layout_name_or_scope"):
                validate_layout(layout, field, raw, FILENAME)

    def test_raw_source_filename_pointer_hash_line_and_bounds_refuse(self):
        raw, layout = numeric_layout()
        for source, filename in ((raw + b" \n", FILENAME), (raw, "other.cbl")):
            with self.assertRaises(ValueError):
                validate_layout(layout, ref("PRICE", "output"), source, filename)
        for pointer_change in (dict(source_sha256="0" * 64), dict(line_start=2), dict(byte_end=len(raw) + 1)):
            altered = layout.model_copy(update={"span": layout.span.model_copy(update=pointer_change)})
            with self.assertRaises(ValueError):
                validate_layout(altered, ref("PRICE", "output"), raw, FILENAME)
        with self.assertRaises(ValueError):
            pointer(raw, "../not-safe.cbl")

    def test_pic_width_digits_scale_sign_and_missing_offset_refuse(self):
        raw, layout = numeric_layout()
        for changes in (dict(pic="ZZ9"), dict(width=3), dict(digits=2), dict(scale=0), dict(sign="none"), dict(offset=None)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_layout(layout.model_copy(update=changes), ref("PRICE", "output"), raw, FILENAME)
        for changes in (dict(pic="9(0)"), dict(offset=-1), dict(width=3), dict(usage="BINARY")):
            with self.assertRaises(ValueError):
                MapField.model_validate(dict(layout.model_dump(), **changes))

    def test_correct_width_does_not_hide_wrong_pic_or_field_declaration(self):
        for declaration in ("05 PRICE PIC S9(3) SIGN LEADING SEPARATE.\n",
                            "05 OTHER PIC S9(2)V9(1) SIGN LEADING SEPARATE.\n"):
            raw, layout = numeric_layout(declaration=declaration)
            with self.assertRaisesRegex(ValueError, "field_declaration_name_pic_unresolved"):
                validate_layout(layout, ref("PRICE", "output"), raw, FILENAME)

    def test_missing_or_trailing_sign_declaration_refuses(self):
        for declaration in ("05 PRICE PIC S9(2)V9(1).\n", "05 PRICE PIC S9(2)V9(1) SIGN TRAILING SEPARATE.\n"):
            raw, layout = numeric_layout(declaration=declaration)
            with self.assertRaisesRegex(ValueError, "field_declaration_sign_unresolved"):
                validate_layout(layout, ref("PRICE", "output"), raw, FILENAME)

    def test_comp3_metadata_or_declaration_never_becomes_external_display_codec(self):
        raw, layout = numeric_layout(signed=False, declaration="05 PRICE PIC 9(2)V9(1) COMP-3.\n")
        with self.assertRaisesRegex(ValueError, "packed_or_non_display_declaration"):
            validate_layout(layout, ref("PRICE", "output"), raw, FILENAME)
        with self.assertRaises(ValueError):
            MapField.model_validate(dict(layout.model_dump(), usage="COMP-3", width=2))
        with self.assertRaisesRegex(ValueError, "external_display_layout_required"):
            validate_layout(layout.model_copy(update={"usage": "COMP-3"}), ref("PRICE", "output"), raw, FILENAME)

    def test_display_numeric_value_and_lexical_sign_zero_are_separate_layers(self):
        raw, layout = numeric_layout()
        validate_layout(layout, ref("PRICE", "output"), raw, FILENAME)
        for data, value in ((b"+125", "12.50"), (b"-125", "-12.5"), (b"-000", "-0.00"), (b"+000", "0.0")):
            self.assertTrue(display_matches(data, layout, literal(value)))
        self.assertFalse(display_matches(b"-000", layout, literal("0.0")))
        self.assertFalse(display_matches(b"+000", layout, literal("-0.0")))
        # Static numeric relation equality alone intentionally does not prove zero's byte sign.
        result = evaluate_claim(claim(literal("-0.0")), (), (binding("Y", "0", "output"),))
        self.assertEqual(result.status, "satisfied")

    def test_display_exact_width_digits_and_alpha_have_no_trimming(self):
        raw, number = numeric_layout(signed=False)
        validate_layout(number, ref("PRICE", "output"), raw, FILENAME)
        self.assertTrue(display_matches(b"012", number, literal("1.20")))
        for data in (b"12", b"012\n", b" 12", b"1.2", b"01A"):
            self.assertFalse(display_matches(data, number, literal("1.2")))
        raw, alpha = alpha_layout()
        validate_layout(alpha, ref("TITLE", "output"), raw, FILENAME)
        self.assertTrue(display_matches(b"A B", alpha, literal("A B", "alpha")))
        for data, expected in ((b"A B", "AB "), (b"A B", "A B "), (b"A\0B", "A B"), (b"A B\n", "A B")):
            self.assertFalse(display_matches(data, alpha, literal(expected, "alpha")))
        self.assertFalse(display_matches(b"012", number, literal("012", "alpha")))

    def test_decoded_input_exact_scale_range_sign_and_alpha_width_refuse(self):
        raw, unsigned = numeric_layout(name="AMOUNT", scope="input", signed=False)
        validate_layout(unsigned, ref("AMOUNT"), raw, FILENAME)
        for value in ("0", "99.9", "1.20"):
            validate_decoded_value(unsigned, literal(value))
        for value in ("100.0", "-0.0", "1.23"):
            with self.assertRaises(ValueError):
                validate_decoded_value(unsigned, literal(value))
        with self.assertRaises(ValueError):
            validate_decoded_value(unsigned, literal("123", "alpha"))
        _, alpha = alpha_layout()
        validate_decoded_value(alpha, literal("A B", "alpha"))
        for value in (literal("AB", "alpha"), literal("123")):
            with self.assertRaises(ValueError):
                validate_decoded_value(alpha, value)


if __name__ == "__main__":
    unittest.main()
