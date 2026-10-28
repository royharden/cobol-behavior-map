"""Builder decimal-shim hypotheses, not native COBOL observations or parity evidence.

Run only as an explicitly selected stdlib unittest file after source review.
The API has named truncation/nearest functions and assignment's ``rounded`` flag;
it has no general rounding-mode enum argument.
"""

import unittest


class DecimalShimRegressions(unittest.TestCase):
    def test_exact_text_and_signed_zero_construction(self):
        """what_bug_this_catches: float conversion, scale collapse, or erased zero sign."""
        from cobolmap.shared.decimal_shim import DecimalValue, decimal_value

        for literal, expected in (("0.10", DecimalValue(10, 2)),
                                  ("-0.00", DecimalValue(0, 2, True)),
                                  ("+12.030", DecimalValue(12030, 3)),
                                  (7, DecimalValue(7, 0))):
            with self.subTest(literal=literal):
                self.assertEqual(decimal_value(literal), expected)
                self.assertEqual(str(decimal_value(literal)), str(expected))
        self.assertTrue(decimal_value("-0.00").is_negative)
        self.assertFalse(decimal_value("0.00").is_negative)

    def test_inexact_or_unbounded_literals_refuse_with_typed_error(self):
        """what_bug_this_catches: implicit float/bool/scientific coercion or unsafe size acceptance."""
        from cobolmap.shared.decimal_shim import ShimError, decimal_value

        for bad, code in ((0.1, "shim_type"), (True, "shim_type"),
                          ("1e2", "shim_type"), (" 1.2", "shim_type"),
                          ("1.", "shim_type"), ("9" * 4097, "shim_type")):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ShimError) as caught:
                    decimal_value(bad)
                self.assertEqual(caught.exception.code, code)

    def test_named_rounding_functions_both_signs_and_near_controls(self):
        """what_bug_this_catches: ties-to-even, away-from-zero on non-ties, or signed bias."""
        from cobolmap.shared.decimal_shim import nearest_ties_away, truncate_toward_zero

        vectors = (
            ("1.25", "1.2", "1.3"), ("-1.25", "-1.2", "-1.3"),
            ("1.24", "1.2", "1.2"), ("-1.24", "-1.2", "-1.2"),
            ("1.26", "1.2", "1.3"), ("-1.26", "-1.2", "-1.3"),
            ("1.20", "1.2", "1.2"), ("-1.20", "-1.2", "-1.2"),
        )
        for source, truncated, nearest in vectors:
            with self.subTest(source=source):
                self.assertEqual(str(truncate_toward_zero(source, 1)), truncated)
                self.assertEqual(str(nearest_ties_away(source, 1)), nearest)

    def test_tiny_fractions_and_negative_zero_survive_quantization(self):
        """what_bug_this_catches: loss of zero sign and ROUND_UP on tiny non-ties."""
        from cobolmap.shared.decimal_shim import nearest_ties_away, truncate_toward_zero

        for source, truncated, nearest in (("0.004", "0.00", "0.00"),
                                            ("-0.004", "-0.00", "-0.00"),
                                            ("0.005", "0.00", "0.01"),
                                            ("-0.005", "-0.00", "-0.01"),
                                            ("-0.000", "-0.00", "-0.00")):
            with self.subTest(source=source):
                self.assertEqual(str(truncate_toward_zero(source, 2)), truncated)
                self.assertEqual(str(nearest_ties_away(source, 2)), nearest)

    def test_rounding_refuses_invalid_scale_and_ignores_ambient_context(self):
        """what_bug_this_catches: ambient precision/rounding leakage or scale coercion."""
        from decimal import ROUND_CEILING, getcontext, localcontext
        from cobolmap.shared.decimal_shim import ShimError, nearest_ties_away, truncate_toward_zero

        baseline = (str(truncate_toward_zero("12345.6789", 2)),
                    str(nearest_ties_away("-12345.675", 2)))
        self.assertEqual(baseline, ("12345.67", "-12345.68"))
        with localcontext() as context:
            context.prec = 2
            context.rounding = ROUND_CEILING
            self.assertEqual((str(truncate_toward_zero("12345.6789", 2)),
                              str(nearest_ties_away("-12345.675", 2))), baseline)
            self.assertEqual(getcontext().prec, 2)
        for bad in (-1, 4097, 1.0, True):
            with self.subTest(scale=bad):
                with self.assertRaises(ShimError) as caught:
                    truncate_toward_zero("1.2", bad)
                self.assertEqual(caught.exception.code, "shim_type")

    def test_numeric_move_truncates_and_unsigned_takes_magnitude_hypothesis(self):
        """what_bug_this_catches: confusing MOVE magnitude with arithmetic sign policy."""
        from cobolmap.shared.decimal_shim import FieldSpec, move

        source = FieldSpec("SRC", "S9(2)V9(2)", sign="LEADING SEPARATE")
        unsigned = FieldSpec("DEST", "9(2)V9(1)")
        signed = FieldSpec("SDEST", "S9(2)V9(1)", sign="LEADING SEPARATE")
        for value, destination, number, stored in (
            ("-1.29", unsigned, "1.2", b"012"),
            ("1.29", unsigned, "1.2", b"012"),
            ("-1.29", signed, "-1.2", b"-012"),
            ("-0.09", signed, "-0.0", b"-000"),
            ("-0.09", unsigned, "0.0", b"000"),
        ):
            with self.subTest(value=value, receiver=destination.name):
                result = move(value, source, destination)
                self.assertIsNone(result.fault_or_null)
                self.assertFalse(result.size_error)
                self.assertEqual(str(result.value), number)
                self.assertEqual(result.stored_bytes_or_null, stored)

    def test_arithmetic_rounded_flag_and_exact_intermediate_hypothesis(self):
        """what_bug_this_catches: early intermediate rounding or wrong assignment tie rule."""
        from cobolmap.shared.decimal_shim import FieldSpec, arithmetic

        receiver = FieldSpec("R", "S9(2)V9(1)", sign="LEADING SEPARATE")
        for op, operands, rounded, expected, stored in (
            ("add", ("1.20", "0.05"), False, "1.2", b"+012"),
            ("add", ("1.20", "0.05"), True, "1.3", b"+013"),
            ("subtract", ("-1.20", "0.05"), True, "-1.3", b"-013"),
            ("multiply", ("0.25", "2"), True, "0.5", b"+005"),
            ("divide", ("1", "8"), True, "0.1", b"+001"),
        ):
            with self.subTest(op=op, operands=operands, rounded=rounded):
                result = arithmetic(op, operands, receiver, rounded=rounded)
                self.assertIsNone(result.fault_or_null)
                self.assertEqual(str(result.value), expected)
                self.assertEqual(result.stored_bytes_or_null, stored)

    def test_arithmetic_negative_zero_and_comparison_zero_equality(self):
        """what_bug_this_catches: dropping signed zero in arithmetic or ordering it below zero."""
        from cobolmap.shared.decimal_shim import FieldSpec, arithmetic, compare, decimal_value

        receiver = FieldSpec("R", "S9(1)V9(2)", sign="LEADING SEPARATE")
        result = arithmetic("multiply", ("-0.01", "0.01"), receiver)
        self.assertEqual(str(result.value), "-0.00")
        self.assertEqual(result.stored_bytes_or_null, b"-000")
        negative, positive = decimal_value("-0.00"), decimal_value("0.00")
        self.assertTrue(compare(negative, "=", positive))
        self.assertFalse(compare(negative, "!=", positive))
        self.assertFalse(compare(negative, "<", positive))
        self.assertTrue(compare(negative, ">=", positive))

    def test_numeric_comparison_enums_and_refusals(self):
        """what_bug_this_catches: lexical numeric ordering or silent comparator coercion."""
        from cobolmap.shared.decimal_shim import ShimError, compare, decimal_value

        left, right = decimal_value("2.00"), decimal_value("10")
        for comparator, expected in (("=", False), ("!=", True), ("<>", True),
                                     ("<", True), ("<=", True), (">", False), (">=", False)):
            with self.subTest(comparator=comparator):
                self.assertIs(compare(left, comparator, right), expected)
        self.assertTrue(compare(decimal_value("2.0"), "=", decimal_value("2.00")))
        for comparator, code in (("eq", "unsupported_expression"), ("==", "unsupported_expression")):
            with self.subTest(comparator=comparator):
                with self.assertRaises(ShimError) as caught:
                    compare(left, comparator, right)
                self.assertEqual(caught.exception.code, code)
        with self.assertRaises(ShimError) as caught:
            compare(left, "=", "2.00")
        self.assertEqual(caught.exception.code, "shim_type")

    def test_overflow_preserves_previous_and_distinguishes_handler(self):
        """what_bug_this_catches: clamping, replacing receiver, or treating handler as success."""
        from cobolmap.shared.decimal_shim import FieldSpec, arithmetic, decimal_value

        receiver = FieldSpec("R", "9(2)")
        previous = decimal_value("42")
        for operands in (("99", "1"), ("-1", "0")):
            for handler in (False, True):
                with self.subTest(operands=operands, handler=handler):
                    result = arithmetic("add", operands, receiver, size_error_handler=handler,
                                        previous_destination=previous)
                    self.assertTrue(result.size_error)
                    self.assertEqual(result.value, previous)
                    self.assertEqual(result.stored_bytes_or_null, b"42")
                    self.assertEqual(None if result.fault_or_null is None else result.fault_or_null.code,
                                     None if handler else "size_error")

    def test_division_zero_preserves_previous_with_and_without_handler(self):
        """what_bug_this_catches: Python ZeroDivisionError or lost SIZE ERROR distinction."""
        from cobolmap.shared.decimal_shim import FieldSpec, arithmetic, decimal_value

        receiver = FieldSpec("R", "S9(2)", sign="LEADING SEPARATE")
        previous = decimal_value("-7")
        for handler in (False, True):
            with self.subTest(handler=handler):
                result = arithmetic("divide", ("1", "0"), receiver,
                                    size_error_handler=handler, previous_destination=previous)
                self.assertTrue(result.size_error)
                self.assertEqual(result.value, previous)
                self.assertEqual(result.stored_bytes_or_null, b"-07")
                self.assertEqual(None if result.fault_or_null is None else result.fault_or_null.code,
                                 None if handler else "division_zero")
        control = arithmetic("divide", ("1", "2"), receiver, rounded=True)
        self.assertFalse(control.size_error)
        self.assertEqual(control.stored_bytes_or_null, b"+01")

    def test_compute_closed_three_operator_tree(self):
        """what_bug_this_catches: lost grouping, early rounding, or unresolved valid binding."""
        from cobolmap.shared.decimal_shim import FieldSpec, compute

        literal = lambda value: {"kind": "literal", "value": value}
        reference = {"kind": "reference", "name": "INPUT"}
        expression = {
            "kind": "binary", "operator": "/",
            "left": {
                "kind": "binary", "operator": "*",
                "left": {
                    "kind": "binary", "operator": "+",
                    "left": reference,
                    "right": literal("2.25"),
                },
                "right": literal("2"),
            },
            "right": literal("3"),
        }
        receiver = FieldSpec("R", "S9(2)V9(1)", sign="LEADING SEPARATE")
        result = compute(expression, {"INPUT": "1.25"}, receiver)
        self.assertFalse(result.size_error)
        self.assertIsNone(result.fault_or_null)
        self.assertEqual(str(result.value), "2.3")
        self.assertEqual(result.stored_bytes_or_null, b"+023")

    def test_compute_missing_reference_cycle_and_unsupported_shapes(self):
        """what_bug_this_catches: implicit globals/eval, cycles, or unbounded expression trees."""
        from cobolmap.shared.decimal_shim import FieldSpec, compute

        receiver = FieldSpec("R", "9(2)")
        literal = {"kind": "literal", "value": "1"}
        binary = lambda left, right: {"kind": "binary", "operator": "+",
                                      "left": left, "right": right}
        cycle = binary(literal, literal)
        cycle["right"] = cycle
        four_ops = binary(binary(binary(binary(literal, literal), literal), literal), literal)
        vectors = (({"kind": "reference", "name": "MISSING"}, "pointer_unresolved"),
                   (cycle, "unsupported_expression"),
                   (four_ops, "unsupported_expression"),
                   ({"kind": "literal", "value": "1", "extra": 0}, "unsupported_expression"),
                   ({"kind": "function", "name": "eval"}, "unsupported_expression"),
                   ({"kind": "binary", "operator": "**", "left": literal,
                     "right": literal}, "unsupported_expression"))
        for index, (expression, code) in enumerate(vectors):
            with self.subTest(index=index):
                result = compute(expression, {}, receiver)
                self.assertIsNone(result.value)
                self.assertFalse(result.size_error)
                self.assertEqual(result.fault_or_null.code, code)
        control = compute(literal, {}, receiver)
        self.assertIsNone(control.fault_or_null)
        self.assertEqual(control.stored_bytes_or_null, b"01")

    def test_compute_division_zero_and_arithmetic_unknown_operation(self):
        """what_bug_this_catches: zero-division exception or invented operation dispatch."""
        from cobolmap.shared.decimal_shim import FieldSpec, arithmetic, compute, decimal_value

        receiver = FieldSpec("R", "9(2)")
        previous = decimal_value("9")
        expression = {"kind": "binary", "operator": "/", "left": {
            "kind": "literal", "value": "1"}, "right": {"kind": "literal", "value": "0"}}
        divided = compute(expression, {}, receiver, size_error_handler=True,
                          previous_destination=previous)
        self.assertTrue(divided.size_error)
        self.assertIsNone(divided.fault_or_null)
        self.assertEqual(divided.stored_bytes_or_null, b"09")
        for operation, operands in (("compute", ("1", "2")), ("power", ("1", "2")),
                                    ("add", ("1",))):
            with self.subTest(operation=operation, operands=operands):
                result = arithmetic(operation, operands, receiver)
                self.assertFalse(result.size_error)
                self.assertEqual(result.fault_or_null.code, "unsupported_expression")


if __name__ == "__main__":
    unittest.main()
