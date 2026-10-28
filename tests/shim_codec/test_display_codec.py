"""Builder byte hypotheses for pure DISPLAY codec; compiler parity is not asserted.

Each case names a concrete regression. Never run before exact-edition static review.
"""
import unittest


class DisplayCodecRegressions(unittest.TestCase):
    def assert_code(self, code, function, *args, **kwargs):
        from cobolmap.shared import ShimError
        with self.assertRaises(ShimError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_signed_implied_scale_and_zero_sign_round_trip(self):
        """Catch physical decimal insertion, sign stripping, or negative-zero erasure."""
        from cobolmap.shared import FieldSpec, parse_display, format_display
        field = FieldSpec("SIGNED-N", "S9(2)V9(2)", sign="leading_separate")
        for encoded, text, negative_zero in ((b"+0123", "1.23", False), (b"-0123", "-1.23", False),
                                               (b"+0000", "0.00", False), (b"-0000", "-0.00", True),
                                               (b"+9999", "99.99", False), (b"-9999", "-99.99", False)):
            with self.subTest(encoded=encoded):
                value = parse_display(encoded, field)
                self.assertEqual(str(value), text)
                self.assertEqual(value.negative_zero, negative_zero)
                self.assertEqual(format_display(value, field), encoded)

    def test_unsigned_encoding_is_exact_not_assignment_rounding(self):
        """Catch hidden quantization, magnitude coercion, or field max off-by-one."""
        from cobolmap.shared import FieldSpec, format_display, parse_display
        field = FieldSpec("N", "9(2)V9(2)")
        for text, raw in (("0", b"0000"), ("0.01", b"0001"), ("1.2300", b"0123"),
                           ("99.98", b"9998"), ("99.99", b"9999")):
            with self.subTest(text=text):
                self.assertEqual(format_display(text, field), raw)
                self.assertEqual(format_display(parse_display(raw, field), field), raw)
        for bad in ("1.239", "1.2301", "100.00", "-0.00", "-1.00"):
            with self.subTest(bad=bad):
                self.assert_code("shim_unrepresentable", format_display, bad, field)
        for bad in (1.2, True):
            self.assert_code("shim_type", format_display, bad, field)

    def test_numeric_bytes_require_digits_and_explicit_leading_sign(self):
        """Catch whitespace/dot/sign normalization and malformed DISPLAY acceptance."""
        from cobolmap.shared import FieldSpec, parse_display
        unsigned = FieldSpec("U", "9(2)V9(2)")
        signed = FieldSpec("S", "S9(2)V9(2)", sign="LEADING SEPARATE")
        for bad in (b"12.3", b" 123", b"+123", b"-123", b"\xff123"):
            with self.subTest(bad=bad):
                self.assert_code("shim_type", parse_display, bad, unsigned)
        for bad in (b"00123", b"0123-", b"--123", b"+ 123"):
            with self.subTest(bad=bad):
                self.assert_code("shim_type", parse_display, bad, signed)

    def test_exact_width_and_builtin_bytes_are_required(self):
        """Catch accepting streams, LF terminators, mutable buffers or null as a record."""
        from cobolmap.shared import FieldSpec, parse_display
        field = FieldSpec("N", "9(2)")
        for bad in (b"1", b"123", b"12\n", b"", "12", bytearray(b"12"), memoryview(b"12"), None):
            with self.subTest(kind=type(bad).__name__):
                self.assert_code("shim_layout", parse_display, bad, field)
        self.assertEqual(str(parse_display(b"12", field)), "12")

    def test_alpha_padding_and_preserved_spaces_without_codec_truncation(self):
        """Catch trimming decoded spaces or truncating an overwidth format request."""
        from cobolmap.shared import FieldSpec, parse_display, format_display
        field = FieldSpec("TEXT", "X(4)")
        for text, raw in (("", b"    "), ("A", b"A   "), (" A ", b" A  "), ("ABCD", b"ABCD")):
            with self.subTest(text=text):
                self.assertEqual(format_display(text, field), raw)
                self.assertEqual(parse_display(raw, field), raw.decode("ascii"))
        for bad in ("ABCDE", "A\n", "\t", "caf\u00e9", 12):
            with self.subTest(bad=bad):
                self.assert_code("shim_unrepresentable", format_display, bad, field)
        for bad in (b"A\nBC", b"A\x00BC", b"\xffABC"):
            self.assert_code("shim_type", parse_display, bad, field)

    def test_alpha_move_assignment_pads_truncates_and_rejects_mixed_types(self):
        """Catch conflating assignment truncation with exact codec formatting or coercion."""
        from cobolmap.shared import FieldSpec, move, decimal_value
        short = FieldSpec("SHORT", "X(3)")
        long = FieldSpec("LONG", "X(5)")
        numeric = FieldSpec("NUM", "9(2)")
        for value, source, destination, expected in (("ABCDE", long, short, "ABC"),
                                                      ("A", short, long, "A    ")):
            result = move(value, source, destination)
            self.assertIsNone(result.fault_or_null)
            self.assertFalse(result.size_error)
            self.assertEqual(result.value, expected)
            self.assertEqual(result.stored_bytes_or_null, expected.encode("ascii"))
        for value, source, destination in (("12", short, numeric), (decimal_value("12"), numeric, short)):
            result = move(value, source, destination)
            self.assertIsNone(result.value)
            self.assertEqual(result.fault_or_null.code, "shim_type")

    def test_internal_signed_or_packed_fields_have_no_external_codec(self):
        """Catch accidental completion of embedded/packed external byte policies."""
        from cobolmap.shared import FieldSpec, parse_display, format_display
        fields = (FieldSpec("E", "S9(2)V9(2)", sign="embedded"),
                  FieldSpec("P", "S9(2)V9(2)", usage="COMP-3", sign="packed"))
        for field in fields:
            self.assert_code("shim_layout", format_display, "1.23", field)
            self.assert_code("shim_layout", parse_display, b"0" * field.width, field)

    def test_layout_metadata_and_mapping_reject_false_types(self):
        """Catch bool-as-int metadata, inconsistent widths, unknown keys and S14 widening."""
        from cobolmap.shared import FieldSpec
        for keywords in ({"offset": True}, {"width": True}, {"scale": True}, {"digits": True},
                         {"width": 99}, {"scale": 1}, {"digits": 4}, {"usage": "BINARY"}):
            with self.subTest(keywords=keywords):
                self.assert_code("shim_layout", FieldSpec, "N", "9(2)", **keywords)
        for sign in ("TRAILING SEPARATE", "SIGN TRAILING SEPARATE"):
            self.assert_code("shim_layout", FieldSpec, "S", "S9(2)", sign=sign)
        for mapping in (None, {"pic": "9(2)"}, {"name": "N"}, {"name": "N", "pic": "9(2)", "unknown": 1}):
            self.assert_code("shim_layout", FieldSpec.from_mapping, mapping)
        valid = FieldSpec.from_mapping({"name": "S", "pic": "s9(2)v9(2)", "usage": "display",
                                        "sign": "leading_separate", "offset": 0, "width": 5, "scale": 2, "digits": 4})
        self.assertEqual((valid.pic, valid.sign, valid.width), ("S9(2)V9(2)", "LEADING SEPARATE", 5))

    def test_record_offsets_control_encoding_order(self):
        """Catch list-order encoding, sign loss, extra-binding leakage, or alpha trimming."""
        from cobolmap.shared import FieldSpec, encode_record, decode_record, decimal_value
        numeric = FieldSpec("N", "S9(1)V9(1)", sign="leading_separate", offset=0)
        alpha = FieldSpec("TEXT", "X(3)", offset=3)
        bindings = {"N": decimal_value("-0.0"), "TEXT": "A", "WORKING-UNUSED": "must-not-leak"}
        for fields in ((numeric, alpha), (alpha, numeric)):
            raw = encode_record(bindings, fields)
            self.assertEqual(raw, b"-00A  ")
            decoded = decode_record(raw, fields)
            self.assertEqual(str(decoded["N"]), "-0.0")
            self.assertTrue(decoded["N"].negative_zero)
            self.assertEqual(decoded["TEXT"], "A  ")

    def test_record_layout_gap_overlap_and_folded_duplicate_refuse(self):
        """Catch silent record holes, overlapping fields or case-folded duplicate names."""
        from cobolmap.shared import FieldSpec, decode_record
        layouts = ((FieldSpec("A", "X(1)", offset=0), FieldSpec("B", "X(1)", offset=2)),
                   (FieldSpec("A", "X(1)", offset=0), FieldSpec("B", "X(1)", offset=0)),
                   (FieldSpec("A", "X(1)", offset=0), FieldSpec("a", "X(1)", offset=1)))
        for fields in layouts:
            self.assert_code("shim_layout", decode_record, b"AB", fields)
        for fields in ((), "not fields", (object(),)):
            self.assert_code("shim_layout", decode_record, b"A", fields)

    def test_record_length_and_missing_binding_failures_remain_distinct(self):
        """Catch missing-field defaults, trailing LF consumption or null-as-empty coercion."""
        from cobolmap.shared import FieldSpec, encode_record, decode_record
        fields = (FieldSpec("A", "X(2)"), FieldSpec("B", "9(1)", offset=2))
        self.assertEqual(encode_record({"A": "X", "B": "1"}, fields), b"X 1")
        for bindings in ({"A": "X"}, {"B": "1"}, None, [("A", "X"), ("B", "1")]):
            self.assert_code("pointer_unresolved", encode_record, bindings, fields)
        for raw in (b"X1", b"X 1Z", b"X 1\n", None, bytearray(b"X 1")):
            self.assert_code("shim_layout", decode_record, raw, fields)

    def test_record_field_count_boundary_is_explicit(self):
        """Catch off-by-one field caps without generating an input partition."""
        from cobolmap.shared import FieldSpec, encode_record, decode_record
        fields = tuple(FieldSpec("F" + str(i), "X(1)", offset=i) for i in range(32))
        values = {field.name: "Q" for field in fields}
        self.assertEqual(encode_record(values, fields), b"Q" * 32)
        self.assertEqual(decode_record(b"Q" * 32, fields), values)
        too_many = fields + (FieldSpec("F32", "X(1)", offset=32),)
        self.assert_code("shim_layout", decode_record, b"Q" * 33, too_many)
