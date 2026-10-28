"""Deferred builder IR/map regression source; no execution during construction."""
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus/fixtures/parser-map/ir"

def load_ir(name):
    from cobolmap.parse import parse
    raw = (FIXTURES / (name + ".cbl")).read_bytes()
    return raw, parse(raw.decode("ascii"), filename=name + ".cbl")

class IRMapRegressions(unittest.TestCase):
    def test_literal_comments_exact_lf_crlf_spans(self):
        from cobolmap.mapping import resolve_pointer
        for name in ("quoted_span_lf", "quoted_span_crlf"):
            with self.subTest(case=name):
                raw, program = load_ir(name)
                self.assertEqual(program.source_sha256, hashlib.sha256(raw).hexdigest())
                self.assertEqual(program.source.encode("ascii"), raw)
                literal = program.paragraphs[0].statements[0].args["values"][0]
                self.assertEqual(literal.args["value"], 'A"B *> CALL')
                self.assertEqual(resolve_pointer(program, literal.span, raw=b'"A""B *> CALL"'), b'"A""B *> CALL"')
                self.assertEqual(literal.span.line_start, raw[:literal.span.byte_start].count(b"\n") + 1)

    def test_pointer_identity_and_bytes_are_not_interchangeable(self):
        from cobolmap.mapping import resolve_pointer, MappingRefusal, build_map
        raw, program = load_ir("quoted_span_lf")
        pointer = program.paragraphs[0].statements[0].args["values"][0].span
        with self.assertRaises(MappingRefusal) as wrong_hash:
            build_map(replace(program, source_sha256="0" * 64))
        self.assertEqual(wrong_hash.exception.code, "pointer_unresolved")
        with self.assertRaises(MappingRefusal):
            resolve_pointer(program, pointer.model_copy(update={"filename": "different.cbl"}))
        with self.assertRaises(MappingRefusal):
            resolve_pointer(program, pointer, raw=b"different literal")

    def test_external_and_packed_layouts_remain_distinct(self):
        raw, program = load_ir("pic_layout")
        fields = {field.name: field for field in program.fields}
        first, second, internal = fields["IN-SIGNED"], fields["IN-TEXT"], fields["PACKED"]
        self.assertEqual((first.storage, first.record_name, first.width, first.offset, first.scale, first.sign),
                         ("input", "IN-REC", 5, 0, 2, "leading_separate"))
        self.assertEqual((second.width, second.offset), (3, 5))
        self.assertEqual((internal.storage, internal.usage, internal.width, internal.digits, internal.scale, internal.sign),
                         ("working", "COMP-3", 3, 5, 2, "packed"))

    def test_call_return_contexts_do_not_cross(self):
        from cobolmap.mapping import build_map
        raw, program = load_ir("two_call_returns")
        result = build_map(program)
        edges = {(edge.source, edge.target) for edge in result.edges}
        first = "paragraph:MAIN/0/return"
        second = "paragraph:MAIN/1/return"
        self.assertIn((first, "paragraph:MAIN/1"), edges)
        self.assertIn((second, "paragraph:MAIN/2"), edges)
        self.assertNotIn((first, "paragraph:MAIN/2"), edges)
        self.assertNotIn((second, "paragraph:MAIN/1"), edges)

    def test_cleanup_flag_tracks_successful_open(self):
        raw, program = load_ir("guarded_open_flag")
        self.assertEqual(program.source.encode("ascii"), raw)
        self.assertEqual(program.paragraphs[-1].name, "MAIN")

    def test_context_expansion_limit_has_no_partial_map(self):
        from cobolmap.mapping import build_map, MappingLimitRefusal
        raw, program = load_ir("map_context_limit")
        with self.assertRaises(MappingLimitRefusal) as caught:
            build_map(program)
        self.assertEqual(caught.exception.code, "map_limit")
        self.assertEqual(caught.exception.span.source_sha256, hashlib.sha256(raw).hexdigest())
