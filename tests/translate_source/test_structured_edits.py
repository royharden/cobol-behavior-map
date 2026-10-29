"""Source-only native edit tests. Generated candidate text is never executed."""
import copy
from dataclasses import replace, fields, is_dataclass
from collections.abc import Mapping
import hashlib
import unittest

from cobolmap.translate import TranslationRefusal, translate
from dl2_translate_fixtures import make_change, one_ir, parse_source, plan_from_result, plan_node, source, walk_ir


def _snapshot(value):
    """Copy IR content to primitives without pickling immutable mapping proxies."""
    if is_dataclass(value):
        return (type(value).__name__, tuple((field.name, _snapshot(getattr(value, field.name)))
                                           for field in fields(value)))
    if isinstance(value, Mapping):
        return tuple(sorted((key, _snapshot(item)) for key, item in value.items()))
    if isinstance(value, (tuple, list)):
        return tuple(_snapshot(item) for item in value)
    if hasattr(value, "source_sha256") and hasattr(value, "byte_start"):
        return tuple((key, getattr(value, key)) for key in
                     ("source_sha256", "filename", "line_start", "line_end", "byte_start", "byte_end"))
    if type(value) in (str, int, bool, type(None)):
        return value
    raise TypeError("unsupported snapshot value")


class StructuredEditSourceTests(unittest.TestCase):
    def _plans(self, text, kind, spelling, operation, before, after, replacement):
        program = parse_source(text)
        original_ir = _snapshot(program)
        raw = program.source.encode("ascii")
        candidates = [node for node in walk_ir(program) if node.kind == kind and
                      raw[node.span.byte_start:node.span.byte_end] == spelling.encode("ascii")]
        self.assertTrue(candidates, "builder target spelling must exist")
        target = candidates[0]
        change = make_change(program, target, operation, before, after, replacement)
        base_result = translate(program)
        changed_result = translate(program, change)
        _, base = plan_from_result(base_result)
        _, changed = plan_from_result(changed_result)
        self.assertEqual(_snapshot(program), original_ir, "translate must not mutate frozen parser IR")
        self.assertEqual(program.source, text, "an edit must not change original COBOL bytes")
        digest = hashlib.sha256(text.encode("ascii")).hexdigest()
        self.assertEqual(base_result.original_source_sha256, digest)
        self.assertEqual(changed_result.original_source_sha256, digest)
        self.assertEqual(changed["source_sha256"], digest)
        self.assertEqual(changed["filename"], program.filename)
        self.assertEqual(changed["fields"], base["fields"])
        self.assertEqual(changed["files"], base["files"])
        self.assertEqual(changed["paragraphs"][0]["span"], base["paragraphs"][0]["span"])
        return program, target, base, changed

    def _refuses(self, program, change, code):
        with self.assertRaises(TranslationRefusal) as caught:
            translate(program, change)
        self.assertEqual(caught.exception.code, code)

    def test_numeric_literal_changes_only_bound_arithmetic_operand(self):
        """what_bug_this_catches: broad text replacement changes a second equal literal or original identity."""
        program, target, base, changed = self._plans(
            source("ADD 1.25 TO WORK-N END-ADD\nIF WORK-N < 1.25\nDISPLAY FLAG\nEND-IF"),
            "literal", "1.25", "replace_numeric_literal", "1.25", "2.50", "2.50")
        # The source has two equal literals; select the arithmetic operand by its statement span.
        self.assertEqual(plan_node(changed, "literal", target.span.byte_start)["value"], "2.50")
        base_target = plan_node(base, "literal", target.span.byte_start)
        self.assertEqual(base_target["value"], "1.25")
        expected = copy.deepcopy(base)
        plan_node(expected, "literal", target.span.byte_start)["value"] = "2.50"
        expected["candidate_loop_proofs"] = []
        self.assertEqual(changed, expected)

    def test_comparator_changes_only_numeric_if_relation(self):
        """what_bug_this_catches: comparator editing rewrites operand order or unrelated IF branches."""
        program, target, base, changed = self._plans(
            source("IF WORK-N < 2\nMOVE \"NEW\" TO FLAG\nELSE\nMOVE \"OLD\" TO FLAG\nEND-IF"),
            "compare", "WORK-N < 2", "replace_comparator", "<", ">=", "WORK-N >= 2")
        comparison = plan_node(changed, "compare", target.span.byte_start)
        self.assertEqual((comparison["left"]["name"], comparison["op"], comparison["right"]["value"]),
                         ("WORK-N", ">=", "2"))
        expected = copy.deepcopy(base)
        plan_node(expected, "compare", target.span.byte_start)["op"] = ">="
        expected["candidate_loop_proofs"] = []
        self.assertEqual(changed, expected)

    def test_alpha_literal_and_rounded_preserve_other_statements(self):
        """what_bug_this_catches: an edit leaks into a neighboring MOVE or drops arithmetic flags."""
        text = source("MOVE \"NEW\" TO FLAG\nMOVE \"OLD\" TO FLAG\nADD 1 TO WORK-N END-ADD")
        _, alpha_target, base, alpha = self._plans(
            text, "literal", '"NEW"', "replace_alpha_literal", "NEW", "YES", '"YES"')
        expected = copy.deepcopy(base)
        plan_node(expected, "literal", alpha_target.span.byte_start)["value"] = "YES"
        expected["candidate_loop_proofs"] = []
        self.assertEqual(alpha, expected)
        _, rounded_target, base, rounded = self._plans(
            text, "add", "ADD 1 TO WORK-N END-ADD", "set_rounded", False, True,
            "ADD 1 TO WORK-N ROUNDED END-ADD")
        changed_add = plan_node(rounded, "add", rounded_target.span.byte_start)
        self.assertTrue(changed_add["rounded"])
        self.assertFalse(changed_add["has_size_error"])
        expected = copy.deepcopy(base)
        plan_node(expected, "add", rounded_target.span.byte_start)["rounded"] = True
        expected["candidate_loop_proofs"] = []
        self.assertEqual(rounded, expected)

    def test_descriptor_identity_and_closed_shape_refusals(self):
        """what_bug_this_catches: a foreign or malformed mapping silently edits a matching token."""
        program = parse_source(source("ADD 1 TO WORK-N END-ADD"))
        node = one_ir(program, "literal", "1")
        valid = make_change(program, node, "replace_numeric_literal", "1", "2", "2")
        mutations = (
            ("original_sha256", "0" * 64, "change_source_hash"),
            ("changed_sha256", "not-a-sha", "change_source_hash"),
            ("changed_sha256", program.source_sha256, "change_source_hash"),
            ("operation", "rewrite_program", "unsupported_change"),
            ("before", "9", "change_target"),
        )
        for key, value, code in mutations:
            with self.subTest(key=key, value=value):
                request = copy.deepcopy(valid)
                request[key] = value
                self._refuses(program, request, code)
        for key, value in (("file", "other.cbl"), ("line", node.span.line_start + 1),
                           ("byte_start", node.span.byte_start + 1),
                           ("byte_end", node.span.byte_end + 1), ("node_kind", "reference")):
            with self.subTest(target_key=key):
                request = copy.deepcopy(valid)
                request["target"][key] = value
                self._refuses(program, request, "change_target")
        request = copy.deepcopy(valid)
        request["extra"] = "unrecognized"
        self._refuses(program, request, "unsupported_change")
        request = copy.deepcopy(valid)
        request["target"]["extra"] = "unrecognized"
        self._refuses(program, request, "change_target")

    def test_semantic_noops_and_context_bounds_refuse(self):
        """what_bug_this_catches: byte-different equal values or unrepresentable edits pass as changes."""
        program = parse_source(source("ADD 1.25 TO WORK-N END-ADD"))
        node = one_ir(program, "literal", "1.25")
        for after, replacement, code in (("1.25", "1.25", "change_noop"),
                                          ("1.250", "1.250", "change_noop"),
                                          ("1.251", "1.251", "change_out_of_subset"),
                                          ("1000.00", "1000.00", "change_out_of_subset")):
            with self.subTest(after=after):
                self._refuses(program, make_change(program, node, "replace_numeric_literal",
                                                  "1.25", after, replacement), code)
        alpha_program = parse_source(source('MOVE "NEW" TO FLAG'))
        alpha_node = one_ir(alpha_program, "literal", '"NEW"')
        for after, code in (("NEW ", "change_noop"), ("TOOLONG", "change_out_of_subset"),
                            ("N\tW", "change_out_of_subset")):
            with self.subTest(alpha=after):
                self._refuses(alpha_program, make_change(alpha_program, alpha_node,
                             "replace_alpha_literal", "NEW", after, '"' + after + '"'), code)

    def test_wrong_owner_and_ambiguous_typed_target_refuse(self):
        """what_bug_this_catches: an inner MOVE borrows outer arithmetic context or duplicate spans pick first."""
        program = parse_source(source("MOVE 1 TO WORK-N\nADD 2 TO WORK-N END-ADD"))
        move_literal = one_ir(program, "literal", "1")
        self._refuses(program, make_change(program, move_literal, "replace_numeric_literal",
                                          "1", "3", "3"), "change_target")
        handler_program = parse_source(source("ADD 1 TO WORK-N ON SIZE ERROR\n"
                                              "MOVE 2 TO WORK-N\nEND-ADD"))
        handler_literal = one_ir(handler_program, "literal", "2")
        self._refuses(handler_program, make_change(handler_program, handler_literal,
                     "replace_numeric_literal", "2", "3", "3"), "change_target")
        display_program = parse_source(source('DISPLAY "NEW"'))
        display_literal = one_ir(display_program, "literal", '"NEW"')
        self._refuses(display_program, make_change(display_program, display_literal,
                     "replace_alpha_literal", "NEW", "YES", '"YES"'), "change_target")
        program = parse_source(source("ADD 2 TO WORK-N END-ADD"))
        node = one_ir(program, "literal", "2")
        first = program.paragraphs[0]
        duplicated = replace(program, paragraphs=(replace(first, statements=(first.statements[0],)
                                                            + first.statements),))
        request = make_change(program, node, "replace_numeric_literal", "2", "3", "3")
        self._refuses(duplicated, request, "change_target")


if __name__ == "__main__":
    unittest.main()
