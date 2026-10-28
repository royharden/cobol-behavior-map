"""Builder assertions about inert translated source/PLAN, never candidate execution."""
import ast
from dataclasses import replace
import hashlib
import unittest
from dl2_translate_fixtures import source, parse_source, plan_from_result, walk_plan


class TranslationPlanRegressions(unittest.TestCase):
    def test_fixed_wrapper_contains_only_literal_plan_and_uninvoked_entry(self):
        """Catch extra imports/module effects or a wrapper that executes foreign text."""
        from cobolmap.translate import translate
        program = parse_source(source())
        tree, plan = plan_from_result(translate(program))
        self.assertEqual(len(tree.body), 4)
        self.assertIsInstance(tree.body[0], ast.Expr)
        self.assertIsInstance(tree.body[0].value, ast.Constant)
        imported, assigned, function = tree.body[1:]
        self.assertIsInstance(imported, ast.ImportFrom)
        self.assertEqual((imported.module, imported.level), ("cobolmap.translate.runtime", 0))
        self.assertEqual([(name.name, name.asname) for name in imported.names], [("run_plan", None)])
        self.assertEqual([target.id for target in assigned.targets], ["PLAN"])
        self.assertIsInstance(function, ast.FunctionDef)
        self.assertEqual(function.name, "run_case")
        self.assertFalse(function.decorator_list)
        self.assertIsNone(function.returns)
        self.assertEqual([arg.arg for arg in function.args.args], ["input_present", "records"])
        self.assertFalse(function.args.defaults or function.args.kw_defaults or function.args.kwonlyargs or function.args.posonlyargs)
        self.assertIsNone(function.args.vararg)
        self.assertIsNone(function.args.kwarg)
        self.assertEqual(len(function.body), 1)
        self.assertIsInstance(function.body[0], ast.Return)
        call = function.body[0].value
        self.assertEqual(call.func.id, "run_plan")
        self.assertEqual([arg.id for arg in call.args], ["PLAN", "input_present", "records"])
        self.assertFalse(call.keywords)
        self.assertEqual(len([node for node in ast.walk(tree) if isinstance(node, ast.Call)]), 1)
        self.assertEqual(set(plan), {"version", "source_sha256", "filename", "fields", "files", "paragraphs"})
        self.assertEqual(plan["version"], 1)

    def test_source_hash_filename_and_unverified_diagnostics_preserved(self):
        """Catch CRLF normalization, lost logical filename, or parity claims in source results."""
        from cobolmap.translate import translate
        hashes = []
        for ending in ("\n", "\r\n"):
            raw = source(line_ending=ending).encode("ascii")
            program = parse_source(raw.decode("ascii"), "units/original.cbl")
            result = translate(program)
            tree, plan = plan_from_result(result)
            digest = hashlib.sha256(raw).hexdigest()
            hashes.append(digest)
            self.assertEqual(result.original_source_sha256, digest)
            self.assertEqual(plan["source_sha256"], digest)
            self.assertEqual(plan["filename"], "units/original.cbl")
            self.assertIn("runtime_unverified", result.diagnostics)
            self.assertIn("no_changed_source_witness_or_equivalence_claim", result.diagnostics)
        self.assertNotEqual(*hashes)

    def test_field_storage_record_sign_and_file_bindings_survive_normalization(self):
        """Catch erased packed/separate sign metadata or input/output field reordering."""
        from cobolmap.translate import translate
        program = parse_source(source())
        tree, plan = plan_from_result(translate(program))
        self.assertEqual([field["name"] for field in plan["fields"]], [field.name for field in program.fields])
        fields = {field["name"]: field for field in plan["fields"]}
        self.assertEqual((fields["INPUT-N"]["offset"], fields["INPUT-N"]["width"], fields["DENOMINATOR"]["offset"]), (0, 4, 4))
        output, working = fields["OUT-N"], fields["WORK-N"]
        self.assertEqual((output["storage"], output["record_name"], output["sign"], output["width"], output["scale"]),
                         ("output", "OUT-REC", "leading_separate", 6, 2))
        self.assertEqual((working["storage"], working["usage"], working["sign"], working["initial"], working["width"]),
                         ("working", "COMP-3", "packed", "-1.25", 3))
        self.assertEqual(plan["files"], [
            {"name": "INFILE", "record": "IN-REC", "status": "IN-STATUS", "direction": "input", "fields": ["INPUT-N", "DENOMINATOR"]},
            {"name": "OUTFILE", "record": "OUT-REC", "status": "OUT-STATUS", "direction": "output", "fields": ["OUT-N"]}])

    def test_divide_dividend_divisor_and_subtract_receiver_order(self):
        """Catch reversing DIVIDE operands or subtracting receiver from input."""
        from cobolmap.translate import translate
        text = source("DIVIDE 10 BY DENOMINATOR GIVING OUT-N END-DIVIDE\nSUBTRACT INPUT-N FROM WORK-N END-SUBTRACT")
        tree, plan = plan_from_result(translate(parse_source(text)))
        divided, subtracted, stopped = plan["paragraphs"][0]["body"]
        self.assertEqual(divided["kind"], "divide")
        self.assertEqual((divided["left"]["kind"], divided["left"]["value"]), ("literal", "10"))
        self.assertEqual((divided["right"]["kind"], divided["right"]["name"]), ("reference", "DENOMINATOR"))
        self.assertEqual(divided["target"], "OUT-N")
        self.assertEqual((subtracted["kind"], subtracted["value"]["name"], subtracted["target"]), ("subtract", "INPUT-N", "WORK-N"))

    def test_move_add_and_multiply_keep_named_receivers(self):
        """Catch replacing destination identity with the arithmetic value operand."""
        from cobolmap.translate import translate
        text = source("MOVE INPUT-N TO WORK-N\nADD 2 TO WORK-N END-ADD\nMULTIPLY 3 BY WORK-N END-MULTIPLY\nMOVE WORK-N TO OUT-N")
        tree, plan = plan_from_result(translate(parse_source(text)))
        moved, added, multiplied, emitted, stopped = plan["paragraphs"][0]["body"]
        self.assertEqual((moved["value"]["name"], moved["target"]), ("INPUT-N", "WORK-N"))
        self.assertEqual((added["value"]["value"], added["target"]), ("2", "WORK-N"))
        self.assertEqual((multiplied["value"]["value"], multiplied["target"]), ("3", "WORK-N"))
        self.assertEqual((emitted["value"]["name"], emitted["target"]), ("WORK-N", "OUT-N"))

    def test_rounded_and_handler_body_scope_preserved(self):
        """Catch dropped ROUNDED/SIZE ERROR flags or handler statements leaked to MAIN."""
        from cobolmap.translate import translate
        text = source('DIVIDE 1 BY DENOMINATOR GIVING OUT-N ROUNDED ON SIZE ERROR MOVE "ERR" TO FLAG END-DIVIDE')
        tree, plan = plan_from_result(translate(parse_source(text)))
        nodes = plan["paragraphs"][0]["body"]
        self.assertEqual([node["kind"] for node in nodes], ["divide", "stop"])
        divided = nodes[0]
        self.assertIs(divided["rounded"], True)
        self.assertIs(divided["has_size_error"], True)
        self.assertFalse(divided["otherwise"])
        self.assertEqual(len(divided["body"]), 1)
        handler = divided["body"][0]
        self.assertEqual((handler["kind"], handler["target"], handler["value"]["value"]), ("move", "FLAG", "ERR"))
        self.assertLess(divided["span"]["byte_start"], handler["span"]["byte_start"])
        self.assertLess(handler["span"]["byte_end"], divided["span"]["byte_end"])

    def test_compute_grouping_and_left_right_tree_preserved(self):
        """Catch flattening parentheses or swapping multiply/divide tree children."""
        from cobolmap.translate import translate
        text = source("COMPUTE OUT-N = (INPUT-N + 2.25) * 2 / DENOMINATOR END-COMPUTE")
        tree, plan = plan_from_result(translate(parse_source(text)))
        expression = plan["paragraphs"][0]["body"][0]["expression"]
        self.assertEqual((expression["kind"], expression["op"], expression["right"]["name"]), ("binary", "/", "DENOMINATOR"))
        multiply = expression["left"]
        self.assertEqual((multiply["op"], multiply["right"]["value"]), ("*", "2"))
        addition = multiply["left"]
        self.assertEqual((addition["op"], addition["left"]["name"], addition["right"]["value"]), ("+", "INPUT-N", "2.25"))

    def test_paragraph_order_and_once_perform_metadata_preserved(self):
        """Catch paragraph reordering, fallthrough flattening, or invented loop bounds."""
        from cobolmap.translate import translate
        text = source('PERFORM WORKER\nDISPLAY FLAG', extra='WORKER.\nMOVE "ONE" TO FLAG\n.\nTAIL.\nDISPLAY FLAG\n.\n')
        tree, plan = plan_from_result(translate(parse_source(text)))
        self.assertEqual([item["name"] for item in plan["paragraphs"]], ["MAIN", "WORKER", "TAIL"])
        perform = plan["paragraphs"][0]["body"][0]
        self.assertEqual((perform["kind"], perform["paragraph"]), ("perform", "WORKER"))
        self.assertIsNone(perform["until"])
        self.assertIsNone(perform["max_iterations"])
        self.assertFalse(perform["body"] or perform["otherwise"])

    def test_boolean_comparisons_and_branch_bodies_preserved(self):
        """Catch changed boolean/comparison operators or swapped THEN/ELSE branches."""
        from cobolmap.translate import translate
        text = source('IF INPUT-N >= 1.00 AND DENOMINATOR <> 0\nMOVE "YES" TO FLAG\nELSE\nMOVE "NO" TO FLAG\nEND-IF')
        tree, plan = plan_from_result(translate(parse_source(text)))
        branch = plan["paragraphs"][0]["body"][0]
        condition = branch["condition"]
        self.assertEqual((condition["kind"], condition["op"]), ("boolean", "AND"))
        self.assertEqual((condition["left"]["op"], condition["left"]["left"]["name"], condition["left"]["right"]["value"]), (">=", "INPUT-N", "1.00"))
        self.assertEqual((condition["right"]["op"], condition["right"]["left"]["name"], condition["right"]["right"]["value"]), ("<>", "DENOMINATOR", "0"))
        self.assertEqual(branch["body"][0]["value"]["value"], "YES")
        self.assertEqual(branch["otherwise"][0]["value"]["value"], "NO")

    def test_all_plan_pointers_bind_exact_original_crlf_bytes(self):
        """Catch byte/line mismatch, foreign filenames or loss of field/node pointer metadata."""
        from cobolmap.translate import translate
        text = source('IF INPUT-N > 1.00\nMOVE "YES" TO FLAG\nEND-IF', line_ending="\r\n")
        program = parse_source(text, "unit/source.cbl")
        tree, plan = plan_from_result(translate(program))
        raw = text.encode("ascii")
        spans = [item["span"] for item in plan["fields"] + plan["paragraphs"]]
        spans.extend(node["span"] for node in walk_plan(plan))
        self.assertGreater(len(spans), len(plan["fields"]))
        for pointer in spans:
            self.assertEqual((pointer["source_sha256"], pointer["filename"]), (hashlib.sha256(raw).hexdigest(), "unit/source.cbl"))
            start, end = pointer["byte_start"], pointer["byte_end"]
            self.assertTrue(0 <= start < end <= len(raw))
            self.assertEqual(pointer["line_start"], raw[:start].count(b"\n") + 1)
            self.assertEqual(pointer["line_end"], raw[:end - 1].count(b"\n") + 1)

    def test_literal_text_cannot_add_generated_imports_or_calls(self):
        """Catch source-literal interpolation becoming executable Python syntax."""
        from cobolmap.translate import translate
        value = "__import__('os')"
        text = source('MOVE "' + value + '" TO FLAG')
        tree, plan = plan_from_result(translate(parse_source(text)))
        self.assertEqual(plan["paragraphs"][0]["body"][0]["value"]["value"], value)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual([node.func.id for node in calls], ["run_plan"])
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].module, "cobolmap.translate.runtime")

    def test_non_ir_wrong_source_hash_and_foreign_filename_refuse(self):
        """Catch accepting arbitrary objects or silently repairing source/IR lineage."""
        from cobolmap.translate import translate, TranslationRefusal
        program = parse_source(source())
        vectors = ((object(), "ir_type"), (replace(program, source_sha256="0" * 64), "source_hash"),
                   (replace(program, filename="foreign.cbl"), "pointer_unresolved"),
                   (replace(program, source=program.source + "\u00e9"), "source_encoding"))
        for value, code in vectors:
            with self.subTest(code=code):
                with self.assertRaises(TranslationRefusal) as caught:
                    translate(value)
                self.assertEqual(caught.exception.code, code)

    def test_duplicate_field_and_unsupported_usage_refuse_without_mutation(self):
        """Catch duplicate identities, forbidden storage modes or mutation of the original IR."""
        from cobolmap.translate import translate, TranslationRefusal
        program = parse_source(source())
        duplicate = replace(program, fields=program.fields + (program.fields[0],))
        changed = replace(program.fields[0], usage="BINARY")
        unsupported = replace(program, fields=(changed,) + program.fields[1:])
        for value, code in ((duplicate, "duplicate_name"), (unsupported, "shim_layout")):
            with self.subTest(code=code):
                with self.assertRaises(TranslationRefusal) as caught:
                    translate(value)
                self.assertEqual(caught.exception.code, code)
        self.assertEqual(program.fields[0].usage, "DISPLAY")
        self.assertEqual(len(program.fields), 7)

    def test_unknown_node_kind_is_blocked_by_native_ir_constructor(self):
        """Catch widening typed IR construction; this is a constructor prerequisite, not a fake translator code."""
        from cobolmap.parse.models import IRNode
        program = parse_source(source())
        with self.assertRaises(ValueError):
            IRNode("unsupported-verb", program.paragraphs[0].span, {})

    def test_repeat_emission_is_deterministic_and_keeps_original_ir(self):
        """Catch nondeterministic text emission or a normalizer that mutates frozen source objects."""
        from cobolmap.translate import translate
        program = parse_source(source('MOVE "YES" TO FLAG'))
        fields, paragraphs, raw = program.fields, program.paragraphs, program.source
        first, second = translate(program), translate(program)
        self.assertEqual(first.code, second.code)
        self.assertEqual(plan_from_result(first)[1], plan_from_result(second)[1])
        self.assertIs(program.fields, fields)
        self.assertIs(program.paragraphs, paragraphs)
        self.assertEqual(program.source, raw)
        self.assertEqual(paragraphs[0].statements[0].args["value"].args["value"], "YES")
