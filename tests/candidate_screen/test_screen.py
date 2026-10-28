"""Builder synthetic structural screening vectors; candidate strings are AST DATA.

No candidate/guest/translator/runtime import, compile, load, invocation or receipt.
Dummy helper bytes/reference presence do NOT authenticate entry approval or tools.
"""
import hashlib
from pprint import pformat
import unittest

from cobolmap.contracts import ArtifactRef, ExecutionPins
from cobolmap.oracle.pins import Blob, CandidateToolchain, SDK_PATHS, helper_digest
from cobolmap.sandbox import ScreenContext, ScreenResult, screen_candidate

SOURCE = b"BUILDER SOURCE DATA ONLY.\nSECOND LINE.\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(path, raw):
    return Blob(ref=ArtifactRef(path=path, sha256=digest(raw), byte_length=len(raw)), data=raw)


def reference(path):
    return blob(path, b"builder synthetic metadata; NOT measured or authentic").ref


def plan(source=SOURCE, filename="builder.cbl"):
    first_end = source.index(b"\n")
    pointer = dict(source_sha256=digest(source), filename=filename,
                   line_start=1, line_end=1, byte_start=0, byte_end=first_end)
    second = dict(pointer, line_start=2, line_end=2, byte_start=first_end + 1, byte_end=len(source) - 1)
    # Native-shaped literal containers/spans, not an admitted/semantic ProgramIR.
    return dict(version=1, source_sha256=digest(source), filename=filename,
        fields=[dict(name="VALUE", span=pointer)], files=[dict(name="INPUT"), dict(name="OUTPUT")],
        paragraphs=[dict(name="MAIN", span=pointer,
            body=[dict(kind="stop", span=second, body=[], otherwise=[])])])


def candidate(data=None, docstring=None):
    # Match the actual emitter's pformat/import/PLAN/fixed-wrapper surface only.
    # This returns inert source text; never compile/exec/import or call it.
    return ((repr(docstring) + "\n" if docstring is not None else "")
        + "from cobolmap.translate.runtime import run_plan\n\nPLAN = "
        + pformat(plan() if data is None else data, width=100, sort_dicts=True)
        + "\n\ndef run_case(input_present, records):\n"
        + "    return run_plan(PLAN, input_present, records)\n")


def context(raw, *, source=SOURCE, filename="builder.cbl", structural_reference=True):
    if type(raw) is str:
        raw = raw.encode("utf-8")
    helpers = tuple(blob(name, ("BUILDER INERT SDK DATA: " + name).encode("ascii")) for name in sorted(SDK_PATHS))
    helper_map = {item.ref.path: item for item in helpers}
    # Synthetic commitments only; no executable, compiler/tool measurement or approval.
    pins = ExecutionPins(compiler_version="builder-synthetic",
        **{name: digest(name.encode("ascii")) for name in (
            "compiler_sha256", "compiler_config_sha256", "runtime_config_sha256", "image_sha256",
            "libcob_sha256", "default_conf_sha256", "generator_sha256")},
        shim_sha256=helper_map["cobolmap/shared/decimal_shim.py"].ref.sha256)
    toolchain = CandidateToolchain(pins=pins, runtime_version="builder-synthetic-not-installed",
        runtime=reference("builder/runtime-not-executable"),
        runtime_package=reference("builder/package-not-installed"), runtime_info=reference("builder/info-not-measured"),
        launcher=helper_map["entry.py"].ref, helper_manifest_sha256=helper_digest(helpers))
    return ScreenContext(task_id="builder_screen_task", program_id="builder_screen_program",
        original_source=blob("builder/source-not-admitted.cbl", source), source_filename=filename,
        candidate_sha256=digest(raw), toolchain=toolchain, helpers=helpers,
        entry_approval=reference("builder/NOT-authentic-entry-approval.json") if structural_reference else None)


class ScreenVectors(unittest.TestCase):
    def accepted(self, raw, ctx=None):
        result = screen_candidate(raw, context=context(raw) if ctx is None else ctx)
        self.assertEqual(result.status, "screened", result.reasons)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.containment_verified)
        self.assertFalse(result.study_admitted)
        return result

    def refused(self, raw, ctx=None, codes=None):
        result = screen_candidate(raw, context=context(raw) if ctx is None else ctx)
        self.assertEqual(result.status, "refused", result.reasons)
        self.assertTrue(result.reasons)
        if codes is not None:
            self.assertIn(result.reasons[0].code, codes)
        return result

    def test_fixed_emitter_wrapper_optional_docstring_and_text_bytes(self):
        for doc in (None, "inert builder module documentation"):
            text = candidate(docstring=doc)
            textual = self.accepted(text)
            binary = self.accepted(text.encode("utf-8"))
            self.assertEqual(textual.candidate, binary.candidate)
            self.assertEqual(textual.candidate.sha256, digest(text.encode("utf-8")))
            self.assertGreater(textual.ast_nodes, 0)

    def test_unicode_docstring_is_inert_and_raw_utf8_pinned(self):
        text = candidate(docstring="Builder café 🔒 — inert text only")
        result = self.accepted(text)
        self.assertEqual(result.candidate.byte_length, len(text.encode("utf-8")))
        self.assertEqual(result.candidate.sha256, digest(text.encode("utf-8")))

    def test_crlf_candidate_is_not_normalized_into_lf_identity(self):
        text = candidate()
        lf = self.accepted(text)
        crlf = self.accepted(text.replace("\n", "\r\n"))
        self.assertNotEqual(lf.candidate.sha256, crlf.candidate.sha256)

    def test_source_logical_filename_and_artifact_path_are_distinct(self):
        text = candidate()
        ctx = context(text)
        result = self.accepted(text, ctx)
        self.assertNotEqual(ctx.original_source.ref.path, ctx.source_filename)
        self.assertEqual(result.context.original_source.ref, ctx.original_source.ref)

    def test_import_alias_foreign_relative_extra_imports_refuse(self):
        text = candidate()
        for imported in ("from cobolmap.translate.runtime import run_plan as run_plan",
                         "from os import run_plan", "from .runtime import run_plan",
                         "from cobolmap.translate.runtime import run_plan, RuntimeFault",
                         "import os\nfrom cobolmap.translate.runtime import run_plan"):
            with self.subTest(imported=imported):
                self.refused(text.replace("from cobolmap.translate.runtime import run_plan", imported, 1))

    def test_decorators_defaults_annotations_variadics_and_async_refuse(self):
        text = candidate()
        header = "def run_case(input_present, records):"
        for replacement in ("@decorate\n" + header, "def run_case(input_present, records=call()):",
                            "def run_case(input_present: int, records):", "def run_case(input_present, *records):",
                            "def run_case(input_present, records, /):", "async " + header,
                            "def run_case(input_present, records) -> int:"):
            with self.subTest(header=replacement):
                self.refused(text.replace(header, replacement))

    def test_extra_top_level_effects_and_bindings_refuse_without_running(self):
        for prefix, suffix in (("print('MUST NOT RUN')\n", ""), ("", "open('MUST-NOT-OPEN')\n"),
                               ("", "run_case(False, ())\n"), ("", "PLAN = {}\n")):
            self.refused(prefix + candidate() + suffix)

    def test_dynamic_calls_reflection_and_argument_rebinding_refuse(self):
        text = candidate()
        call = "run_plan(PLAN, input_present, records)"
        for replacement in ("getattr(run_plan, '__call__')(PLAN, input_present, records)",
                            "run_plan.__call__(PLAN, input_present, records)", "__import__('os')",
                            "eval('1')", "exec('pass')", "run_plan(PLAN, records, input_present)",
                            "run_plan(PLAN, input_present=input_present, records=records)"):
            with self.subTest(call=replacement):
                self.refused(text.replace(call, replacement))

    def test_function_body_assignment_and_wrong_entry_name_refuse(self):
        text = candidate()
        self.refused(text.replace("    return ", "    local = 1\n    return "))
        self.refused(text.replace("def run_case(", "def other_case("))

    def test_inert_negative_tuple_bool_none_literals_are_supported(self):
        data = plan()
        data["candidate_loop_proofs"] = [(-1, None, True, "inert metadata")]
        self.accepted(candidate(data))

    def test_unsupported_literals_comprehensions_calls_duplicate_keys_unpack_refuse(self):
        data = plan()
        data["candidate_loop_proofs"] = ["BUILDER_REPLACE_LITERAL"]
        text = candidate(data)
        for expression in ("[x for x in ()]", "call()", "f'not ordinary'", "b'bytes'", "1.5", "1j",
                           "{1: 2}", "{'x':1,'x':2}", "{'x':1,**{}}", "{1,2}", "...", "2**3"):
            with self.subTest(expression=expression):
                self.refused(text.replace(repr("BUILDER_REPLACE_LITERAL"), expression, 1))

    def test_encoding_cookies_first_or_second_line_refuse(self):
        for prefix in ("# coding: utf-8\n", "# coding=unicode_escape\n", "# first\n# coding: latin-1\n"):
            raw = prefix + candidate()
            self.refused(raw, codes={"candidate_encoding"})

    def test_empty_nul_invalid_utf8_and_candidate_subclasses_refuse(self):
        for raw in (b"", b"\0", b"\xff"):
            result = screen_candidate(raw)
            self.assertEqual(result.status, "refused")
        class OtherBytes(bytes):
            pass
        class OtherText(str):
            pass
        for raw in (OtherBytes(b"data"), OtherText("data")):
            self.assertEqual(screen_candidate(raw).reasons[0].code, "candidate_type")

    def test_candidate_pin_mismatch_retains_actual_hash(self):
        text = candidate()
        ctx = context(text).model_copy(update={"candidate_sha256": digest(b"other structural bytes")})
        result = self.refused(text, ctx, {"candidate_pin"})
        self.assertEqual(result.candidate.sha256, digest(text.encode()))

    def test_plan_source_version_filename_and_unknown_root_refuse(self):
        for key, value in (("source_sha256", digest(b"other source")), ("filename", "other.cbl"),
                           ("version", True), ("extra_root", "not supported")):
            data = plan()
            data[key] = value
            self.refused(candidate(data), codes={"plan_shape"})

    def test_pointer_source_line_filename_bounds_and_bool_offsets_refuse(self):
        for key, value in (("source_sha256", digest(b"wrong pointer")), ("filename", "other.cbl"),
                           ("line_start", 2), ("line_end", True), ("byte_start", True),
                           ("byte_start", 1000), ("byte_end", len(SOURCE) + 1)):
            data = plan()
            data["fields"][0]["span"][key] = value
            self.refused(candidate(data), codes={"source_pointer"})

    def test_pointer_second_line_and_exclusive_end_lf_crlf(self):
        for source in (SOURCE, SOURCE.replace(b"\n", b"\r\n")):
            text = candidate(plan(source))
            self.accepted(text, context(text, source=source))

    def test_original_unicode_oversize_linecount_and_unsafe_filename_refuse(self):
        text = candidate()
        for source in ("café\nsecond\n".encode(), b"a" * 65537, b"x\n" * 201):
            self.refused(text, context(text, source=source), {"source_invalid"})
        self.refused(text, context(text, filename="../builder.cbl"), {"source_invalid"})

    def test_missing_context_and_missing_structural_entry_reference_pending(self):
        text = candidate()
        missing = screen_candidate(text)
        absent = screen_candidate(text, context=context(text, structural_reference=False))
        self.assertEqual((missing.status, absent.status), ("pending", "pending"))
        self.assertEqual(missing.reasons[0].code, "context_missing")
        self.assertEqual(absent.reasons[0].code, "entry_missing")

    def test_exact_eight_helpers_order_and_missing_duplicate_foreign_paths(self):
        text = candidate()
        ctx = context(text)
        self.accepted(text, ctx.model_copy(update={"helpers": tuple(reversed(ctx.helpers))}))
        for helpers in (ctx.helpers[:-1], ctx.helpers[:-1] + (ctx.helpers[0],),
                        ctx.helpers[:-1] + (blob("foreign.py", b"inert foreign helper"),)):
            self.refused(text, ctx.model_copy(update={"helpers": helpers}), {"helper_pin"})

    def test_manifest_launcher_shim_pin_and_empty_entry_bytes_refuse(self):
        text = candidate()
        ctx = context(text)
        for toolchain in (
            ctx.toolchain.model_copy(update={"helper_manifest_sha256": digest(b"wrong manifest")}),
            ctx.toolchain.model_copy(update={"launcher": reference("builder/not-entry.py")}),
            ctx.toolchain.model_copy(update={"pins": ctx.toolchain.pins.model_copy(update={"shim_sha256": digest(b"wrong shim")})}),
        ):
            self.refused(text, ctx.model_copy(update={"toolchain": toolchain}), {"helper_pin"})
        helpers = tuple(blob("entry.py", b"") if item.ref.path == "entry.py" else item for item in ctx.helpers)
        empty = next(item.ref for item in helpers if item.ref.path == "entry.py")
        toolchain = ctx.toolchain.model_copy(update={"launcher": empty, "helper_manifest_sha256": helper_digest(helpers)})
        self.refused(text, ctx.model_copy(update={"helpers": helpers, "toolchain": toolchain}), {"helper_pin"})

    def test_constructed_nested_hash_bypass_and_context_subclass_refuse(self):
        text = candidate()
        ctx = context(text)
        changed_blob = ctx.original_source.model_copy(update={"data": b"unmatched bytes"})
        self.refused(text, ctx.model_copy(update={"original_source": changed_blob}), {"context_invalid"})
        changed_helper = ctx.helpers[0].model_copy(update={"data": b"unmatched bytes"})
        self.refused(text, ctx.model_copy(update={"helpers": (changed_helper,) + ctx.helpers[1:]}), {"context_invalid"})
        self.refused(text, ctx.model_copy(update={"source_filename": 4}), {"context_invalid"})
        class ForeignContext(ScreenContext):
            pass
        foreign = ForeignContext(**ctx.model_dump())
        self.refused(text, foreign, {"context_invalid"})

    def test_screened_dummy_reference_never_grants_authority_and_all_states_false(self):
        text = candidate()
        screened = self.accepted(text)
        self.assertIn("NOT-authentic", screened.context.entry_approval.path)
        results = (screened, screen_candidate(text), self.refused(text + "print('DATA ONLY')\n"))
        for result in results:
            self.assertIs(result.execution_authorized, False)
            self.assertIs(result.containment_verified, False)
            self.assertIs(result.study_admitted, False)
        fields = screened.model_dump()
        for name in ("execution_authorized", "containment_verified", "study_admitted"):
            with self.assertRaises(ValueError):
                ScreenResult(**dict(fields, **{name: True}))

    def test_candidate_byte_and_line_limits_refuse_before_ast(self):
        for raw in (b"x" * 65537, "é" * 65536, b"#\n" * 4097):
            result = screen_candidate(raw)
            self.assertEqual(result.status, "refused")
            self.assertEqual(result.reasons[0].code, "candidate_limit")
            self.assertIsNone(result.ast_nodes)

    def test_string_integer_and_sequence_small_native_boundaries(self):
        data = plan()
        data["candidate_loop_proofs"] = ["BUILDER_BOUNDARY_REPLACE"]
        template = candidate(data)
        for good, bad in (("s" * 8192, "s" * 8193), (999999999999, 1000000000000),
                          ([0] * 4096, [0] * 4097)):
            # Compact repr keeps line/byte ceilings out of the literal boundary
            # experiment; pprint would otherwise introduce thousands of lines.
            self.accepted(template.replace(repr("BUILDER_BOUNDARY_REPLACE"), repr(good), 1))
            self.refused(template.replace(repr("BUILDER_BOUNDARY_REPLACE"), repr(bad), 1), codes={"literal_limit"})

    def test_lexical_depth_and_token_limits_bounded_inert_data(self):
        data = plan()
        data["candidate_loop_proofs"] = ["BUILDER_DEPTH_REPLACE"]
        text = candidate(data)
        for expression in ("[" * 65 + "0" + "]" * 65, "[" + "0," * 17000 + "]"):
            raw = text.replace(repr("BUILDER_DEPTH_REPLACE"), expression, 1)
            self.assertLess(len(raw.encode()), 65536)
            self.refused(raw, codes={"token_limit"})

    def test_plan_container_caps_are_not_accepted_as_favorable_screen(self):
        for key, value in (("fields", [{}] * 33), ("files", [{}]), ("paragraphs", [{}] * 9)):
            data = plan()
            data[key] = value
            self.refused(candidate(data), codes={"plan_shape"})


if __name__ == "__main__":
    unittest.main()
