"""Pure descriptor/pending metadata; no adapted packet or receipt fabrication."""
import hashlib
import unittest
from dl2_adapter_fixtures import ROOT,PINS,g,a,binding,incomplete_artifacts,adapter_refuses


class DescriptorTests(unittest.TestCase):
    def test_relative_posix_path_preservation_and_refusals(self):
        """Catch unsafe/normalized paths being accepted as an artifact identity."""
        for value in ("unit/file.json","a-b/c_1.md","unit/.hidden"):
            self.assertEqual(a.path_name(value),value)
        for value in ("","/tmp/x","C:/x","C:x","a\\b","a//b","a/./b","a/../b","a/","./a","../a","a\n", "Ã©",True):
            with self.subTest(value=value):
                with self.assertRaises(g.AdmissionError) as caught:a.path_name(value)
                self.assertEqual(caught.exception.code,"bad_value")

    def test_raw_canonical_and_spec_lf_descriptors_are_distinct(self):
        """Catch replacing an actual-byte artifact commitment with canonical JSON or LF hash."""
        raw=b'{ "v":1 }\r\n';document={"v":1}
        item=a.descriptor("unit/meta.json",raw,document,spec=True)
        self.assertEqual(set(item),{"path","raw_bytes","raw_sha256","canonical_sha256","spec_lf_sha256"})
        self.assertEqual(item["raw_bytes"],raw)
        self.assertEqual(item["raw_sha256"],hashlib.sha256(raw).hexdigest())
        self.assertEqual(item["canonical_sha256"],hashlib.sha256(b'{"v":1}').hexdigest())
        self.assertEqual(item["spec_lf_sha256"],hashlib.sha256(b'{ "v":1 }\n').hexdigest())
        self.assertEqual(len({item[key] for key in ("raw_sha256","canonical_sha256","spec_lf_sha256")}),3)

    def test_subset_spec_is_a_required_raw_actual_pin(self):
        """Catch losing raw subset_spec or substituting GENERATOR/canonical case commitment."""
        self.assertEqual(set(a.ACTUAL_PINS),{"compiler_source","compiler_package","base_image","libcob",
              "default_conf","compiler_config","runtime_config","tool_info","runner",
              "receipt_validator","receipt_values","subset_spec"})
        self.assertEqual(a.ACTUAL_PINS.count("subset_spec"),1)
        raw=b"unit subset declaration\r\n"
        item=a.descriptor("unit/subset.md",raw)
        self.assertEqual(item["raw_sha256"],hashlib.sha256(raw).hexdigest())
        self.assertIsNone(item["canonical_sha256"]);self.assertIsNone(item["spec_lf_sha256"])
        self.assertNotEqual(item["raw_sha256"],a.CASE_HASH_CONTRACT_SHA256)

    def test_exact_spec_edition_lf_pins_preserve_raw_crlf(self):
        """Catch ratifying a different LF edition or silently normalizing stored spec bytes."""
        expected={"case_spec":"706962cfa01ebe22892e8862260db1b8e4535d38d0e665af1c8b85bc5d4100fd",
                  "family_spec":"f780695503c0f5764ba6f05737ff6d8c2466f767c847466efc4a1a6496afe483"}
        self.assertEqual(a.SPEC_PINS,expected)
        self.assertEqual(a.CASE_HASH_CONTRACT_SHA256,expected["case_spec"])
        for role,file in (("case_spec","GENERATOR.md"),("family_spec","FAMILY.md")):
            raw=(ROOT/"admission/specs"/file).read_bytes()
            item=a.descriptor("unit/"+file,raw,spec=True)
            self.assertEqual(item["raw_bytes"],raw)
            self.assertEqual(item["spec_lf_sha256"],expected[role])
            self.assertNotEqual(item["raw_sha256"],item["spec_lf_sha256"])

    def test_descriptor_bytes_type_and_absent_optional_commitments(self):
        """Catch coercing text/bytearray to pinned native artifact bytes."""
        for raw in ("text",bytearray(b'x'),None):
            with self.assertRaises(g.AdmissionError) as caught:a.descriptor("unit/x",raw)
            self.assertEqual(caught.exception.code,"bad_value")
        item=a.descriptor("unit/empty",b'')
        self.assertIsNone(item["canonical_sha256"]);self.assertIsNone(item["spec_lf_sha256"])
        self.assertEqual(item["raw_bytes"],b'')

    def test_paired_index_raw_bytes_are_not_native_recipe_commitment(self):
        """Catch collapsing task-level index bytes into a partition-local canonical document digest."""
        # Tiny structural markers only, deliberately not closed index/recipe artifacts.
        recipe={"unit_kind":"native-recipe-marker"};index={"unit_kind":"paired-index-marker"}
        recipe_raw=b'{ "unit_kind":"native-recipe-marker" }\n'
        index_raw=b'{ "unit_kind":"paired-index-marker" }\r\n'
        r=a.descriptor("unit/recipe-marker",recipe_raw,recipe)
        i=a.descriptor("unit/index-marker",index_raw,index)
        self.assertNotEqual(r["raw_sha256"],r["canonical_sha256"])
        self.assertNotEqual(i["raw_sha256"],i["canonical_sha256"])
        self.assertNotEqual(i["raw_sha256"],r["canonical_sha256"])
        self.assertEqual(r["canonical_sha256"],hashlib.sha256(b'{"unit_kind":"native-recipe-marker"}').hexdigest())


class AdapterEarlyTests(unittest.TestCase):
    def test_pending_metadata_keeps_missing_roles_and_external_pin_separate(self):
        """Catch treating a generator artifact as its own externally authenticated pin."""
        b=binding();result=a.adapt_task(b,{}, {})
        self.assertEqual(result,{"status":"pending","missing_artifacts":sorted(a.REQUIRED),
                                  "binding":b,"missing_external_bindings":["expected_generator_sha256"]})
        result=a.adapt_task(b,{},incomplete_artifacts())
        self.assertEqual(result["missing_artifacts"],[])
        self.assertEqual(result["missing_external_bindings"],["expected_generator_sha256"])
        self.assertEqual(result["status"],"pending")
        self.assertNotIn("missing_actual_pins",result) # full adapted output remains unreachable

    def test_unknown_artifact_and_binding_shape_panel_refuse(self):
        """Catch permissive unknown keys/unsupported panel before transport activation."""
        b=binding();b["extra"]=0;adapter_refuses(self,"unknown_key",b,{})
        b=binding();b["panel"]="other";adapter_refuses(self,"bad_identifier",b,{})
        adapter_refuses(self,"unknown_key",binding(),{"ungranted":{}})
        b=binding();b["task_id"]="InvalidTask";adapter_refuses(self,"bad_identifier",b,{})

    def test_source_original_edit_commitments_and_panel_rules_refuse(self):
        """Catch source/edit hash identity substitution even in pending requests."""
        b=binding();b["oracle_source_sha256"]="2"*64;adapter_refuses(self,"bad_hash",b,{})
        b=binding();b["change_sha256"]="2"*64;adapter_refuses(self,"bad_hash",b,{})
        b=binding("change");b["change_sha256"]="2"*64 # changed source still equals original
        adapter_refuses(self,"bad_hash",b,{})
        b=binding("change");b.update(oracle_source_sha256="2"*64,change_sha256="invalid")
        adapter_refuses(self,"bad_hash",b,{})

    def test_external_generator_pin_is_required_and_compared_to_raw_generator(self):
        """Catch accepting a corrupt/mismatched external instrument commitment."""
        artifacts=incomplete_artifacts()
        adapter_refuses(self,"bad_hash",binding(),artifacts,expected="not-a-hash")
        # All descriptor parsing/spec checks succeed before the external comparison.
        error=adapter_refuses(self,"bad_hash",binding(),artifacts,expected="2"*64)
        self.assertEqual(error.pointer,"")
        self.assertNotEqual(PINS["generate"],hashlib.sha256((ROOT/"admission/prepare/generator_adapter.py").read_bytes()).hexdigest())

    def test_duplicate_artifact_path_and_wrong_spec_edition_target_refuse(self):
        """Catch alias descriptors or accepting a modified construction spec edition."""
        artifacts=incomplete_artifacts();artifacts["fields"]["path"]=artifacts["case_spec"]["path"]
        adapter_refuses(self,"duplicate_key",binding(),artifacts)
        artifacts=incomplete_artifacts();artifacts["case_spec"]["raw_bytes"]+=b"unit changed edition\n"
        adapter_refuses(self,"bad_hash",binding(),artifacts)

    def test_source_raw_hash_mismatch_refuses_before_document_validation(self):
        """Catch treating a different raw source as the task-bound source artifact."""
        artifacts=incomplete_artifacts();artifacts["source"]["raw_bytes"]+=b'changed'
        adapter_refuses(self,"bad_hash",binding(),artifacts)

    def test_change_task_and_raw_edit_hash_bindings_refuse(self):
        """Catch valid-looking foreign task IDs or oracle-source hash replacing raw edit bytes."""
        b=binding("change");artifacts=incomplete_artifacts()
        source=b"changed unit metadata, not COBOL\n"
        artifacts["source"]["raw_bytes"]=source
        b["oracle_source_sha256"]=hashlib.sha256(source).hexdigest()
        declaration={"manifest_version":1,"task_id":"unit-task","original_sha256":b["original_sha256"],
                     "target":{},"operation":"unit-declaration-only","before":None,"after":None,
                     "prose":"Untrusted malformed structural marker, not an actual change task.",
                     "changed_sha256":b["oracle_source_sha256"]}
        raw=g.canonical(declaration)
        artifacts["change"]={"path":"unit/change-marker","raw_bytes":raw}
        b["change_sha256"]=b["oracle_source_sha256"]
        self.assertNotEqual(b["change_sha256"],hashlib.sha256(raw).hexdigest())
        adapter_refuses(self,"bad_hash",b,artifacts)
        declaration["task_id"]="foreign-unit-task"
        raw=g.canonical(declaration);artifacts["change"]["raw_bytes"]=raw
        b["change_sha256"]=hashlib.sha256(raw).hexdigest()
        adapter_refuses(self,"bad_hash",b,artifacts)

    def test_batch_pending_refuses_claiming_incomplete_packets_are_adapted(self):
        """Catch batch aggregation promoting unadapted declarations to transport-ready state."""
        self.assertEqual(a.combine_tasks([{"status":"pending"}]),
                         {"status":"pending","reason":"complete adapted task packets required"})
        for value in ([],(),None):
            with self.assertRaises(g.AdmissionError) as caught:a.combine_tasks(value)
            self.assertEqual((caught.exception.code,caught.exception.stage),("bad_value","transport_index"))
