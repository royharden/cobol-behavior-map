"""Synthetic negative diagnostics, never P2 authority or independent evidence."""

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid


ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = ROOT / "admission" / "gate.py"
SPEC = importlib.util.spec_from_file_location("builder_admission_gate", GATE_PATH)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
SCHEMAS = GATE_PATH.parent / "schemas"


def schema(name):
    return json.loads((SCHEMAS / (name + ".schema.json")).read_bytes())


class GateDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace = ROOT / ".agent-work" / "admission-gate-diagnostics" / uuid.uuid4().hex
        cls.namespace.mkdir(parents=True, exist_ok=False)
        cls.sequence = 0
        print("Retained builder diagnostic namespace:", cls.namespace)

    def retain(self, raw):
        type(self).sequence += 1
        path = self.namespace / (str(self.sequence) + ".json")
        with path.open("xb") as stream:
            stream.write(raw)
        return path.name

    def evaluate(self, record=b"{}", authority=None, digest=None, record_path=None,
                 authority_path=None):
        record_path = self.retain(record) if record_path is None else record_path
        if authority_path is None:
            authority_path = "missing-actual-authority.json" if authority is None else self.retain(authority)
        digest = hashlib.sha256(authority or b"").hexdigest() if digest is None else digest
        # Defense in depth: even a path-validation regression cannot read outside
        # this fresh owned namespace or native read-only schemas.
        original = Path.read_bytes
        reads = []

        def bounded_read(path):
            resolved = path.resolve()
            if not (resolved.is_relative_to(self.namespace) or resolved.is_relative_to(SCHEMAS)):
                raise AssertionError("diagnostic attempted external read: " + str(resolved))
            reads.append(str(resolved))
            return original(path)

        with patch.object(Path, "read_bytes", bounded_read):
            result = gate.evaluate(self.namespace, record_path, authority_path, digest)
        self.assertIn(result["status"], ("PENDING", "NO-GO"))
        self.assertEqual(result["recipe_bindings"], [])
        self.assertIn("caller must authenticate", result["claim"])
        self.retain(json.dumps({"result": result, "reads": reads}, sort_keys=True).encode())
        return result

    def issue(self, result, item, status, reason):
        matches = [entry for entry in result["issues"] if entry["item"] == item]
        self.assertEqual(len(matches), 1, result)
        self.assertEqual(matches[0]["status"], status)
        self.assertIn(reason, matches[0]["reason"])

    def test_missing_actual_authority_and_record_stay_pending(self):
        result = self.evaluate(record_path="missing-actual-record.json")
        self.assertEqual(result["status"], "PENDING")
        self.issue(result, "authority", "PENDING", "missing-actual-authority.json")
        self.issue(result, "record", "PENDING", "missing-actual-record.json")

    def test_empty_objects_do_not_appoint_roles_or_admit_p2(self):
        result = self.evaluate(authority=b"{}")
        self.assertEqual(result["status"], "PENDING")
        self.issue(result, "authority", "PENDING", "missing")
        self.issue(result, "record", "PENDING", "missing")

    def test_missing_authority_digest_refuses_before_authority_read(self):
        for digest in ("", "a" * 63, "A" * 64, "g" * 64):
            with self.subTest(digest=digest):
                result = self.evaluate(digest=digest)
                self.issue(result, "authority", "NO-GO", "externally approved digest required")

    def test_self_computed_digest_is_only_byte_binding_not_approval(self):
        result = self.evaluate(authority=b'{"gate_version":"m10-p2-v3"}')
        self.issue(result, "authority", "PENDING", "missing")
        self.assertEqual(result["status"], "PENDING")

    def test_raw_authority_hash_does_not_accept_canonical_substitute(self):
        raw = b'{ "gate_version" : "m10-p2-v3" }\n'
        digest = gate.canonical_sha256({"gate_version": "m10-p2-v3"})
        self.assertNotEqual(digest, hashlib.sha256(raw).hexdigest())
        result = self.evaluate(authority=raw, digest=digest)
        self.issue(result, "authority", "NO-GO", "authority digest mismatch")

    def test_duplicate_json_key_dominates_missing_authority(self):
        result = self.evaluate(record=b'{"gate_version":"m10-p2-v3","gate_version":"m10-p2-v3"}')
        self.assertEqual(result["status"], "NO-GO")
        self.issue(result, "record", "NO-GO", "duplicate JSON key: gate_version")
        self.issue(result, "authority", "PENDING", "missing-actual-authority")

    def test_top_level_unknown_key_is_not_masked_by_missing_fields(self):
        result = self.evaluate(record=b'{"pretend_seal":true}')
        self.issue(result, "record", "NO-GO", "record: unknown fields")

    def test_wrong_record_root_types_refuse_exact_type(self):
        for raw in (b"[]", b"null", b"true", b"1", b'"record"'):
            with self.subTest(raw=raw):
                self.issue(self.evaluate(record=raw), "record", "NO-GO", "record: wrong type")

    def test_invalid_json_encoding_and_bom_are_no_go(self):
        for raw, reason in ((b"\xef\xbb\xbf{}", "UTF-8 BOM forbidden"),
                            (b"\xff", "utf-8"), (b"{", "property name")):
            with self.subTest(raw=raw):
                self.issue(self.evaluate(record=raw), "record", "NO-GO", reason)

    def test_authority_digest_is_checked_before_its_json_shape(self):
        result = self.evaluate(authority=b"not JSON", digest="0" * 64)
        self.issue(result, "authority", "NO-GO", "authority digest mismatch")

    def test_unsafe_record_paths_refuse_without_external_file_reads(self):
        for path in ("../never-read-builder-marker", "/never-read-builder-marker", "C:/never-read-builder-marker",
                     "a\\never-read-builder-marker", "a//b", "./marker", "a/../marker", "a/", "a\nmarker"):
            with self.subTest(path=path):
                self.issue(self.evaluate(record_path=path), "record", "NO-GO", "unsafe evidence path")

    def test_unsafe_authority_path_refuses_with_syntactic_digest(self):
        result = self.evaluate(authority_path="../never-read-builder-authority")
        self.issue(result, "authority", "NO-GO", "unsafe evidence path")

    def test_strict_json_nested_duplicates_and_noninteger_numbers(self):
        for raw, reason in ((b'{"x":{"y":1,"y":2}}', "duplicate JSON key: y"),
                            (b"NaN", "nonfinite number"), (b"Infinity", "nonfinite number"),
                            (b"1.0", "nonfinite number"), (b"1e2", "nonfinite number"),
                            (b"123456789012345678901", "integer exceeds 20 digits")):
            with self.subTest(raw=raw), self.assertRaisesRegex(gate.Invalid, reason):
                gate.strict_json(raw)
        self.assertEqual(gate.strict_json(b"-12345678901234567890"), -12345678901234567890)

    def test_canonical_commitments_ignore_spacing_but_not_strings_or_arrays(self):
        left = gate.strict_json(b'{ "b": [1,2], "a": "x" }\n')
        right = gate.strict_json(b'{"a":"x","b":[1,2]}')
        expected = hashlib.sha256(b'{"a":"x","b":[1,2]}').hexdigest()
        self.assertEqual(gate.canonical_sha256(left), expected)
        self.assertEqual(gate.canonical_sha256(right), expected)
        for changed in ({"a": "x ", "b": [1, 2]}, {"a": "x", "b": [2, 1]}):
            self.assertNotEqual(gate.canonical_sha256(changed), expected)
        self.assertEqual(gate.canonical_sha256({"x": "é"}), hashlib.sha256(b'{"x":"\\u00e9"}').hexdigest())

    def test_schema_exact_integer_rejects_bool_float_and_bounded_counts(self):
        target = schema("receipt")["properties"]["executed"]
        gate.shape(0, target, "receipt.executed")
        for value, reason in ((True, "wrong type"), (1.0, "wrong type"), (-1, "below minimum")):
            with self.subTest(value=value), self.assertRaisesRegex(gate.Invalid, reason):
                gate.shape(value, target, "receipt.executed")

    def test_raw_reference_schema_missing_extra_and_uppercase_hash_refuse(self):
        target = schema("paired-recipe-index")["properties"]["recipes"]["properties"]["loop"]
        valid = {"path": "missing-actual-recipe.json", "sha256": "a" * 64}
        gate.shape(valid, target, "ref")
        with self.assertRaisesRegex(gate.Pending, "ref: missing"):
            gate.shape({"path": valid["path"]}, target, "ref")
        with self.assertRaisesRegex(gate.Invalid, "ref: unknown fields"):
            gate.shape(dict(valid, canonical_sha256="a" * 64), target, "ref")
        with self.assertRaisesRegex(gate.Invalid, "ref.sha256: pattern"):
            gate.shape(dict(valid, sha256="A" * 64), target, "ref")

    def test_recipe_closed_partition_counter_and_target_schema(self):
        properties = schema("partition-recipe")["properties"]
        probes = (("partition", "dev", "unknown value"), ("collision_counter", 1, "wrong constant"),
                  ("collision_counter", False, "wrong type"), ("manifest_version", True, "wrong type"))
        for key, value, reason in probes:
            with self.subTest(key=key, value=value), self.assertRaisesRegex(gate.Invalid, reason):
                gate.shape(value, properties[key], key)
        fill = properties["fill"]["properties"]
        for value in (0, 31, 33, 127, 129):
            with self.subTest(value=value), self.assertRaisesRegex(gate.Invalid, "unknown value"):
                gate.shape(value, fill["target_count"], "target")
        for value in (32, 128):
            gate.shape(value, fill["target_count"], "target")

    def test_seed_length_and_record_bounds_without_case_generation(self):
        properties = schema("partition-recipe")["properties"]
        seed = properties["fill"]["properties"]["seed_material"]
        for size, reason in ((4, "too few items"), (6, "too many items")):
            with self.subTest(size=size), self.assertRaisesRegex(gate.Invalid, reason):
                gate.shape(["builder-unit"] * size, seed, "seed")
        with self.assertRaisesRegex(gate.Invalid, "too many items"):
            gate.shape([{}] * 65, properties["records"], "records")
        # Typed additional properties are permitted only as row values here.
        gate.shape([{"UNIT": ""}], properties["records"], "records")
        with self.assertRaisesRegex(gate.Invalid, "wrong type"):
            gate.shape([{"UNIT": 1}], properties["records"], "records")

    def test_partition_count_schemas_reject_absence_without_real_partitions(self):
        task = schema("go-record")["properties"]["tasks"]["items"]["properties"]
        for key in ("loop_hashes", "verification_hashes"):
            with self.subTest(key=key), self.assertRaisesRegex(gate.Invalid, "too few items"):
                gate.shape([], task[key], key)

    def test_unappointed_role_and_harness_strings_refuse_schema(self):
        actor = schema("authority")["properties"]["actors"]["items"]["properties"]
        for key, value in (("role", "standin"), ("harness", "independent-builder-label")):
            with self.subTest(key=key), self.assertRaisesRegex(gate.Invalid, "unknown value"):
                gate.shape(value, actor[key], key)
        with self.assertRaisesRegex(gate.Invalid, "too few items"):
            gate.shape([], schema("authority")["properties"]["actors"], "actors")

    def test_receipt_probe_and_review_fields_have_closed_types_not_authenticity(self):
        props = schema("receipt")["properties"]
        for key in ("admission_probes", "shim_probes", "failed", "skipped"):
            for value, reason in ((-1, "below minimum"), (True, "wrong type")):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(gate.Invalid, reason):
                    gate.shape(value, props[key], key)
        for key, value in (("mode", "reviewed"), ("result", "GO")):
            with self.subTest(key=key), self.assertRaisesRegex(gate.Invalid, "unknown value"):
                gate.shape(value, props[key], key)
        with self.assertRaisesRegex(gate.Invalid, "too few items"):
            gate.shape([], props["observations"], "observations")

    def test_pending_check_and_actual_receipt_mode_are_distinct_schema_domains(self):
        check = schema("go-record")["properties"]["checks"]["items"]["properties"]
        gate.shape("pending", check["result"], "check.result")
        with self.assertRaisesRegex(gate.Invalid, "unknown value"):
            gate.shape("pending", schema("receipt")["properties"]["result"], "receipt.result")
        # Static/fixture schema membership is NOT successful actual receipt admission.
        for mode in ("static", "fixture"):
            gate.shape(mode, schema("receipt")["properties"]["mode"], "receipt.mode")

    def test_timestamp_requires_timezone_and_does_not_sign_anything(self):
        gate.stamp("2026-10-27T00:00:00Z")
        with self.assertRaisesRegex(gate.Invalid, "timestamp requires timezone"):
            gate.stamp("2026-10-27T00:00:00")
        with self.assertRaises(ValueError):
            gate.stamp("not-a-timestamp")


if __name__ == "__main__":
    unittest.main()
