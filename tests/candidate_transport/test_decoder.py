"""Builder synthetic protocol vectors ONLY. No guest/candidate/backend execution.

Hashes and resource integers here describe synthetic test data, never actual
observations, receipts, installed SDK artifacts or measured containment.
"""
import copy
import hashlib
import json
import unittest

from cobolmap.oracle.candidate_transport import (
    CONTROL_CAP, NATIVE_CAP, CandidateSidecar, CandidateTransportExpectation,
    StagedTransportPin, capture_control, capture_physical, decode_candidate_transport,
)
from cobolmap.oracle.pins import SDK_PATHS


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


class DecoderVectors(unittest.TestCase):
    def setUp(self):
        self.expected = CandidateTransportExpectation(
            plan_sha256=digest(b"builder synthetic plan"),
            case_sha256=digest(b"builder synthetic case"),
            candidate_sha256=digest(b"builder synthetic candidate commitment"),
            staged=tuple(StagedTransportPin(path=name, sha256=digest(name.encode()),
                         byte_length=len(name)) for name in sorted(SDK_PATHS)),
            allowed_return_codes=(0, 3))
        self.frame = {
            "abi": "m10-run-case-v1", "status": "returned", "fault": None,
            "case_sha256": self.expected.case_sha256, "candidate_sha256": self.expected.candidate_sha256,
            "staged": {pin.path: {"sha256": pin.sha256, "byte_length": pin.byte_length} for pin in self.expected.staged},
            "ordinary": {"output": {"present": False, "data": None}, "stdout": "", "stderr": "", "return_code": 0},
            "semantics": "construction_hypothesis", "runtime_verified": False,
        }

    def sidecar(self, raw=None, **updates):
        fields = dict(plan_sha256=self.expected.plan_sha256, backend_id="builder_backend",
            execution_id="builder_vector", control=capture_control(wire(self.frame) if raw is None else raw),
            physical_stdout=capture_physical(b""), physical_stderr=capture_physical(b""),
            process_return_code=0, cpu_microseconds=1, wall_microseconds=2, backend_outcome="completed")
        fields.update(updates)
        return CandidateSidecar(**fields)

    def decode(self, raw=None, **updates):
        return decode_candidate_transport(self.sidecar(raw, **updates), expected=self.expected)

    def test_logical_return_is_separate_from_process_exit_and_hashes(self):
        self.frame["ordinary"]["return_code"] = 3
        raw = wire(self.frame)
        result = self.decode(raw)
        self.assertEqual(result.status, "decoded")
        self.assertEqual(result.logical.return_code, 3)
        self.assertEqual(result.sidecar.process_return_code, 0)
        self.assertEqual(result.sidecar.control.data, raw)
        self.assertEqual(result.retained_control_sha256, digest(raw))
        self.assertNotEqual(result.retained_control_sha256, result.decoded_logical_sha256)
        self.assertNotEqual(result.retained_control_sha256, result.sidecar_sha256)
        self.assertEqual(result.evidence_mode, "not_run")
        self.assertEqual(result.conformance_gap, "candidate_control_capture_policy_unresolved")

    def test_absent_and_present_empty_remain_distinct(self):
        absent = self.decode()
        self.frame["ordinary"]["output"] = {"present": True, "data": ""}
        empty = self.decode()
        self.assertFalse(absent.logical.output_present)
        self.assertIsNone(absent.logical.output_bytes)
        self.assertTrue(empty.logical.output_present)
        self.assertEqual(empty.logical.output_bytes, b"")
        self.assertNotEqual(absent.decoded_logical_sha256, empty.decoded_logical_sha256)

    def test_candidate_and_adapter_faults_are_not_empty_success(self):
        for status, fault, code in (("candidate_fault", "runtime_fault", 2), ("adapter_fault", "case_protocol", 3)):
            with self.subTest(status=status):
                frame = copy.deepcopy(self.frame)
                frame.update(status=status, fault=fault, ordinary=None)
                if status == "adapter_fault":
                    frame.update(case_sha256=None, candidate_sha256=None, staged={})
                result = self.decode(wire(frame), process_return_code=code)
                self.assertEqual(result.status, "fault")
                self.assertEqual(result.guest_fault, fault)
                self.assertIsNone(result.logical)

    def test_fault_frame_cannot_smuggle_ordinary(self):
        self.frame.update(status="candidate_fault", fault="candidate_exception")
        result = self.decode(process_return_code=2)
        self.assertIn("fault_has_ordinary", result.issues)
        self.assertIsNone(result.logical)

    def test_candidate_fault_requires_completed_staging_not_null_setup_pins(self):
        self.frame.update(status="candidate_fault", fault="runtime_fault", ordinary=None,
                          case_sha256=None, candidate_sha256=None, staged={})
        result = self.decode(process_return_code=2)
        self.assertEqual(result.status, "rejected")
        self.assertIn("guest_scope_pin", result.issues)

    def test_fault_frame_retains_physical_output_without_calling_it_ordinary(self):
        self.frame.update(status="candidate_fault", fault="candidate_exception", ordinary=None)
        result = self.decode(process_return_code=2, physical_stderr=capture_physical(b"fault bytes"))
        self.assertEqual(result.status, "fault")
        self.assertIsNone(result.logical)
        self.assertEqual(result.sidecar.physical_stderr.data, b"fault bytes")

    def test_process_and_declared_return_mismatches_keep_logical_untrusted(self):
        self.frame["ordinary"]["return_code"] = 4
        result = self.decode(process_return_code=2)
        self.assertEqual(result.status, "rejected")
        self.assertIn("physical_process_exit_mismatch", result.issues)
        self.assertIn("logical_return_undeclared", result.issues)
        self.assertEqual(result.logical.return_code, 4)

    def test_physical_channels_are_never_merged_or_hidden(self):
        self.frame["ordinary"]["stdout"] = b"logical".hex()
        result = self.decode(physical_stdout=capture_physical(b"physical out"),
                             physical_stderr=capture_physical(b"physical err"))
        self.assertIn("unexpected_physical_channels", result.issues)
        self.assertEqual(result.sidecar.physical_stdout.data, b"physical out")
        self.assertEqual(result.sidecar.physical_stderr.data, b"physical err")
        self.assertEqual(result.logical.stdout, b"logical")

    def test_missing_frame_keeps_backend_timeout_signal_and_resource_facts(self):
        result = self.decode(b"", process_return_code=-9, signal=9, backend_outcome="timeout",
                             flags=("cpu", "signal"), cpu_microseconds=5000001, wall_microseconds=10000001)
        self.assertEqual(result.status, "rejected")
        self.assertIn("missing_control_frame", result.issues)
        self.assertIn("backend_fault_facts", result.issues)
        self.assertIn("backend_time_budget_exceeded", result.issues)
        self.assertEqual(result.sidecar.flags, ("cpu", "signal"))
        self.assertEqual(result.sidecar.signal, 9)
        self.assertIsNone(result.logical)

    def test_favorable_frame_cannot_override_backend_faults(self):
        result = self.decode(backend_outcome="forbidden", flags=("forbidden",))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.sidecar.backend_outcome, "forbidden")
        self.assertEqual(result.guest_status, "returned")

    def test_missing_resource_facts_do_not_become_zero_measurement(self):
        result = self.decode(cpu_microseconds=None, wall_microseconds=None)
        self.assertIn("resource_measurement_missing", result.issues)
        self.assertIsNone(result.sidecar.cpu_microseconds)

    def test_partial_and_oversize_capture_retains_prefix_count(self):
        partial = self.decode(control=capture_control(wire(self.frame), complete=False))
        self.assertIn("control_capture_incomplete", partial.issues)
        raw = b"x" * (CONTROL_CAP + 1)
        oversized = self.decode(raw)
        self.assertEqual(len(oversized.sidecar.control.data), CONTROL_CAP)
        self.assertEqual(oversized.sidecar.control.observed_bytes, len(raw))
        self.assertIn("control_capture_truncated", oversized.issues)
        self.assertEqual(oversized.retained_control_sha256, digest(raw[:CONTROL_CAP]))

    def test_physical_oversize_retains_prefix_and_counts(self):
        result = self.decode(physical_stdout=capture_physical(b"p" * (NATIVE_CAP + 1)))
        self.assertEqual(len(result.sidecar.physical_stdout.data), NATIVE_CAP)
        self.assertEqual(result.sidecar.physical_stdout.observed_bytes, NATIVE_CAP + 1)
        self.assertIn("stdout_capture_truncated", result.issues)
        self.assertIn("native_physical_output_budget_exceeded", result.issues)

    def test_wire_and_decoded_budgets_are_distinct_and_native_cap_unchanged(self):
        self.frame["ordinary"]["stdout"] = (b"x" * (NATIVE_CAP // 2)).hex()
        result = self.decode()
        self.assertLess(len(result.sidecar.control.data), CONTROL_CAP)
        self.assertLess(len(result.logical.stdout), NATIVE_CAP)
        self.assertIn("native_physical_output_budget_exceeded", result.issues)
        self.assertEqual(result.status, "rejected")

    def test_decoded_aggregate_cap_is_independent_of_frame_retention(self):
        self.frame["ordinary"].update(stdout=(b"a" * NATIVE_CAP).hex(), stderr="62")
        result = self.decode()
        self.assertLess(len(result.sidecar.control.data), CONTROL_CAP)
        self.assertIn("logical_ordinary_cap", result.issues)
        self.assertIsNone(result.logical)

    def test_noncanonical_duplicate_unknown_and_trailing_json_refuse(self):
        raw = wire(self.frame)
        vectors = [raw + b"\n", raw + raw, b'{"abi":"x","abi":"x"}', b"\xef\xbb\xbf" + raw,
                   b"[[[[[0]]]]]", b"{", b'{"n":NaN}', b'{"n":1.5}', b'{"n":123456789012345678901}']
        unknown = dict(self.frame, flags=[])
        vectors.append(wire(unknown))
        for value in vectors:
            with self.subTest(raw_prefix=value[:30]):
                result = self.decode(value)
                self.assertEqual(result.status, "rejected")
                self.assertEqual(result.sidecar.control.data, value)

    def test_pin_scope_mismatches_refuse_without_rewriting_raw(self):
        for key in ("case_sha256", "candidate_sha256"):
            frame = copy.deepcopy(self.frame)
            frame[key] = digest(b"foreign builder scope")
            result = self.decode(wire(frame))
            self.assertIn("guest_scope_pin", result.issues)
        result = self.decode(plan_sha256=digest(b"foreign plan"))
        self.assertIn("sidecar_plan_pin", result.issues)
        frame = copy.deepcopy(self.frame)
        frame["staged"]["entry.py"]["sha256"] = digest(b"wrong entry")
        self.assertIn("staged_pin", self.decode(wire(frame)).issues)

    def test_exact_frame_types_presence_hex_and_closure(self):
        vectors = []
        for field, value in (("return_code", True), ("stdout", "AA"), ("stderr", "0")):
            frame = copy.deepcopy(self.frame)
            frame["ordinary"][field] = value
            vectors.append(frame)
        frame = copy.deepcopy(self.frame)
        frame["ordinary"]["output"]["data"] = ""
        vectors.append(frame)
        frame = copy.deepcopy(self.frame)
        frame["staged"]["entry.py"]["byte_length"] = True
        vectors.append(frame)
        frame = copy.deepcopy(self.frame)
        del frame["staged"]["entry.py"]
        vectors.append(frame)
        frame = copy.deepcopy(self.frame)
        frame["runtime_verified"] = 0
        vectors.append(frame)
        for value in vectors:
            self.assertEqual(self.decode(wire(value)).status, "rejected")

    def test_malformed_constructed_sidecar_and_subclass_refuse(self):
        valid = self.sidecar()
        invalid = valid.model_copy(update={"cpu_microseconds": -1})
        self.assertIn("transport_dto_invalid", decode_candidate_transport(invalid, expected=self.expected).issues)
        class ForeignSidecar(CandidateSidecar):
            pass
        foreign = ForeignSidecar(**valid.model_dump())
        self.assertIn("transport_dto_invalid", decode_candidate_transport(foreign, expected=self.expected).issues)
        with self.assertRaises(ValueError):
            self.sidecar(flags=("unrecognized",))


if __name__ == "__main__":
    unittest.main()
