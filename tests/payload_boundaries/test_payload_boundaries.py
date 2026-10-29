"""Synthetic builder policy vectors; no model/actual-evidence expectations.

Instances exist only when separately authorized tests run. No candidate/guest
source is imported, compiled, evaluated or executed. No paid wire/ledger/backend.
"""
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus" / "fixtures" / "payload"


def api():
    try:
        from cobolmap import contracts as c
        from cobolmap import providers as p
    except ModuleNotFoundError as exc:
        raise unittest.SkipTest("PENDING local source/Pydantic prerequisites: " + str(exc)) from exc
    return SimpleNamespace(c=c, p=p)


def builders():
    try:
        module = importlib.import_module("evaluation.prompts")
    except ModuleNotFoundError as exc:
        raise unittest.SkipTest("PENDING canonical DL4 fixture source integration") from exc
    names = ("FixturePrompt", "build_fixture_initial_prompt", "build_fixture_counterexample_prompt", "build_fixture_count_prompt")
    if any(not hasattr(module, name) for name in names):
        raise unittest.SkipTest("PENDING exact canonical fixture API")
    return module


def identity(letter):
    # Explicit invented unit call identifier, NOT a real call/event or pin.
    return "c_" + letter * 62


def context(a, filename="comment-hostile.cbl", *, arm="C", previous=None):
    raw = (FIXTURES / filename).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    original = a.c.ArtifactRef(path="corpus/fixtures/payload/" + filename, sha256=digest, byte_length=len(raw))
    task = a.c.TaskBinding(task_id="synthetic_builder_task", program_id="synthetic_builder_program",
                         family_id="synthetic_builder_family", split="dev", panel="unchanged",
                         original=original, oracle_source=original)
    behavior = None if arm == "B" else a.c.BehaviorMap(source_sha256=digest, filename=original.path)
    ctx = a.c.FeedbackContext(source_sha256=digest, source_text=raw.decode("ascii"),
                 shim_api="SYNTHETIC BUILDER SHIM DATA ONLY", request_text="",
                 behavior_map=behavior, previous_candidate=previous)
    return task, ctx


def case_hash(record):
    preimage = b"M10-CASE-v1\0" + b"\1" + (1).to_bytes(4, "big") + len(record).to_bytes(4, "big") + record
    return hashlib.sha256(preimage).hexdigest()


def loop_hashes():
    # Future synthetic unit scope only, never an authentic seal/custody canary.
    return frozenset(case_hash(("BUILDER%02d" % n).encode("ascii")) for n in range(32))


def repair(a, *, arm="D", index=0):
    task, _ = context(a)
    code = "# SYNTHETIC BUILDER PRIOR TEXT; NEVER EXECUTED\n"
    previous = a.c.CandidateAttempt(task_id=task.task_id, arm="C", attempt=0, code=code,
        candidate_sha256=hashlib.sha256(code.encode()).hexdigest(), call_id=identity("c"),
        evidence_mode="fixture", status="generated")
    task, ctx = context(a, arm=arm, previous=previous)
    if arm == "R":
        return task, a.c.CountOnlyFeedback(task_id=task.task_id, attempt=1, context=ctx, failed_cases=1, loop_cases=32)
    record = ("BUILDER%02d" % index).encode("ascii")
    case = a.c.CaseBundle(input_present=True, records=(record,), case_sha256=case_hash(record))
    left = a.c.OrdinaryObservation(output=a.c.ObservedFile(present=True, data=b"SYNTHETIC_LEFT\n"), stdout=b"", stderr=b"", return_code=0)
    right = a.c.OrdinaryObservation(output=a.c.ObservedFile(present=True, data=b"SYNTHETIC_RIGHT\n"), stdout=b"", stderr=b"", return_code=0)
    witness = a.c.LoopWitness(case_id="synthetic_builder_case", case=case, oracle=left, candidate=right, classification="unknown")
    return task, a.c.CounterexampleFeedback(task_id=task.task_id, attempt=1, context=ctx, witness=witness)


def fixture_messages(a, packet, task):
    b = builders()
    args = dict(task=task, loop_hashes=loop_hashes())
    if packet.arm in ("B", "C"):
        return b.build_fixture_initial_prompt(packet, **args)
    args.update(call_id=identity("d" if packet.arm == "D" else "e"), shared_c_call_id=identity("c"), expected_previous_call_id=identity("c"))
    fn = b.build_fixture_counterexample_prompt if packet.arm == "D" else b.build_fixture_count_prompt
    return fn(packet, **args)


def neutral_request(a, filename="comment-hostile.cbl"):
    """Policy-unit DTO, not a production template or actual prompt/wire."""
    task, ctx = context(a, filename, arm="B")
    def part(kind, text):
        return a.p.ContextPart(task_id=task.task_id, kind=kind, text=text, sha256=hashlib.sha256(text.encode()).hexdigest())
    messages = (a.p.Message(role="system", parts=(part("instruction", "SYNTHETIC BUILDER UNIT DATA"),)),
                a.p.Message(role="user", parts=(part("original_source", ctx.source_text), part("shim_api", ctx.shim_api), part("structured_change", ""))))
    return a.p.ProviderRequest(call_id=identity("b"), task_id=task.task_id, arm="B", attempt=0, messages=messages)


def policy(a, request, *, fingerprints=(), limit=60000):
    parts = tuple(p for m in request.messages for p in m.parts)
    source = next(p for p in parts if p.kind == "original_source")
    return a.p.LeakagePolicy(task_id=request.task_id, original_source_sha256=source.sha256,
         loop_hashes=loop_hashes(), allowed_context_hashes=frozenset(p.sha256 for p in parts),
         prohibited_fingerprints=fingerprints, max_payload_bytes=limit)


class PairSourceTests(unittest.TestCase):
    def test_pairs_change_only_declared_data_region(self):
        """Catches attack fixtures accidentally changing executable COBOL body."""
        for pair in ("comment", "literal"):
            benign = (FIXTURES / (pair + "-benign.cbl")).read_text(encoding="ascii")
            hostile = (FIXTURES / (pair + "-hostile.cbl")).read_text(encoding="ascii")
            def without_region(text):
                return "\n".join(line for line in text.splitlines()
                    if not ("*>" in line if pair == "comment" else line.strip().startswith("VALUE ")))
            self.assertNotEqual(benign, hostile)
            self.assertEqual(without_region(benign), without_region(hostile))


class NativeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.a = api()

    def test_allowed_source_preserved_but_not_system_instruction(self):
        """Catches instruction interpolation or removal of hostile source data."""
        for filename in ("comment-benign.cbl", "comment-hostile.cbl", "literal-benign.cbl", "literal-hostile.cbl"):
            for arm in ("B", "C"):
                task, ctx = context(self.a, filename, arm=arm)
                packet = self.a.c.InitialFeedback(task_id=task.task_id, arm=arm, context=ctx)
                wrapper = fixture_messages(self.a, packet, task)
                source = [p for m in wrapper.messages for p in m.parts if p.kind == "original_source"]
                self.assertEqual([p.text for p in source], [(FIXTURES / filename).read_bytes().decode("ascii")])
                decoded = json.loads(wrapper.messages[1].content())
                self.assertEqual(next(p["text"] for p in decoded if p["kind"] == "original_source"), ctx.source_text)
                system = wrapper.messages[0].content()
                self.assertNotIn("SYNTHETIC_BUILDER_COMMENT_MARKER", system)
                self.assertNotIn("SYNTHETIC_BUILDER_LITERAL_MARKER", system)
                self.assertIs(wrapper.admitted, False)
                self.assertIs(wrapper.transport_authorized, False)

    def test_synthetic_marker_policy_rejection_has_allowed_source_control(self):
        """Catches bypassed canary scans; not a real canary or robustness result."""
        request = neutral_request(self.a)
        allowed = self.a.p.validate_payload(request, policy(self.a, request), require_actual_context=False)
        denied = self.a.p.validate_payload(request, policy(self.a, request, fingerprints=("SYNTHETIC_BUILDER_COMMENT_MARKER",)), require_actual_context=False)
        self.assertEqual(allowed.status, "checked")
        self.assertEqual(denied.status, "refused")
        self.assertIn("prohibited_payload_fingerprint", denied.issues)
        self.assertIs(allowed.transport_authorized, False)

    def test_foreign_task_context_refuses_even_allowlisted_bytes(self):
        """Catches trusting a digest allowlist without the task identity join."""
        request = neutral_request(self.a)
        user = request.messages[1]
        foreign = user.parts[0].model_copy(update={"task_id": "synthetic_foreign_task"})
        altered = request.model_copy(update={"messages": (request.messages[0], user.model_copy(update={"parts": (foreign,) + user.parts[1:]}))})
        result = self.a.p.validate_payload(altered, policy(self.a, altered), require_actual_context=False)
        self.assertEqual(result.status, "refused")
        self.assertIn("other_task_context", result.issues)

    def test_forbidden_context_channels_remain_closed(self):
        """Catches a schema widening that accepts verification/oracle/trace/proofs."""
        text = "SYNTHETIC BUILDER FORBIDDEN DATA"
        for kind in ("verification", "changed_oracle", "trace", "derivative_lineage", "execution_receipt"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.a.p.ContextPart(task_id="synthetic_builder_task", kind=kind, text=text, sha256=hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(neutral_request(self.a).messages[1].parts[0].kind, "original_source")

    def test_fixture_structural_check_does_not_satisfy_actual_gates(self):
        """Catches promoting no-model fixture DTOs into actual admitted requests."""
        request = neutral_request(self.a)
        result = self.a.p.validate_payload(request, policy(self.a, request), require_actual_context=True)
        self.assertEqual(result.status, "pending")
        self.assertIn("model_pin_missing", result.issues)
        self.assertIn("exact_token_count_missing", result.issues)
        self.assertIs(result.transport_authorized, False)
        with self.assertRaises(ValueError):
            self.a.p.ProviderResult(call_id=request.call_id, request_sha256=request.request_sha256(), provenance="fixture", sent=True, status="success", text="SYNTHETIC UNIT TEXT")

    def test_byte_cap_refuses_instead_of_truncating_source(self):
        """Catches shrinking a payload to silently discard hostile data or context."""
        request = neutral_request(self.a)
        result = self.a.p.validate_payload(request, policy(self.a, request, limit=64), require_actual_context=False)
        self.assertEqual(result.status, "refused")
        self.assertIn("payload_byte_limit_never_truncate", result.issues)
        self.assertIn("SYNTHETIC_BUILDER_COMMENT_MARKER", request.messages[1].parts[0].text)

    def test_phase_and_counter_forgery_refuses(self):
        """Catches initial/repair arm phase and aggregate-counter drift."""
        request = neutral_request(self.a)
        with self.assertRaises(ValueError):
            self.a.p.ProviderRequest.model_validate({**request.model_dump(), "attempt": 1})
        task, packet = repair(self.a, arm="R")
        with self.assertRaises(ValueError):
            self.a.c.CountOnlyFeedback(task_id=task.task_id, attempt=1, context=packet.context, failed_cases=33, loop_cases=32)
        with self.assertRaises(ValueError):
            self.a.c.CountOnlyFeedback(task_id=task.task_id, arm="D", attempt=1, context=packet.context, failed_cases=1, loop_cases=32)
        self.assertEqual(packet.failed_cases, 1)

    def test_original32_witness_positive_and_derivative_negative(self):
        """Catches treating a new case hash as a sealed original member."""
        task, packet = repair(self.a)
        wrapper = fixture_messages(self.a, packet, task)
        self.assertEqual(sum(p.kind == "loop_witness" for m in wrapper.messages for p in m.parts), 1)
        task, outside = repair(self.a, index=32)
        with self.assertRaises(ValueError):
            fixture_messages(self.a, outside, task)
        b = builders()
        with self.assertRaises(TypeError):
            b.build_fixture_counterexample_prompt(packet, task=task, call_id=identity("d"), shared_c_call_id=identity("c"), expected_previous_call_id=identity("c"), loop_hashes=loop_hashes(), derivative={})

    def test_forged_previous_call_and_attempt_refuse(self):
        """Catches repairing a different candidate/call or skipping a repair phase."""
        task, packet = repair(self.a)
        b = builders()
        with self.assertRaises(ValueError):
            b.build_fixture_counterexample_prompt(packet, task=task, call_id=identity("d"), shared_c_call_id=identity("c"), expected_previous_call_id=identity("f"), loop_hashes=loop_hashes())
        altered = packet.model_copy(update={"attempt": 2})
        with self.assertRaises(ValueError):
            fixture_messages(self.a, altered, task)
        self.assertEqual(fixture_messages(self.a, packet, task).evidence_mode, "fixture")

    def test_R_has_counts_without_witness_or_answers(self):
        """Catches leaking D's witness/ordinary bytes through R's feedback path."""
        task, packet = repair(self.a, arm="R")
        wrapper = fixture_messages(self.a, packet, task)
        parts = [p for m in wrapper.messages for p in m.parts]
        self.assertEqual(sum(p.kind == "counts" for p in parts), 1)
        self.assertFalse(any(p.kind == "loop_witness" for p in parts))
        self.assertIn("1 of 32", next(p.text for p in parts if p.kind == "counts"))
        self.assertNotIn(b"SYNTHETIC_LEFT".hex(), "".join(m.content() for m in wrapper.messages))
        with self.assertRaises(ValueError):
            self.a.c.CountOnlyFeedback(task_id=task.task_id, attempt=1, context=packet.context, failed_cases=1, loop_cases=32, witness={})

    def test_D_multiple_or_intermediate_witnesses_refuse(self):
        """Catches whole-lineage projection or accepting several witnesses in D."""
        task, packet = repair(self.a)
        wrapper = fixture_messages(self.a, packet, task)
        witness = next(p for m in wrapper.messages for p in m.parts if p.kind == "loop_witness")
        body = json.loads(witness.text)
        self.assertIn("oracle", body)
        self.assertNotIn("lineage", body)
        self.assertNotIn("context", body)
        object.__setattr__(packet, "lineage", ("SYNTHETIC_INTERMEDIATE_ONLY",))
        with self.assertRaises(ValueError):
            fixture_messages(self.a, packet, task)
        user = wrapper.messages[1]
        request = self.a.p.ProviderRequest(call_id=identity("d"), task_id=task.task_id, arm="D", attempt=1, shared_c_call_id=identity("c"), messages=(wrapper.messages[0], user.model_copy(update={"parts": user.parts + (witness,)})))
        result = self.a.p.validate_payload(request, policy(self.a, request), require_actual_context=False)
        self.assertEqual(result.status, "refused")
        self.assertIn("at_most_one_loop_witness", result.issues)

    def test_fixture_builder_has_no_admitted_keyword_escape(self):
        """Catches conflating explicit fixture projection with actual admission."""
        task, ctx = context(self.a, arm="B")
        packet = self.a.c.InitialFeedback(task_id=task.task_id, arm="B", context=ctx)
        b = builders()
        with self.assertRaises(TypeError):
            b.build_fixture_initial_prompt(packet, task=task, loop_hashes=loop_hashes(), admitted=True)
        self.assertIs(fixture_messages(self.a, packet, task).admitted, False)

    def test_mock_missing_mismatch_and_malformed_never_advance(self):
        """Catches fixture retries/false success or bills for unusable script input."""
        request = neutral_request(self.a)
        self.assertEqual(self.a.p.validate_payload(request, policy(self.a, request), require_actual_context=False).status, "checked")
        mocks = [self.a.p.ScriptedMock(entries=()),
            self.a.p.ScriptedMock(entries=(self.a.p.ScriptEntry(call_id=identity("f"), request_sha256=request.request_sha256(), format="openai_chat", raw_response_json=b""),)),
            self.a.p.ScriptedMock(entries=(self.a.p.ScriptEntry(call_id=request.call_id, request_sha256=request.request_sha256(), format="openai_chat", raw_response_json=b"NOT_JSON_SYNTHETIC_BUILDER"),))]
        for mock, fault in zip(mocks, ("missing_script", "script_mismatch", "malformed_response")):
            result, following = mock.respond(request)
            self.assertEqual(following.position, mock.position)
            self.assertIs(result.sent, False)
            self.assertEqual(result.provenance, "fixture")
            self.assertIsNone(result.cost_usd)
            self.assertNotEqual(result.status, "success")
            self.assertEqual(result.fault.code, fault)
