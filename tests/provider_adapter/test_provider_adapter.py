"""Pure synthetic adapter fixtures; no model answers, candidate code or transport."""
import hashlib
import json
import unittest

from cobolmap.providers import ContextPart, Message, ProviderRequest, LeakagePolicy
from cobolmap.providers.adapters import PreparedPayload, parse_response, prepare_payload


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def request(*, call_letter="a"):
    task = "synthetic_adapter_task"
    def part(kind, text):
        return ContextPart(task_id=task, kind=kind, text=text, sha256=sha(text.encode("utf-8")))
    messages = (Message(role="system", parts=(part("instruction", "SYNTHETIC_BUILDER_INSTRUCTION_DATA"),)),
                Message(role="user", parts=(part("original_source", "SYNTHETIC_BUILDER_SOURCE_DATA"),
                     part("shim_api", "SYNTHETIC_BUILDER_SHIM_DATA"), part("structured_change", ""))))
    return ProviderRequest(call_id="c_" + call_letter * 62, task_id=task, arm="B", attempt=0,
                           messages=messages)  # model/run/price/auth/token slots stay None.


def policy(req, *, limit=60000, fingerprints=(), task=None):
    parts = tuple(p for m in req.messages for p in m.parts)
    original = next(p for p in parts if p.kind == "original_source")
    return LeakagePolicy(task_id=task or req.task_id, original_source_sha256=original.sha256,
         allowed_context_hashes=frozenset(p.sha256 for p in parts), max_payload_bytes=limit,
         prohibited_fingerprints=fingerprints)


def compact(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def openai(*, usage=None):
    value = {"choices": [{"message": {"role": "assistant", "content": "SYNTHETIC_BUILDER_NONCODE_TEXT"}, "finish_reason": "stop"}]}
    if usage is not None: value["usage"] = usage
    return value


def anthropic(*, usage=None):
    value = {"type": "message", "role": "assistant", "content": [{"type": "text", "text": "SYNTHETIC_BUILDER_NONCODE_TEXT"}], "stop_reason": "end_turn"}
    if usage is not None: value["usage"] = usage
    return value


def fixture(req, raw, format="openai_chat"):
    # Only this explicit provenance/sent pair is allowed by the grant.
    return parse_response(req, raw, format=format, provenance="fixture", sent=False)


class PureAdapterDiagnostics(unittest.TestCase):
    def assert_fixture(self, result, req, raw):
        self.assertEqual(result.provenance, "fixture")
        self.assertIs(result.sent, False)
        self.assertIsNone(result.model_id)
        self.assertIsNone(result.cost_usd)
        self.assertEqual(result.call_id, req.call_id)
        self.assertEqual(result.request_sha256, req.request_sha256())
        self.assertEqual(result.raw_response_sha256, sha(raw))
        if result.fault is not None:
            self.assertIs(result.fault.retryable, False)

    def assert_malformed(self, raw, format="openai_chat"):
        req = request()
        result = fixture(req, raw, format)
        self.assert_fixture(result, req, raw)
        self.assertEqual(result.status, "refused")
        self.assertEqual(result.fault.code, "malformed_response")
        return result

    def test_complete_single_text_fixtures_have_no_model_cost_or_transport_fact(self):
        """Catches accidental actual provenance/sent/billing or failure of supported text."""
        req = request()
        for format, doc in (("openai_chat", openai()), ("anthropic_messages", anthropic())):
            raw = compact(doc)
            result = fixture(req, raw, format)
            self.assert_fixture(result, req, raw)
            self.assertEqual(result.status, "success")
            self.assertEqual(result.text, "SYNTHETIC_BUILDER_NONCODE_TEXT")
            self.assertTrue(all(value is None for value in result.usage.model_dump().values()))

    def test_raw_digest_binds_original_bytes_not_reserialized_json(self):
        """Catches canonicalizing the response before recording its raw artifact hash."""
        req = request()
        first = compact(openai())
        second = json.dumps(openai(), indent=2).encode("utf-8")
        left, right = fixture(req, first), fixture(req, second)
        self.assert_fixture(left, req, first)
        self.assert_fixture(right, req, second)
        self.assertEqual(left.text, right.text)
        self.assertNotEqual(left.raw_response_sha256, right.raw_response_sha256)

    def test_request_call_and_hash_binding_is_not_reused_from_prior_parse(self):
        """Catches stale request/call binding despite identical caller fixture bytes."""
        first, second = request(call_letter="a"), request(call_letter="b")
        raw = compact(openai())
        a, b = fixture(first, raw), fixture(second, raw)
        self.assert_fixture(a, first, raw)
        self.assert_fixture(b, second, raw)
        self.assertNotEqual(a.call_id, b.call_id)
        self.assertNotEqual(a.request_sha256, b.request_sha256)
        self.assertEqual(a.raw_response_sha256, b.raw_response_sha256)

    def test_choice_count_role_and_text_only_shape_are_required(self):
        """Catches accepting several candidates, tools, wrong roles or nontext blocks."""
        good = openai()
        invalid = [dict(choices=[]), dict(choices=good["choices"] * 2), dict(choices={}),
                   {"choices": [{"message": None, "finish_reason": "stop"}]},
                   {"choices": [{"message": {"role": "user", "content": "SYNTHETIC_DATA"}, "finish_reason": "stop"}]},
                   {"choices": [{"message": {"role": "assistant", "content": "SYNTHETIC_BUILDER_TEXT", "tool_calls": [{}]}, "finish_reason": "stop"}]},
                   {"choices": [{"message": {"role": "assistant", "content": [{"type": "text", "text": "SYNTHETIC_DATA"}]}, "finish_reason": "stop"}]}]
        self.assertEqual(fixture(request(), compact(good)).status, "success")
        for doc in invalid:
            with self.subTest(vector=doc): self.assert_malformed(compact(doc))

    def test_stream_chunks_truncation_and_missing_finish_are_not_complete_text(self):
        """Catches turning partial/chunked output into a completed fixture answer."""
        for reason in ("length", "tool_calls", None):
            doc = openai()
            doc["choices"][0]["finish_reason"] = reason
            self.assert_malformed(compact(doc))
        self.assert_malformed(b'data: {"synthetic":"stream_chunk"}\n\n')
        self.assert_malformed(compact({"choices": [{"delta": {"content": "SYNTHETIC_FRAGMENT"}, "finish_reason": None}]}))
        doc = anthropic(); doc["stop_reason"] = "max_tokens"
        self.assert_malformed(compact(doc), "anthropic_messages")
        self.assertEqual(fixture(request(), compact(anthropic()), "anthropic_messages").status, "success")

    def test_anthropic_blocks_keep_order_and_refuse_nontext_or_wrong_message(self):
        """Catches ignored tool blocks/stream message types or reordered text data."""
        req = request()
        doc = anthropic()
        doc["content"] = [{"type": "text", "text": "SYNTHETIC_A"}, {"type": "text", "text": "_SYNTHETIC_B"}]
        raw = compact(doc); result = fixture(req, raw, "anthropic_messages")
        self.assert_fixture(result, req, raw)
        self.assertEqual(result.text, "SYNTHETIC_A_SYNTHETIC_B")
        for key, value in (("type", "message_delta"), ("role", "user"), ("content", [{"type": "tool_use", "text": "SYNTHETIC_BUILDER_TEXT"}]), ("content", None)):
            bad = anthropic(); bad[key] = value
            self.assert_malformed(compact(bad), "anthropic_messages")

    def test_refusal_and_error_controls_are_not_success_or_free_actual_events(self):
        """Catches losing refusal/error semantics, inventing zero bills or auto retry."""
        req = request()
        refusal = openai(); refusal["choices"][0]["message"]["refusal"] = "SYNTHETIC_BUILDER_REFUSAL_CONTROL"
        content_filter = openai(); content_filter["choices"][0]["finish_reason"] = "content_filter"
        anth = anthropic(); anth["stop_reason"] = "refusal"
        for format, doc in (("openai_chat", refusal), ("openai_chat", content_filter), ("anthropic_messages", anth)):
            raw = compact(doc); result = fixture(req, raw, format)
            self.assert_fixture(result, req, raw)
            self.assertEqual(result.status, "refused")
            self.assertEqual(result.fault.code, "provider_refusal")
        raw = compact({"error": {"message": "SYNTHETIC_BUILDER_ERROR_CONTROL"}})
        result = fixture(req, raw)
        self.assert_fixture(result, req, raw)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.fault.code, "provider_error")
        self.assert_malformed(compact({"error": "SYNTHETIC_NOT_OBJECT"}))

    def test_malformed_utf8_top_level_and_truncated_json_preserve_raw_hash(self):
        """Catches invalid bytes/objects being swallowed as empty successful output."""
        for raw in (b"", b"\xff", b"{", b'"SYNTHETIC_TOP_TEXT"', b"[]", b"null", compact(openai())[:-1]):
            with self.subTest(raw=raw): self.assert_malformed(raw)
        self.assertEqual(fixture(request(), compact(openai())).status, "success")

    def test_duplicate_keys_and_nonfinite_numbers_are_refused(self):
        """Catches ambiguous JSON and nonfinite billing values escaping strict parse."""
        self.assert_malformed(b'{"choices":[],"choices":[]}')
        good = compact(openai(usage={"prompt_tokens": 1}))
        self.assertEqual(good.count(b'"prompt_tokens":1'), 1)
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1e999"):
            self.assert_malformed(good.replace(b'"prompt_tokens":1', b'"prompt_tokens":' + token))
        duplicate = good.replace(b'"prompt_tokens":1', b'"prompt_tokens":1,"prompt_tokens":2')
        self.assert_malformed(duplicate)
        self.assertEqual(fixture(request(), good).usage.input_tokens, 1)

    def test_usage_boolean_negative_fractional_and_wrong_containers_refuse(self):
        """Catches coercing bad usage into counts while erasing unknown charges."""
        for usage in ({"prompt_tokens": True}, {"completion_tokens": -1}, {"prompt_tokens": 1.5},
                      {"prompt_tokens_details": {"cached_tokens": False}},
                      {"completion_tokens_details": {"reasoning_tokens": -1}},
                      {"prompt_tokens_details": []}):
            self.assert_malformed(compact(openai(usage=usage)))
        for usage in ({"input_tokens": True}, {"output_tokens": -1}, {"cache_read_input_tokens": False},
                      {"cache_creation_input_tokens": -1}):
            self.assert_malformed(compact(anthropic(usage=usage)), "anthropic_messages")
        doc = openai(); doc["usage"] = []
        self.assert_malformed(compact(doc))
        self.assertEqual(fixture(request(), compact(openai(usage={"prompt_tokens": 0}))).usage.input_tokens, 0)

    def test_openai_usage_preserves_explicit_counts_and_unknown_overlap_fees(self):
        """Catches zero-filling absent cache/write/other usage or inferring overlap."""
        req = request()
        raw = compact(openai(usage={"prompt_tokens": 10, "completion_tokens": 5,
            "prompt_tokens_details": {"cached_tokens": 2}, "completion_tokens_details": {"reasoning_tokens": 3}}))
        result = fixture(req, raw); self.assert_fixture(result, req, raw)
        self.assertEqual((result.usage.input_tokens, result.usage.output_tokens, result.usage.cache_read_tokens, result.usage.reasoning_tokens), (10, 5, 2, 3))
        self.assertIsNone(result.usage.cache_write_tokens)
        self.assertIsNone(result.usage.other_tokens)
        self.assertIsNone(result.usage.reasoning_in_output)
        nullable = fixture(req, compact(openai(usage={"prompt_tokens": None, "completion_tokens": 0, "prompt_tokens_details": None})))
        self.assertIsNone(nullable.usage.input_tokens)
        self.assertEqual(nullable.usage.output_tokens, 0)
        self.assertIsNone(nullable.usage.cache_read_tokens)

    def test_anthropic_cache_counts_do_not_imply_reasoning_or_actual_price(self):
        """Catches collapsing cache categories or inferring absent reasoning/fees."""
        req = request()
        raw = compact(anthropic(usage={"input_tokens": 10, "output_tokens": 4,
                                    "cache_read_input_tokens": 2, "cache_creation_input_tokens": 3}))
        result = fixture(req, raw, "anthropic_messages"); self.assert_fixture(result, req, raw)
        self.assertEqual((result.usage.input_tokens, result.usage.output_tokens, result.usage.cache_read_tokens, result.usage.cache_write_tokens), (10, 4, 2, 3))
        self.assertIsNone(result.usage.reasoning_tokens)
        self.assertIsNone(result.usage.reasoning_in_output)
        self.assertIsNone(result.usage.other_tokens)
        missing = anthropic(); missing["usage"] = None
        self.assertTrue(all(value is None for value in fixture(req, compact(missing), "anthropic_messages").usage.model_dump().values()))

    def test_preparation_missing_policy_or_model_remains_pending_without_wire(self):
        """Catches manufacturing a model pin or preparing an authorized wire by default."""
        req = request()
        for format in ("openai_chat", "anthropic_messages"):
            absent = prepare_payload(req, format)
            missing = prepare_payload(req, format, policy=policy(req))
            self.assertEqual(absent.status, "pending")
            self.assertIn("payload_policy_missing", absent.issues)
            self.assertEqual(missing.status, "pending")
            self.assertIn("model_pin_missing", missing.issues)
            for result in (absent, missing):
                self.assertIsNone(result.payload_json)
                self.assertEqual(result.compatibility, "unverified")
                self.assertIs(result.transport_authorized, False)

    def test_preparation_propagates_context_byte_canary_refusal_before_missing_model(self):
        """Catches adapter serialization bypassing a failed neutral preflight."""
        req = request()
        for pol, issue in ((policy(req, task="synthetic_other_task"), "policy_task_mismatch"),
                           (policy(req, limit=1), "payload_byte_limit_never_truncate"),
                           (policy(req, fingerprints=("SYNTHETIC_BUILDER_SOURCE_DATA",)), "prohibited_payload_fingerprint")):
            result = prepare_payload(req, "openai_chat", policy=pol)
            self.assertEqual(result.status, "refused")
            self.assertIn(issue, result.issues)
            self.assertIsNone(result.payload_json)
            self.assertIs(result.transport_authorized, False)
        self.assertEqual(prepare_payload(req, "openai_chat", policy=policy(req)).status, "pending")

    def test_prepared_payload_integrity_is_not_provider_compatibility_or_authority(self):
        """Catches inconsistent byte/digest pairs or status escalating to authority."""
        req = request(); raw = b"SYNTHETIC_BUILDER_PENDING_DTO_BYTES"
        positive = PreparedPayload(format="openai_chat", request_sha256=req.request_sha256(),
            payload_json=raw, payload_sha256=sha(raw), status="pending")
        self.assertEqual(positive.payload_json, raw)
        self.assertIs(positive.transport_authorized, False)
        self.assertEqual(positive.compatibility, "unverified")
        for args in ({"payload_json": raw}, {"payload_sha256": sha(raw)},
                     {"payload_json": raw, "payload_sha256": sha(b"SYNTHETIC_DIFFERENT_BYTES")},
                     {"status": "prepared"}, {"transport_authorized": True}, {"compatibility": "verified"}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                PreparedPayload(format="openai_chat", request_sha256=req.request_sha256(), **args)

    def test_unknown_format_refuses_instead_of_guessing_a_provider_adapter(self):
        """Catches silently routing an unsupported format through a known branch."""
        req = request()
        with self.assertRaises(ValueError): prepare_payload(req, "synthetic_unsupported", policy=policy(req))
        with self.assertRaises(ValueError): fixture(req, compact(openai()), "synthetic_unsupported")
        self.assertEqual(fixture(req, compact(openai())).status, "success")
