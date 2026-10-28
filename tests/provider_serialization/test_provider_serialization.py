"""BUILDER_STRUCTURAL_TEST bytes only, no provider/model/access or authority."""
import hashlib
import json
import unittest

from cobolmap.contracts import canonical_json
from cobolmap.providers import ContextPart, Message, ProviderRequest, LeakagePolicy
from cobolmap.providers.adapters import prepare_payload


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def part(kind, text):
    return ContextPart(task_id="builder_structural_task", kind=kind, text=text,
                       sha256=sha(text.encode("utf-8")))


def request(*, source=None, instruction="BUILDER_STRUCTURAL_TEST_SYSTEM", cap=37):
    if source is None:
        source = '*> BUILDER_STRUCTURAL_TEST_SOURCE "quoted data".\n'
    messages = (Message(role="system", parts=(part("instruction", instruction),)),
        Message(role="user", parts=(part("original_source", source),
             part("shim_api", "BUILDER_STRUCTURAL_TEST_SHIM"),
             part("structured_change", "BUILDER_STRUCTURAL_TEST_CHANGE_DATA"),
             part("map", '{"builder_structural_test":"MAP_DATA"}'))))
    return ProviderRequest(call_id="c_" + "a" * 62, task_id="builder_structural_task", arm="C", attempt=0,
        messages=messages, max_output_tokens=cap,
        model_id="<PLACEHOLDER_MODEL_PIN>")  # Explicit grant: test DTO only, never approved config.


def policy(req, *, limit=60000, fingerprints=()):
    parts = tuple(p for m in req.messages for p in m.parts)
    source = next(p for p in parts if p.kind == "original_source")
    return LeakagePolicy(task_id=req.task_id, original_source_sha256=source.sha256,
        allowed_context_hashes=frozenset(p.sha256 for p in parts), max_payload_bytes=limit,
        prohibited_fingerprints=fingerprints)


def dense_source():
    # Small escape-dense data: final nested JSON exceeds neutral request bytes.
    return ('*> BUILDER_STRUCTURAL_TEST "' + ('\\' * 8) + '"\t\n') * 24


def flat_parts(body, format):
    if format == "openai_chat":
        contents = [m["content"] for m in body["messages"]]
    else:
        contents = [b["text"] for b in body.get("system", [])] + [m["content"] for m in body["messages"]]
    return [p for content in contents for p in json.loads(content)]


class BuilderStructuralSerialization(unittest.TestCase):
    def assert_untrusted(self, packet):
        self.assertEqual(packet.compatibility, "unverified")
        self.assertIs(packet.transport_authorized, False)

    def prepared(self, req, format, pol=None):
        packet = prepare_payload(req, format, policy=pol or policy(req))
        self.assert_untrusted(packet)
        self.assertEqual(packet.status, "prepared")
        self.assertIn(b"BUILDER_STRUCTURAL_TEST", packet.payload_json)
        self.assertEqual(packet.request_sha256, req.request_sha256())
        self.assertEqual(packet.payload_sha256, sha(packet.payload_json))
        return packet, json.loads(packet.payload_json)

    def assert_all_context(self, req, body, format):
        expected = [p.model_dump(mode="json") for m in req.messages for p in m.parts]
        actual = flat_parts(body, format)
        self.assertEqual(actual, expected)
        # Fixture parts have unique hashes; a dropped/duplicated part cannot hide.
        self.assertEqual(len(actual), len({p["sha256"] for p in actual}))

    def test_openai_envelope_and_delimited_context_are_exact(self):
        """Catches wrong model/output cap/sample/stream or lost/duplicated context."""
        req = request()
        _, body = self.prepared(req, "openai_chat")
        self.assertEqual(set(body), {"model", "messages", "max_completion_tokens", "n", "stream"})
        self.assertEqual(body["model"], req.model_id)
        self.assertEqual(body["max_completion_tokens"], 37)
        self.assertEqual(body["n"], 1)
        self.assertIs(body["stream"], False)
        self.assertEqual(body["messages"], [{"role": m.role, "content": m.content()} for m in req.messages])
        self.assert_all_context(req, body, "openai_chat")

    def test_anthropic_envelope_system_and_conversation_remain_separate(self):
        """Catches merged system/user text, extra sample fields or wrong token key."""
        req = request()
        _, body = self.prepared(req, "anthropic_messages")
        self.assertEqual(set(body), {"model", "messages", "max_tokens", "stream", "system"})
        self.assertEqual(body["model"], req.model_id)
        self.assertEqual(body["max_tokens"], 37)
        self.assertIs(body["stream"], False)
        self.assertEqual(body["system"], [{"type": "text", "text": req.messages[0].content()}])
        self.assertEqual(body["messages"], [{"role": "user", "content": req.messages[1].content()}])
        self.assert_all_context(req, body, "anthropic_messages")

    def test_multiple_leading_systems_and_conversation_order_are_preserved(self):
        """Catches dropping one system message or reshuffling assistant/user data."""
        req = request()
        second = Message(role="system", parts=(part("instruction", "BUILDER_STRUCTURAL_TEST_SYSTEM_TWO"),))
        assistant = Message(role="assistant", parts=(part("instruction", "BUILDER_STRUCTURAL_TEST_ASSISTANT_DATA"),))
        user = Message(role="user", parts=(part("instruction", "BUILDER_STRUCTURAL_TEST_USER_TWO"),))
        req = req.model_copy(update={"messages": (req.messages[0], second, req.messages[1], assistant, user)})
        _, body = self.prepared(req, "anthropic_messages")
        self.assertEqual([b["text"] for b in body["system"]], [m.content() for m in req.messages[:2]])
        self.assertEqual([m["role"] for m in body["messages"]], ["user", "assistant", "user"])
        self.assert_all_context(req, body, "anthropic_messages")

    def test_absent_system_is_not_invented_or_reclassified(self):
        """Catches fabricating a system instruction from user-delimited source data."""
        req = request()
        all_parts = tuple(p for m in req.messages for p in m.parts)
        req = req.model_copy(update={"messages": (Message(role="user", parts=all_parts),)})
        _, body = self.prepared(req, "anthropic_messages")
        self.assertNotIn("system", body)
        self.assert_all_context(req, body, "anthropic_messages")

    def test_system_after_conversation_refuses_instead_of_reordering(self):
        """Catches silently changing instruction order to fit a provider hypothesis."""
        req = request()
        self.prepared(req, "anthropic_messages")
        req = req.model_copy(update={"messages": tuple(reversed(req.messages))})
        refused = prepare_payload(req, "anthropic_messages", policy=policy(req))
        self.assert_untrusted(refused)
        self.assertEqual(refused.status, "refused")
        self.assertIn("nonleading_system_message", refused.issues)
        self.assertIsNone(refused.payload_json)

    def test_system_only_refuses_without_fabricating_conversation(self):
        """Catches accepting an empty conversation or inventing a synthetic user."""
        req = request()
        self.prepared(req, "anthropic_messages")
        req = req.model_copy(update={"messages": tuple(Message(role="system", parts=m.parts) for m in req.messages)})
        refused = prepare_payload(req, "anthropic_messages", policy=policy(req))
        self.assert_untrusted(refused)
        self.assertEqual(refused.status, "refused")
        self.assertIn("conversation_missing", refused.issues)
        self.assertIsNone(refused.payload_json)

    def test_json_escaping_nonascii_and_source_comment_data_roundtrip(self):
        """Catches JSON interpolation, Unicode loss or whitespace/comment rewriting."""
        source = '*> BUILDER_STRUCTURAL_TEST "caf\u00e9 \u6f22\u5b57 \U0001f642"\r\n' + '\\tab\tend\x00'
        req = request(source=source)
        for format in ("openai_chat", "anthropic_messages"):
            packet, body = self.prepared(req, format)
            self.assertTrue(all(byte < 128 for byte in packet.payload_json))
            self.assert_all_context(req, body, format)
            decoded = next(p for p in flat_parts(body, format) if p["kind"] == "original_source")
            self.assertEqual(decoded["text"], source)
            self.assertEqual(decoded["sha256"], sha(source.encode("utf-8")))

    def test_final_escaped_byte_boundary_refuses_without_truncation(self):
        """Catches enforcing neutral size alone or shrinking a too-large final frame."""
        req = request(source=dense_source())
        neutral_size = len(canonical_json(req))
        for format in ("openai_chat", "anthropic_messages"):
            complete, _ = self.prepared(req, format)
            size = len(complete.payload_json)
            self.assertGreater(size, neutral_size, "escape-dense builder vector must reach final-only bound")
            equal, _ = self.prepared(req, format, policy(req, limit=size))
            self.assertEqual(equal.payload_json, complete.payload_json)
            refused = prepare_payload(req, format, policy=policy(req, limit=size - 1))
            self.assert_untrusted(refused)
            self.assertEqual(refused.status, "refused")
            self.assertIn("wire_payload_byte_limit_never_truncate", refused.issues)
            self.assertNotIn("payload_byte_limit_never_truncate", refused.issues)
            self.assertEqual(refused.payload_json, complete.payload_json)
            self.assertEqual(refused.payload_sha256, sha(complete.payload_json))

    def test_final_serialized_fingerprint_is_checked_after_extra_json_escaping(self):
        """Catches scanning decoded/neutral context while missing final-frame bytes."""
        req = request(source='*> BUILDER_STRUCTURAL_TEST "quoted".')
        fingerprint = '\\' * 3 + '"'  # Invented structural vector, not an authentic canary.
        self.assertNotIn(fingerprint, canonical_json(req).decode("ascii"))
        self.assertTrue(all(fingerprint not in p.text for m in req.messages for p in m.parts))
        for format in ("openai_chat", "anthropic_messages"):
            complete, _ = self.prepared(req, format)
            self.assertIn(fingerprint, complete.payload_json.decode("ascii"))
            safe, _ = self.prepared(req, format, policy(req, fingerprints=("BUILDER_STRUCTURAL_TEST_ABSENT_MARKER",)))
            self.assertEqual(safe.payload_json, complete.payload_json)
            refused = prepare_payload(req, format, policy=policy(req, fingerprints=(fingerprint,)))
            self.assert_untrusted(refused)
            self.assertEqual(refused.status, "refused")
            self.assertIn("prohibited_wire_fingerprint", refused.issues)
            self.assertNotIn("prohibited_payload_fingerprint", refused.issues)
            self.assertEqual(refused.payload_json, complete.payload_json)

    def test_context_change_updates_both_hashes_without_mutating_input(self):
        """Catches stale hashes or serialization mutating caller-owned context."""
        first = request()
        second = request(instruction="BUILDER_STRUCTURAL_TEST_ALTERNATE")
        before = canonical_json(first)
        for format in ("openai_chat", "anthropic_messages"):
            left, _ = self.prepared(first, format)
            right, _ = self.prepared(second, format)
            self.assertNotEqual(left.request_sha256, right.request_sha256)
            self.assertNotEqual(left.payload_sha256, right.payload_sha256)
            self.assertNotEqual(left.payload_json, right.payload_json)
        self.assertEqual(canonical_json(first), before)

    def test_repeat_serialization_is_deterministic_and_remains_untrusted(self):
        """Catches hidden nondeterminism or structure-only success acquiring authority."""
        req = request()
        for format in ("openai_chat", "anthropic_messages"):
            first, _ = self.prepared(req, format)
            second, _ = self.prepared(req, format)
            self.assertEqual(first.payload_json, second.payload_json)
            self.assertEqual(first.payload_sha256, second.payload_sha256)
        self.assertIsNone(req.run_plan_sha256)
        self.assertIsNone(req.prices_sha256)
        self.assertIsNone(req.input_tokens)
        self.assertIsNone(req.token_count_receipt)
        self.assertIsNone(policy(req).context_authority)

    def test_unicode_source_forms_are_not_silently_normalized(self):
        """Catches altering distinct source byte identities during JSON encoding."""
        first = request(source='*> BUILDER_STRUCTURAL_TEST caf\u00e9')
        second = request(source='*> BUILDER_STRUCTURAL_TEST cafe\u0301')
        for format in ("openai_chat", "anthropic_messages"):
            a, body_a = self.prepared(first, format)
            b, body_b = self.prepared(second, format)
            self.assertNotEqual(a.request_sha256, b.request_sha256)
            self.assertNotEqual(a.payload_sha256, b.payload_sha256)
            text_a = next(p["text"] for p in flat_parts(body_a, format) if p["kind"] == "original_source")
            text_b = next(p["text"] for p in flat_parts(body_b, format) if p["kind"] == "original_source")
            self.assertNotEqual(text_a, text_b)
