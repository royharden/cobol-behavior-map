"""Pure, unverified provider wire-shape hypotheses; no transport or billing.

These shapes require compatibility validation before any future provider use.
Preparation checks structure only; it cannot grant policy/accounting authority.
"""
import json
import math
from typing import Literal, Self

from pydantic import model_validator

from cobolmap.contracts import FrozenModel, Sha256, sha256
from .models import LeakagePolicy, ProviderFault, ProviderRequest, ProviderResult, Usage
from .payload import validate_payload

PayloadFormat = Literal["openai_chat", "anthropic_messages"]


class PreparedPayload(FrozenModel):
    format: PayloadFormat
    request_sha256: Sha256
    payload_json: bytes | None = None
    payload_sha256: Sha256 | None = None
    status: Literal["pending", "refused", "prepared"] = "pending"
    issues: tuple[str, ...] = ()
    compatibility: Literal["unverified"] = "unverified"
    transport_authorized: Literal[False] = False

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if (self.payload_json is None) != (self.payload_sha256 is None):
            raise ValueError("payload bytes and digest must occur together")
        if self.payload_json is not None and sha256(self.payload_json) != self.payload_sha256:
            raise ValueError("prepared payload digest mismatch")
        if self.status == "prepared" and (self.payload_json is None or self.issues):
            raise ValueError("prepared requires complete structural payload")
        return self


def prepare_payload(request: ProviderRequest, format: PayloadFormat, *,
                    policy: LeakagePolicy | None = None) -> PreparedPayload:
    """Serialize all context without truncation; full wire-policy admission is external."""
    base = {"format": format, "request_sha256": request.request_sha256()}
    if format not in ("openai_chat", "anthropic_messages"):
        raise ValueError("unsupported payload format")
    if policy is None:
        return PreparedPayload(**base, issues=("payload_policy_missing",))
    checked = validate_payload(request, policy, require_actual_context=False)
    if checked.status != "checked":
        return PreparedPayload(**base, status=checked.status, issues=checked.issues)
    if request.model_id is None:
        return PreparedPayload(**base, issues=("model_pin_missing",))
    messages = [{"role": message.role, "content": message.content()}
                for message in request.messages]
    if format == "openai_chat":
        wire = {"model": request.model_id, "messages": messages,
                "max_completion_tokens": request.max_output_tokens, "n": request.sample,
                "stream": False}
    else:
        system = []
        conversation = []
        for message in messages:
            if message["role"] == "system":
                if conversation:
                    return PreparedPayload(**base, status="refused",
                                           issues=("nonleading_system_message",))
                system.append({"type": "text", "text": message["content"]})
            else:
                conversation.append(message)
        if not conversation:
            return PreparedPayload(**base, status="refused", issues=("conversation_missing",))
        wire = {"model": request.model_id, "messages": conversation,
                "max_tokens": request.max_output_tokens, "stream": False}
        if system:
            wire["system"] = system
    raw = json.dumps(wire, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                     allow_nan=False).encode("utf-8")
    issues = []
    if len(raw) > policy.max_payload_bytes:
        issues.append("wire_payload_byte_limit_never_truncate")
    if any(value in raw.decode("utf-8") for value in policy.prohibited_fingerprints):
        issues.append("prohibited_wire_fingerprint")
    return PreparedPayload(**base, payload_json=raw, payload_sha256=sha256(raw),
                           status="refused" if issues else "prepared", issues=tuple(issues))


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise ValueError("nonfinite JSON constant")


def _float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("nonfinite JSON number")
    return parsed


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _count(source: dict, key: str) -> int | None:
    value = source.get(key)
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError("nonnegative integer usage required")
    return value


def _usage(document: dict, format: PayloadFormat) -> Usage:
    raw = document.get("usage")
    if raw is None:
        return Usage()
    raw = _object(raw)
    if format == "openai_chat":
        prompt_value = raw.get("prompt_tokens_details")
        completion_value = raw.get("completion_tokens_details")
        prompt = {} if prompt_value is None else _object(prompt_value)
        completion = {} if completion_value is None else _object(completion_value)
        return Usage(input_tokens=_count(raw, "prompt_tokens"),
                     output_tokens=_count(raw, "completion_tokens"),
                     cache_read_tokens=_count(prompt, "cached_tokens"),
                     reasoning_tokens=_count(completion, "reasoning_tokens"))
    return Usage(input_tokens=_count(raw, "input_tokens"),
                 output_tokens=_count(raw, "output_tokens"),
                 cache_read_tokens=_count(raw, "cache_read_input_tokens"),
                 cache_write_tokens=_count(raw, "cache_creation_input_tokens"))


def parse_response(request: ProviderRequest, raw_json: bytes, *, format: PayloadFormat,
                   sent: bool | None,
                   provenance: Literal["provider_declared", "fixture"] = "provider_declared"
                   ) -> ProviderResult:
    """Parse caller-supplied bytes; sent state is a declaration, never transport evidence.

    Missing usage remains nullable and cost is always unknown. No cache/reasoning
    overlap semantics or prices are inferred. Malformed possibly-sent outcomes stay
    unknown, including usage: they must never become zero-cost failed calls.
    Explicit fixture provenance requires sent=False and may omit the model pin
    only when the supplied response also omits it; it never grants actual status.
    """
    if type(raw_json) is not bytes:
        raise TypeError("raw response bytes required")
    if sent is not None and type(sent) is not bool:
        raise TypeError("explicit bool or unknown sent state required")
    if provenance not in ("provider_declared", "fixture"):
        raise ValueError("explicit provider declaration or fixture provenance required")
    if provenance == "fixture" and sent is not False:
        raise ValueError("fixture response must be explicitly unsent")
    if format not in ("openai_chat", "anthropic_messages"):
        raise ValueError("unsupported response format")
    base = {"call_id": request.call_id, "request_sha256": request.request_sha256(),
            "model_id": request.model_id, "sent": sent,
            "raw_response_sha256": sha256(raw_json), "provenance": provenance}
    try:
        document = _object(json.loads(raw_json.decode("utf-8"), object_pairs_hook=_pairs,
                                      parse_constant=_constant, parse_float=_float))
        if request.model_id is None and provenance != "fixture":
            raise ValueError("response request model pin missing")
        if document.get("model") is not None and document["model"] != request.model_id:
            raise ValueError("response model differs from request pin")
        usage = _usage(document, format)
        if "error" in document:
            _object(document["error"])
            return ProviderResult(**base, status="failed" if sent is not None else "unknown",
                                  usage=usage, fault=ProviderFault(code="provider_error",
                                                                 message="supplied provider error"))
        refusal = False
        if format == "openai_chat":
            choices = document.get("choices")
            if not isinstance(choices, list) or len(choices) != 1:
                raise ValueError("exactly one choice required")
            choice = _object(choices[0])
            message = _object(choice.get("message"))
            if message.get("role") != "assistant" or message.get("tool_calls"):
                raise ValueError("text-only assistant response required")
            refusal_text = message.get("refusal")
            if refusal_text is not None and not isinstance(refusal_text, str):
                raise ValueError("invalid refusal")
            refusal = bool(refusal_text) or choice.get("finish_reason") == "content_filter"
            text = message.get("content")
            complete = choice.get("finish_reason") == "stop"
        else:
            if document.get("type") != "message" or document.get("role") != "assistant":
                raise ValueError("assistant message required")
            blocks = document.get("content")
            if not isinstance(blocks, list):
                raise ValueError("content blocks required")
            texts = []
            for block in blocks:
                block = _object(block)
                if block.get("type") != "text" or not isinstance(block.get("text"), str):
                    raise ValueError("only complete text blocks supported")
                texts.append(block["text"])
            text = "".join(texts)
            refusal = document.get("stop_reason") == "refusal"
            complete = document.get("stop_reason") == "end_turn"
        if refusal:
            return ProviderResult(**base, status="refused", usage=usage,
                                  fault=ProviderFault(code="provider_refusal",
                                                      message="supplied provider refusal"))
        if not isinstance(text, str) or not complete:
            raise ValueError("complete response text required")
        return ProviderResult(**base, status="success", text=text, usage=usage)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return ProviderResult(**base, status="unknown" if sent is not False else "refused",
                              fault=ProviderFault(code="malformed_response",
                                                  message="response outside supported strict shape"))
