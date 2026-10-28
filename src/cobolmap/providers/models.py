"""Neutral provider declarations. No model, price, authority or evidence is supplied."""
from typing import Annotated, Literal, Self
from pydantic import Field, StringConstraints, model_validator
from cobolmap.contracts import ArtifactRef, FrozenModel, Identifier, Sha256, canonical_json, sha256

MoneyText = Annotated[str, StringConstraints(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")]
TokenCount = Annotated[int, Field(ge=0)]
ProviderStatus = Literal["not_sent", "refused", "failed", "unknown", "success"]
ContextKind = Literal["instruction", "original_source", "map", "shim_api", "structured_change",
                      "previous_candidate", "diagnostic", "loop_witness", "counts"]


class ContextPart(FrozenModel):
    task_id: Identifier
    kind: ContextKind
    text: str
    sha256: Sha256
    case_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def identity(self) -> Self:
        if sha256(self.text.encode("utf-8")) != self.sha256:
            raise ValueError("context text/hash mismatch")
        if (self.kind == "loop_witness") != (self.case_sha256 is not None):
            raise ValueError("only a loop witness has a case pin")
        return self


class Message(FrozenModel):
    role: Literal["system", "user", "assistant"]
    parts: tuple[ContextPart, ...]

    def content(self) -> str:
        # Delimited JSON data, never interpolation into executable/system code.
        import json
        return json.dumps([p.model_dump(mode="json") for p in self.parts], sort_keys=True,
                          ensure_ascii=True, separators=(",", ":"), allow_nan=False)


class Usage(FrozenModel):
    input_tokens: TokenCount | None = None
    output_tokens: TokenCount | None = None
    cache_read_tokens: TokenCount | None = None
    cache_write_tokens: TokenCount | None = None
    reasoning_tokens: TokenCount | None = None
    other_tokens: TokenCount | None = None
    reasoning_in_output: bool | None = None

    def ledger_mapping(self) -> dict[str, int | bool | None]:
        return self.model_dump(mode="python")


class ProviderFault(FrozenModel):
    code: Literal["not_authorized", "accounting_blocked", "payload_rejected", "missing_model",
                  "missing_script", "script_mismatch", "malformed_response", "provider_refusal",
                  "provider_error", "transport_unknown"]
    message: str
    retryable: Literal[False] = False


class ProviderRequest(FrozenModel):
    call_id: Identifier
    task_id: Identifier
    arm: Literal["B", "C", "D", "R"]
    attempt: Annotated[int, Field(ge=0, le=3)]
    messages: tuple[Message, ...]
    sample: Literal[1] = 1
    model_id: str | None = None
    run_plan_sha256: Sha256 | None = None
    prices_sha256: Sha256 | None = None
    shared_c_call_id: Identifier | None = None
    max_input_tokens: Annotated[int, Field(ge=1, le=6000)] = 6000
    max_output_tokens: Annotated[int, Field(ge=1, le=2500)] = 2500
    input_tokens: TokenCount | None = None
    token_count_receipt: ArtifactRef | None = None

    @model_validator(mode="after")
    def binding(self) -> Self:
        if type(self.sample) is not int:
            raise ValueError("strict integer sample required")
        if self.model_id is not None and (not self.model_id or any(c.isspace() or ord(c) < 32 for c in self.model_id)):
            raise ValueError("exact model ID or None required")
        if self.arm in ("B", "C") and (self.attempt != 0 or self.shared_c_call_id is not None):
            raise ValueError("initial B/C call identity")
        if self.arm in ("D", "R") and (self.attempt == 0 or self.shared_c_call_id is None
                                        or self.shared_c_call_id == self.call_id):
            raise ValueError("repair needs distinct own ID and shared C identity")
        return self

    def request_sha256(self) -> str:
        return sha256(canonical_json(self))


class ProviderResult(FrozenModel):
    call_id: Identifier
    request_sha256: Sha256
    model_id: str | None = None
    status: ProviderStatus = "not_sent"
    sent: bool | None = False
    text: str | None = None
    usage: Usage = Field(default_factory=Usage)
    cost_usd: MoneyText | None = None
    raw_response_sha256: Sha256 | None = None
    fault: ProviderFault | None = None
    provenance: Literal["not_run", "fixture", "provider_declared"] = "not_run"

    @model_validator(mode="after")
    def result_shape(self) -> Self:
        if self.status == "not_sent" and self.sent is not False:
            raise ValueError("not_sent must be proven unsent")
        if self.status == "unknown" and self.cost_usd is not None:
            raise ValueError("unknown outcome retains unknown billed cost")
        if self.status == "success" and self.text is None:
            raise ValueError("success needs supplied response text")
        if self.provenance == "not_run" and self.status != "not_sent":
            raise ValueError("unrun response cannot claim provider outcome")
        if self.provenance == "fixture" and self.sent is not False:
            raise ValueError("fixture is never a paid sent event")
        return self


class LeakagePolicy(FrozenModel):
    task_id: Identifier
    original_source_sha256: Sha256
    context_authority: ArtifactRef | None = None
    prohibited_fingerprints: tuple[str, ...] = ()
    loop_hashes: frozenset[Sha256] = frozenset()
    max_payload_bytes: Annotated[int, Field(ge=1, le=1048576)] = 60000
    token_count_receipt: ArtifactRef | None = None
    canary_policy_receipt: ArtifactRef | None = None
    allowed_context_hashes: frozenset[Sha256] = frozenset()


class PreflightResult(FrozenModel):
    status: Literal["refused", "pending", "checked"] = "pending"
    request_sha256: Sha256
    payload_sha256: Sha256 | None = None
    issues: tuple[str, ...] = ()
    # Structural checks cannot authenticate policy or grant transport authority.
    transport_authorized: Literal[False] = False
