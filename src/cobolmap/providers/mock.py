"""Deterministic caller-supplied scripts, never paid execution or actual evidence."""
from typing import Annotated

from pydantic import Field

from cobolmap.contracts import FrozenModel, Identifier, Sha256
from .adapters import PayloadFormat, parse_response
from .models import ProviderFault, ProviderRequest, ProviderResult


class ScriptEntry(FrozenModel):
    call_id: Identifier
    request_sha256: Sha256
    format: PayloadFormat
    raw_response_json: bytes


class ScriptedMock(FrozenModel):
    """Pure immutable cursor; caller explicitly threads the returned next state.

    Entries are supplied by the caller. No default script, expected compiler output,
    credential lookup, mutable global state, transport or retry exists here.
    Missing, mismatched or malformed entries refuse without consuming the cursor.
    """
    entries: tuple[ScriptEntry, ...]
    position: Annotated[int, Field(ge=0)] = 0

    def respond(self, request: ProviderRequest) -> tuple[ProviderResult, "ScriptedMock"]:
        base = {"call_id": request.call_id, "request_sha256": request.request_sha256(),
                "model_id": request.model_id, "sent": False, "provenance": "fixture"}
        if self.position >= len(self.entries):
            return (ProviderResult(**base, status="refused", fault=ProviderFault(
                code="missing_script", message="no caller-supplied entry at script position")), self)
        entry = self.entries[self.position]
        if entry.call_id != request.call_id or entry.request_sha256 != request.request_sha256():
            return (ProviderResult(**base, status="refused", fault=ProviderFault(
                code="script_mismatch", message="script call/request/order binding differs")), self)
        result = parse_response(request, entry.raw_response_json, format=entry.format,
                                sent=False, provenance="fixture")
        if result.fault is not None and result.fault.code == "malformed_response":
            return result, self
        return result, ScriptedMock(entries=self.entries, position=self.position + 1)
