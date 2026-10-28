"""Fail-closed serialization only. No provider, network or message dispatch."""
from .derivation import (DerivativeAuthority, DerivativeEvidence, authenticate_derivative,
                         revalidate_closed, wire_json)
from .study import CounterexampleFeedback, CountOnlyFeedback, FeedbackPacket, InitialFeedback


def feedback_json(packet: FeedbackPacket, *, loop_hashes: frozenset[str],
                  admitted: bool = False, max_payload_bytes: int = 60000,
                  derivative: DerivativeEvidence | None = None,
                  derivative_authority: DerivativeAuthority | None = None) -> bytes:
    """Caller authenticates source/diagnostic origins and loop partition externally.

    A byte bound is not a model token bound. Exact token/runplan/canary checks are
    still required before a separately authorized sender can use this data.
    """
    if admitted is not True:
        raise ValueError("feedback unavailable: external admission required")
    if type(packet) not in (InitialFeedback, CounterexampleFeedback, CountOnlyFeedback):
        raise ValueError("closed feedback packet type required")
    packet = revalidate_closed(packet, type(packet))
    import re
    if (type(loop_hashes) is not frozenset or len(loop_hashes) != 32
            or any(type(h) is not str or not re.fullmatch(r"[0-9a-f]{64}", h) for h in loop_hashes)):
        raise ValueError("authenticated complete loop partition required")
    if type(max_payload_bytes) is not int or max_payload_bytes <= 0:
        raise ValueError("positive byte bound required")
    if derivative is not None or derivative_authority is not None:
        if type(packet) is not CounterexampleFeedback or derivative is None:
            raise ValueError("derivative_only_for_changed_D_witness")
        raw = authenticate_derivative(packet, derivative, loop_hashes, derivative_authority)
    else:
        raw = None
    if isinstance(packet, CounterexampleFeedback):
        if derivative is None:
            packet.assert_loop_membership(loop_hashes)
        if packet.witness is not None:
            source = packet.context.source_text.encode("utf-8")
            for pointer in packet.witness.pointers:
                pointer.resolve(source)
    if isinstance(packet, CountOnlyFeedback) and packet.loop_cases != len(loop_hashes):
        raise ValueError("count-only partition count mismatch")
    raw = wire_json(packet) if raw is None else raw
    if len(raw) > max_payload_bytes:
        raise ValueError("feedback payload exceeds declared byte bound; never truncate")
    return raw
