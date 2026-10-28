"""LOCAL reduction control evidence. No authority implementation or wire union."""
import json
from typing import Annotated, Protocol, TYPE_CHECKING
from pydantic import Field
from .base import ArtifactRef, FrozenModel, Identifier, Sha256, SourcePointer, sha256
from . import claim_models as claims
from . import maps, evidence, study
from .evidence import CaseBundle, ExecutionObservation, ExecutionPins
from .study import CounterexampleFeedback

if TYPE_CHECKING:
    from cobolmap.providers.models import ProviderRequest


class DerivativeScope(FrozenModel):
    task_id: Identifier
    program_id: Identifier
    source_sha256: Sha256
    candidate_sha256: Sha256
    original_loop_hashes: frozenset[Sha256]
    oracle_pins: ExecutionPins
    candidate_pins: ExecutionPins
    admission_authority: ArtifactRef
    derivation_authority: ArtifactRef


class RetainedReduction(FrozenModel):
    parent_case: CaseBundle
    child_case: CaseBundle
    child_oracle: ExecutionObservation
    child_candidate: ExecutionObservation
    reason: str


class DerivativeEvidence(FrozenModel):
    scope: DerivativeScope
    origin_case: CaseBundle
    origin_oracle: ExecutionObservation
    origin_candidate: ExecutionObservation
    retained: Annotated[tuple[RetainedReduction, ...], Field(min_length=1, max_length=100)]
    final_case: CaseBundle
    final_oracle: ExecutionObservation
    final_candidate: ExecutionObservation
    proof_artifacts: Annotated[tuple[ArtifactRef, ...], Field(min_length=1)]


class DerivativeAuthority(Protocol):
    """Externally designated actual verifier: authenticate or raise; return None.

    Caller must authenticate this dependency itself. Flags/hashes/duck typing and
    returning None do not establish that it is an actual authority. Authenticate
    sealed32 provenance, complete actual lineage/criterion/isolation/pins and exact
    final content. No implementation, receipt producer or appointment is supplied.
    """
    def verify_derivation(self, *, evidence: DerivativeEvidence,
                          packet: CounterexampleFeedback,
                          request: "ProviderRequest | None",
                          feedback_sha256: str, wire_sha256: str | None) -> None: ...


# Canonical classes only: no arbitrary subclasses/dicts/model_dump forwarding.
_WIRE_TYPES = (
    ArtifactRef, SourcePointer, claims.Claim, claims.FieldComparison, claims.FieldRef,
    claims.FieldValue, claims.LinearTerm, claims.LinearValue, claims.LiteralValue,
    claims.OutputEquality, maps.BehaviorMap, maps.MapField, maps.MapParagraph,
    maps.ControlEdge, maps.Effect, maps.Hazard, evidence.CaseBundle,
    evidence.ObservedFile, evidence.OrdinaryObservation, study.CandidateAttempt,
    study.FeedbackContext, study.LoopWitness, study.CounterexampleFeedback,
    study.CountOnlyFeedback, study.InitialFeedback,
)
_LOCAL_TYPES = (DerivativeScope, RetainedReduction, DerivativeEvidence,
                evidence.ExecutionPins, evidence.EvidenceBinding, evidence.ExecutionObservation)


def revalidate_closed(value, expected, *, extra_types=()):
    """Rebuild canonical nested values, including model_construct-created objects.

    Exact classes and field sets are checked before reading fields. No dict/list
    carrier can substitute for a nested model/tuple. Every model validator reruns.
    """
    allowed = _WIRE_TYPES + _LOCAL_TYPES + extra_types

    def clone(item):
        cls = type(item)
        if cls in allowed:
            names = tuple(cls.model_fields)
            if (set(item.__dict__) != set(names)
                    or getattr(item, "__pydantic_extra__", None)):
                raise ValueError("closed_model_fields_required")
            return cls.model_validate({name: clone(getattr(item, name)) for name in names})
        if cls is tuple:
            return tuple(clone(x) for x in item)
        if cls is frozenset:
            return frozenset(clone(x) for x in item)
        if cls in (str, bytes, int, bool, float, type(None)):
            return item
        raise ValueError("exact_closed_nested_value_required")

    if type(value) is not expected or expected not in allowed:
        raise ValueError("exact_closed_root_required")
    return clone(value)


def wire_value(value):
    """Closed allowlist projection; local evidence/observations are never allowed."""
    cls = type(value)
    if cls in _WIRE_TYPES:
        return {name: wire_value(getattr(value, name)) for name in cls.model_fields}
    if cls is tuple:
        return [wire_value(x) for x in value]
    if cls is bytes:
        return value.hex()
    if cls in (str, int, bool, type(None)):
        return value
    raise ValueError("local_or_unknown_value_forbidden_on_wire")


def wire_json(value) -> bytes:
    return json.dumps(wire_value(value), sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _raw_channel(oracle, candidate, channel):
    left, right = oracle.ordinary, candidate.ordinary
    if channel == "output_presence":
        return left.output.present, right.output.present
    if channel == "output":
        return left.output.data, right.output.data
    if channel in ("stdout", "stderr", "return_code"):
        return getattr(left, channel), getattr(right, channel)
    raise ValueError("ordinary_mismatch_channel_required")


def validate_derivative(packet: CounterexampleFeedback, local: DerivativeEvidence,
                        loop_hashes: frozenset[str]) -> tuple[CounterexampleFeedback, DerivativeEvidence]:
    """Structural checks only. Never authorizes serialization or execution."""
    packet = revalidate_closed(packet, CounterexampleFeedback)
    local = revalidate_closed(local, DerivativeEvidence)
    scope = local.scope
    if (type(loop_hashes) is not frozenset or len(loop_hashes) != 32
            or scope.original_loop_hashes != loop_hashes
            or local.origin_case.case_sha256 not in loop_hashes):
        raise ValueError("exact_original32_origin_required")
    if (packet.witness is None or packet.context.previous_candidate is None
            or packet.task_id != scope.task_id
            or packet.context.source_sha256 != scope.source_sha256
            or packet.context.previous_candidate.candidate_sha256 != scope.candidate_sha256):
        raise ValueError("derivative_packet_scope_mismatch")
    if local.final_case.case_sha256 in loop_hashes:
        raise ValueError("use_original_membership_path")
    source = packet.context.source_text.encode("utf-8")
    if sha256(source) != scope.source_sha256:
        raise ValueError("derivative_source_mismatch")
    behavior = packet.context.behavior_map
    fields = tuple(f for f in behavior.fields if f.storage == "output")
    # Resolve every source-bearing map pointer, including nested claim operands.
    def pointers(value):
        if type(value) is SourcePointer:
            value.resolve(source, behavior.filename)
        elif type(value) in _WIRE_TYPES:
            for name in type(value).model_fields:
                pointers(getattr(value, name))
        elif type(value) is tuple:
            for item in value:
                pointers(item)
    pointers(behavior)
    for pointer in packet.witness.pointers:
        pointer.resolve(source, behavior.filename)

    # Local import avoids facade cycles; compare is pure and performs no execution.
    from cobolmap.diff.comparator import compare

    def pair(case, oracle, candidate):
        for observation, pins, candidate_hash in (
                (oracle, scope.oracle_pins, None),
                (candidate, scope.candidate_pins, scope.candidate_sha256)):
            if (observation.task_id != scope.task_id or observation.program_id != scope.program_id
                    or observation.source_sha256 != scope.source_sha256
                    or observation.case_sha256 != case.case_sha256
                    or observation.candidate_sha256 != candidate_hash
                    or observation.evidence.pins != pins
                    or observation.evidence.admission_authority != scope.admission_authority
                    or observation.evidence.missing_actual()):
                raise ValueError("actual_derivative_observation_binding_required")
            if observation.allowed_return_codes != local.origin_oracle.allowed_return_codes:
                raise ValueError("declared_return_codes_changed")
        result = compare(oracle, candidate, admitted=True, fields=fields)
        if result.status != "mismatch":
            raise ValueError("actual_ordinary_mismatch_required")
        return result

    baseline = pair(local.origin_case, local.origin_oracle, local.origin_candidate)
    previous = local.origin_case
    seen = {previous.case_sha256}
    for step in local.retained:
        if not step.reason or step.parent_case != previous:
            raise ValueError("retained_parent_bytes_or_reason_mismatch")
        child = step.child_case
        if child.case_sha256 in seen or child.case_sha256 in loop_hashes:
            raise ValueError("retained_cycle_or_original_relabel")
        if (child.input_present != local.origin_case.input_present
                or (local.origin_case.records and not child.records)):
            raise ValueError("reduction_input_scenario_changed")
        result = pair(child, step.child_oracle, step.child_candidate)
        for original in baseline.differences:
            matches = [d for d in result.differences
                       if (d.channel, d.classification, d.field_name) ==
                       (original.channel, original.classification, original.field_name)]
            if not matches:
                raise ValueError("reduction_criterion_changed")
            if original.basis == "byte_heuristic" or original.classification == "unknown":
                if _raw_channel(step.child_oracle, step.child_candidate, original.channel) != _raw_channel(
                        local.origin_oracle, local.origin_candidate, original.channel):
                    raise ValueError("uncertain_raw_channel_criterion_changed")
        seen.add(child.case_sha256)
        previous = child
    last = local.retained[-1]
    if (local.final_case != previous or local.final_oracle != last.child_oracle
            or local.final_candidate != last.child_candidate):
        raise ValueError("final_retained_pair_mismatch")
    witness = packet.witness
    final = pair(local.final_case, local.final_oracle, local.final_candidate)
    if (witness.case != local.final_case or witness.oracle != local.final_oracle.ordinary
            or witness.candidate != local.final_candidate.ordinary
            or witness.minimization != "best_found"
            or not any((witness.classification, witness.first_offset, witness.field_name) ==
                       (d.classification, d.first_offset, d.field_name) for d in final.differences)):
        raise ValueError("final_witness_projection_mismatch")
    return packet, local


def authenticate_derivative(packet, local, loop_hashes, authority, *, request=None,
                            wire_sha256=None) -> bytes:
    packet, local = validate_derivative(packet, local, loop_hashes)
    raw = wire_json(packet)
    if authority is None:
        raise ValueError("external_derivative_authority_required")
    if authority.verify_derivation(evidence=local, packet=packet, request=request,
                                   feedback_sha256=sha256(raw), wire_sha256=wire_sha256) is not None:
        raise ValueError("derivative_authority_must_authenticate_or_raise")
    # Evidence and packet are reconstructed immutable snapshots. A verifier is a
    # trusted dependency, not attacker data; it must not mutate supplied objects.
    if wire_json(revalidate_closed(packet, CounterexampleFeedback)) != raw:
        raise ValueError("feedback_changed_during_authentication")
    return raw


def derivative_from_reduction(result, *, scope: DerivativeScope,
                              proof_artifacts: tuple[ArtifactRef, ...]) -> DerivativeEvidence:
    """Adapt actual supplied retained bytes only. Does NOT authenticate/authorize.

    Requires the extended producer API; older/missing fields refuse. No callbacks,
    store, data construction from hashes or outbound-compatibility flag is granted.
    """
    from cobolmap.oracle.minimize_models import ReductionResult, ReductionStep, ObservationPair
    if (type(result) is not ReductionResult or result.status != "best_found"
            or result.minimization != "best_found"
            or result.outbound_feedback_compatible is not False
            or result.universal_minimum is not False
            or type(result.lineage) is not tuple or not 1 <= len(result.lineage) <= 100):
        raise ValueError("extended_actual_retained_reduction_required")
    origin = getattr(result, "origin_case", None)
    baseline = getattr(result, "origin_witness", None)
    if type(origin) is not CaseBundle or type(baseline) is not ObservationPair:
        raise ValueError("origin_bytes_and_baseline_missing")
    if origin.case_sha256 != result.origin_case_sha256 or type(result.witness) is not ObservationPair:
        raise ValueError("reduction_origin_or_final_binding_missing")
    steps = []
    for step in result.lineage:
        if (type(step) is not ReductionStep or type(step.witness) is not ObservationPair
                or type(getattr(step, "parent_case", None)) is not CaseBundle
                or type(getattr(step, "derivative_case", None)) is not CaseBundle):
            raise ValueError("retained_parent_child_bytes_missing")
        if (step.parent_case.case_sha256 != step.parent_case_sha256
                or step.derivative_case.case_sha256 != step.derivative_case_sha256):
            raise ValueError("producer_step_hash_binding_mismatch")
        steps.append(RetainedReduction(parent_case=step.parent_case, child_case=step.derivative_case,
                                       child_oracle=step.witness.oracle,
                                       child_candidate=step.witness.candidate, reason=step.reason))
    local = DerivativeEvidence(scope=scope, origin_case=origin,
                               origin_oracle=baseline.oracle, origin_candidate=baseline.candidate,
                               retained=tuple(steps), final_case=result.case,
                               final_oracle=result.witness.oracle, final_candidate=result.witness.candidate,
                               proof_artifacts=proof_artifacts)
    return revalidate_closed(local, DerivativeEvidence)
