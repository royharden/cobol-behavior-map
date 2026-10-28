"""Versioned project instrument source; never an evidence-gate core certification."""
from dataclasses import dataclass, fields
import re
from typing import Protocol

from cobolmap.contracts import (ArtifactRef, ByteDifference, CaseBundle, ComparisonResult,
                                EvidenceBinding, ExecutionObservation, ExecutionPins,
                                ObservedFile, OrdinaryObservation, TaskBinding, canonical_json)
from .mutants import CATALOGUE, MutationArtifact, mutate

INSTRUMENT_EDITION = 'm10-dev-instrument-v1'
STATUSES = frozenset({'not_executed', 'pending', 'killed', 'survived', 'invalid',
                      'equivalent-with-written-proof'})


@dataclass(frozen=True)
class FrozenVerification:
    task_id: str
    program_id: str
    source_sha256: str
    partition: ArtifactRef
    cases: tuple[CaseBundle, ...]


@dataclass(frozen=True)
class CaseComparison:
    case_sha256: str
    oracle: ExecutionObservation
    candidate: ExecutionObservation
    comparison: ComparisonResult


@dataclass(frozen=True)
class BaselineProof:
    task_id: str
    candidate_sha256: str
    partition_sha256: str
    observations: tuple[CaseComparison, ...]
    execution_receipt: ArtifactRef


@dataclass(frozen=True)
class MutantAssessment:
    operator_id: str
    mutation: MutationArtifact | None = None
    status: str = 'not_executed'
    observed_class: str | None = None
    frozen_case_sha256: str | None = None
    kill: CaseComparison | None = None
    survivor_observations: tuple[CaseComparison, ...] = ()
    validity_review: ArtifactRef | None = None
    classification_review: ArtifactRef | None = None
    equivalence_proof: ArtifactRef | None = None
    extra_verifier_witnesses: tuple[ArtifactRef, ...] = ()


@dataclass(frozen=True)
class InstrumentPolicy:
    edition: str
    instrument_source_sha256: str
    catalogue_source_sha256: str
    generator_sha256: str
    runtime_sha256: str
    plan_reader_sha256: str
    preparation_generator_sha256: str
    dev_tasks: tuple[TaskBinding, ...]
    oracle_pins: ExecutionPins
    candidate_pins: ExecutionPins
    authorization: ArtifactRef | None = None
    independent_review: ArtifactRef | None = None
    generation_round: int = 0
    improvement_authorization: ArtifactRef | None = None
    revalidation: ArtifactRef | None = None
    reseal: ArtifactRef | None = None
    renewed_go: ArtifactRef | None = None


class InstrumentAuthority(Protocol):
    def verify(self, *, policy: InstrumentPolicy, baselines: tuple[BaselineProof, ...],
               cases: tuple[FrozenVerification, ...], assessments: tuple[MutantAssessment, ...]) -> None:
        """Authenticate externally approved edition/code/catalogue/pins/scope and ALL
        actual observations, frozen partitions, passing A, original/non-equivalent
        validity/classification or written equivalence, nonauthor review lineage,
        true execution receipts and any sole dev improvement/reseal/renewed GO.
        Caller must authenticate this verifier's external appointment separately.
        Presence, hashes, status flags or a callback returning None are not proof.
        No implementation or actual appointment is provided by this source.
        """
        ...


@dataclass(frozen=True)
class InstrumentReport:
    edition: str
    status: str
    issues: tuple[str, ...]
    scheduled: int
    killed: int
    survived: int
    invalid: int
    equivalent_with_written_proof: int
    pending: int
    missing_classes: tuple[str, ...]
    # Structural evaluation under the external boundary is not a product GO.
    claim: str = 'versioned project instrument; no normalized-core certification'
    product_go: bool = False
    dispatch_allowed: bool = False


def _native(value, cls):
    allowed = (ArtifactRef, ByteDifference, CaseBundle, ComparisonResult, EvidenceBinding,
               ExecutionObservation, ExecutionPins, ObservedFile, OrdinaryObservation, TaskBinding)
    def closed(item):
        if type(item) in allowed:
            fields = type(item).model_fields
            if set(item.__dict__) != set(fields) or item.__pydantic_extra__:
                raise ValueError('nested evidence extras cannot be silently discarded')
            for name in fields:
                closed(item.__dict__[name])
        elif type(item) is tuple:
            for child in item:
                closed(child)
        elif item is not None and type(item) not in (str, bytes, int, bool):
            raise ValueError('unknown/subclassed nested evidence type')
    if type(value) is not cls:
        raise ValueError('exact closed native evidence model required')
    closed(value)
    return cls.model_validate_json(canonical_json(value))


def _digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('exact lowercase SHA256 required')


def _record(value, cls):
    if type(value) is not cls or set(value.__dict__) != {f.name for f in fields(cls)}:
        raise ValueError('exact closed instrument record required')


def _frame(tasks):
    if type(tasks) is not tuple or len(tasks) != 48:
        raise ValueError('complete 48-task DEV frame required')
    tasks = tuple(_native(t, TaskBinding) for t in tasks)
    if any(t.split != 'dev' for t in tasks) or len({t.task_id for t in tasks}) != 48:
        raise ValueError('unique DEV tasks only; no holdout instrument work')
    families = {t.family_id for t in tasks}
    if len(families) != 6:
        raise ValueError('six DEV families required')
    programs = set()
    for family in families:
        members = [t for t in tasks if t.family_id == family]
        unchanged = {t.program_id: t for t in members if t.panel == 'unchanged'}
        changed = {t.program_id: t for t in members if t.panel == 'change'}
        if len(members) != 8 or len(unchanged) != 4 or unchanged.keys() != changed.keys():
            raise ValueError('four programs with both panels per DEV family')
        if programs & unchanged.keys():
            raise ValueError('program reused across families')
        programs.update(unchanged)
        if any(unchanged[p].original.sha256 != changed[p].original.sha256 for p in unchanged):
            raise ValueError('paired original source drift')
    return {t.task_id: t for t in tasks}


def _comparison(item, task, candidate_hash, oracle_pins, candidate_pins, *, matching):
    _record(item, CaseComparison)
    oracle = _native(item.oracle, ExecutionObservation)
    candidate = _native(item.candidate, ExecutionObservation)
    result = _native(item.comparison, ComparisonResult)
    _digest(item.case_sha256)
    for observation, pins in ((oracle, oracle_pins), (candidate, candidate_pins)):
        if (observation.task_id != task.task_id or observation.program_id != task.program_id
                or observation.case_sha256 != item.case_sha256 or observation.evidence.mode != 'actual'
                or observation.evidence.missing_actual() or observation.evidence.pins != pins):
            raise ValueError('actual task/program/case/pin/receipt/authority context required')
    if (oracle.source_sha256 != task.oracle_source.sha256 or oracle.candidate_sha256 is not None
            or candidate.source_sha256 != task.original.sha256 or candidate.candidate_sha256 != candidate_hash):
        raise ValueError('oracle/source/candidate identity drift')
    if oracle.outcome not in ('completed', 'handled') or oracle.ordinary is None:
        raise ValueError('uncontrolled oracle fault/infra is not instrument evidence')
    if matching:
        if (candidate.outcome not in ('completed', 'handled') or candidate.ordinary is None
                or candidate.ordinary != oracle.ordinary or result.status != 'match' or result.equal is not True):
            raise ValueError('genuine passing A/survivor requires exact actual ordinary match')
    else:
        if result.equal is not False or result.status not in ('mismatch', 'candidate_failure'):
            raise ValueError('kill requires actual nonmatching comparison')
        if candidate.outcome in ('not_run', 'infra_invalid'):
            raise ValueError('missing execution/infra is not mutant detection')
        if result.status == 'mismatch' and (candidate.ordinary is None or candidate.ordinary == oracle.ordinary):
            raise ValueError('mismatch requires genuine differing ordinary observations')
        if result.status == 'candidate_failure' and candidate.outcome in ('completed', 'handled'):
            raise ValueError('ordinary completion cannot be relabeled candidate fault')
    return result


def evaluate_instrument(policy: InstrumentPolicy, baselines: tuple[BaselineProof, ...],
                        cases: tuple[FrozenVerification, ...], assessments: tuple[MutantAssessment, ...],
                        *, authority: InstrumentAuthority | None = None) -> InstrumentReport:
    """Check actual supplied records in a future authorized call; never execute them.

    Missing real evidence remains pending. Malformed/contradictory records refuse.
    The return is a versioned local structural verdict, never product/GO authority.
    No checker, regression or generator invocation occurred during construction.
    """
    _record(policy, InstrumentPolicy)
    if policy.edition != INSTRUMENT_EDITION:
        raise ValueError('exact externally pinned instrument edition required')
    for digest in (policy.instrument_source_sha256, policy.catalogue_source_sha256,
                   policy.generator_sha256, policy.runtime_sha256, policy.plan_reader_sha256,
                   policy.preparation_generator_sha256):
        _digest(digest)
    tasks = _frame(policy.dev_tasks)
    oracle_pins = _native(policy.oracle_pins, ExecutionPins)
    candidate_pins = _native(policy.candidate_pins, ExecutionPins)
    # generator_sha256 above binds DL2 translator source; native execution pins
    # bind the separate preparation/case generator. Never equate these roles.
    if any(p.generator_sha256 != policy.preparation_generator_sha256 for p in (oracle_pins, candidate_pins)):
        raise ValueError('shared preparation generator execution pin drift')
    if any(getattr(oracle_pins, name) != getattr(candidate_pins, name)
           for name in ExecutionPins.model_fields if name != 'image_sha256'):
        raise ValueError('shared oracle/candidate execution pins drift')
    if type(policy.generation_round) is not int or policy.generation_round not in (0, 1):
        raise ValueError('only one DEV generator improvement/reseal is permitted')
    if any(type(v) is not tuple for v in (baselines, cases, assessments)):
        raise ValueError('closed immutable record tuples required')
    issues = []
    for name in ('authorization', 'independent_review'):
        if getattr(policy, name) is None:
            issues.append('missing_' + name)
        else:
            _native(getattr(policy, name), ArtifactRef)
    if policy.generation_round == 1:
        for name in ('improvement_authorization', 'revalidation', 'reseal', 'renewed_go'):
            if getattr(policy, name) is None:
                issues.append('missing_' + name)
            else:
                _native(getattr(policy, name), ArtifactRef)
    case_map = {}
    for partition in cases:
        _record(partition, FrozenVerification)
        if partition.task_id in case_map or partition.task_id not in tasks:
            raise ValueError('duplicate/foreign frozen partition')
        task = tasks[partition.task_id]
        _native(partition.partition, ArtifactRef)
        hashes = tuple(_native(c, CaseBundle).case_sha256 for c in partition.cases)
        if (type(partition.cases) is not tuple or len(hashes) != 128 or len(set(hashes)) != 128
                or partition.program_id != task.program_id or partition.source_sha256 != task.oracle_source.sha256):
            raise ValueError('exact actual 128-case frozen task partition required')
        case_map[task.task_id] = (partition, frozenset(hashes))
    issues.extend('missing_frozen_partition:' + t for t in sorted(tasks.keys() - case_map.keys()))
    baseline_map = {}
    for baseline in baselines:
        _record(baseline, BaselineProof)
        if baseline.task_id in baseline_map or baseline.task_id not in tasks:
            raise ValueError('duplicate/foreign A baseline')
        _native(baseline.execution_receipt, ArtifactRef)
        _digest(baseline.candidate_sha256)
        _digest(baseline.partition_sha256)
        task = tasks[baseline.task_id]
        partition = case_map.get(task.task_id)
        if partition is None:
            issues.append('baseline_missing_partition:' + task.task_id)
        else:
            if (type(baseline.observations) is not tuple or len(baseline.observations) != 128
                    or {o.case_sha256 for o in baseline.observations} != partition[1]
                    or baseline.partition_sha256 != partition[0].partition.sha256):
                raise ValueError('complete A baseline must cover exactly the frozen128')
            for observation in baseline.observations:
                _comparison(observation, task, baseline.candidate_sha256, oracle_pins, candidate_pins, matching=True)
        baseline_map[task.task_id] = baseline
    issues.extend('missing_passing_A:' + t for t in sorted(tasks.keys() - baseline_map.keys()))
    operators = {o.operator_id: o for o in CATALOGUE}
    seen, covered = set(), set()
    counts = {s: 0 for s in STATUSES}
    for assessment in assessments:
        _record(assessment, MutantAssessment)
        if assessment.operator_id not in operators or assessment.operator_id in seen:
            raise ValueError('exact-once numbered catalogue required')
        seen.add(assessment.operator_id)
        if assessment.status not in STATUSES:
            raise ValueError('unknown mutant outcome; cannot silently reclassify survivors')
        if type(assessment.survivor_observations) is not tuple or type(assessment.extra_verifier_witnesses) is not tuple:
            raise ValueError('immutable outcome/witness record tuples required')
        if assessment.status != 'killed' and any(v is not None for v in
                (assessment.kill, assessment.frozen_case_sha256, assessment.observed_class, assessment.classification_review)):
            raise ValueError('kill evidence cannot be discarded by another status label')
        if assessment.status != 'survived' and assessment.survivor_observations:
            raise ValueError('survivor observations cannot be discarded by another status label')
        if assessment.status != 'equivalent-with-written-proof' and assessment.equivalence_proof is not None:
            raise ValueError('written equivalence belongs only to explicit equivalent status')
        counts[assessment.status] += 1
        if assessment.status in ('not_executed', 'pending'):
            issues.append(assessment.operator_id + ':' + assessment.status)
            continue
        mutation = assessment.mutation
        _record(mutation, MutationArtifact)
        if mutation.operator_id != assessment.operator_id:
            raise ValueError('actual exact-once mutation artifact required')
        task = tasks.get(mutation.binding.task_id)
        if (task is None or mutation.binding.program_id != task.program_id
                or mutation.binding.family_id != task.family_id or mutation.binding.split != 'dev'
                or mutation.binding.original_source_sha256 != task.original.sha256
                or mutation.binding.generator_sha256 != policy.generator_sha256
                or mutation.binding.runtime_sha256 != policy.runtime_sha256
                or mutation.binding.operator_source_sha256 != policy.catalogue_source_sha256
                or mutation.binding.plan_reader_sha256 != policy.plan_reader_sha256):
            raise ValueError('mutation task/source/generator/runtime scope drift')
        parent = mutation.changed_candidate[:mutation.byte_start] + mutation.before + mutation.changed_candidate[mutation.byte_start + len(mutation.after):]
        if mutate(parent, assessment.operator_id, binding=mutation.binding) != mutation:
            raise ValueError('mutation lineage is not the exact one declared transformation')
        baseline = baseline_map.get(task.task_id)
        if baseline is None or baseline.candidate_sha256 != mutation.binding.parent_candidate_sha256:
            issues.append(assessment.operator_id + ':missing_matching_passing_A')
        if assessment.validity_review is None:
            issues.append(assessment.operator_id + ':missing_nonauthor_validity')
        else:
            _native(assessment.validity_review, ArtifactRef)
        partition = case_map.get(task.task_id)
        if assessment.status == 'invalid':
            issues.append(assessment.operator_id + ':invalid_catalogue_requires_recorded_replacement')
        elif assessment.status == 'equivalent-with-written-proof':
            if assessment.equivalence_proof is None:
                issues.append(assessment.operator_id + ':missing_written_equivalence_proof')
            else:
                _native(assessment.equivalence_proof, ArtifactRef)
        elif assessment.status == 'survived':
            if partition is None:
                issues.append(assessment.operator_id + ':missing_frozen_partition')
            else:
                observations = assessment.survivor_observations
                if (type(observations) is not tuple or len(observations) != 128
                        or {o.case_sha256 for o in observations} != partition[1]):
                    raise ValueError('survivor requires all frozen128 observations; no denominator cuts')
                for observation in observations:
                    _comparison(observation, task, mutation.changed_candidate_sha256, oracle_pins, candidate_pins, matching=True)
            issues.append(assessment.operator_id + ':valid_nonequivalent_survivor')
        elif assessment.status == 'killed':
            if partition is None or assessment.frozen_case_sha256 not in partition[1]:
                issues.append(assessment.operator_id + ':kill_not_in_frozen_verification')
            if assessment.kill is None or assessment.kill.case_sha256 != assessment.frozen_case_sha256:
                issues.append(assessment.operator_id + ':missing_exact_kill_observation')
            else:
                comparison = _comparison(assessment.kill, task, mutation.changed_candidate_sha256, oracle_pins, candidate_pins, matching=False)
                if assessment.observed_class != operators[assessment.operator_id].intended_class:
                    issues.append(assessment.operator_id + ':intended_class_not_demonstrated')
                elif assessment.classification_review is None:
                    issues.append(assessment.operator_id + ':missing_nonauthor_class_proof')
                else:
                    _native(assessment.classification_review, ArtifactRef)
                    if partition is not None and assessment.frozen_case_sha256 in partition[1]:
                        covered.add(assessment.observed_class)
        # Additional verifier witnesses never satisfy a frozen kill or class gate.
        for witness in assessment.extra_verifier_witnesses:
            _native(witness, ArtifactRef)
    missing = operators.keys() - seen
    issues.extend('missing_operator:' + o for o in sorted(missing))
    classes = {o.intended_class for o in CATALOGUE}
    missing_classes = tuple(sorted(classes - covered))
    issues.extend('missing_target_class:' + c for c in missing_classes)
    if authority is None:
        issues.append('external_nonauthor_authority_missing')
    elif not issues:
        try:
            result = authority.verify(policy=policy, baselines=baselines, cases=cases, assessments=assessments)
            if result is not None:
                issues.append('external_authority_invalid_return')
        except Exception:
            issues.append('external_authority_refused_or_unavailable')
    unresolved = counts['pending'] + counts['not_executed'] + len(missing)
    status = ('not_fit' if counts['survived'] or counts['invalid'] else 'pending') if issues else 'structurally_eligible_under_external_authority'
    return InstrumentReport(policy.edition, status, tuple(issues), 20, counts['killed'],
                            counts['survived'], counts['invalid'], counts['equivalent-with-written-proof'],
                            unresolved, missing_classes)
