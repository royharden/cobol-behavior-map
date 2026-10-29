"""Closed, inert preregistration declarations. Hash presence is not authority."""
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
import re

from cobolmap.contracts import ArtifactRef, RunPlan, canonical_json
from cobolmap.shared.callledger import CostBounds, PricePlan
from .schedule import build_schedule

COMMITMENT_KEYS = frozenset((
    'tasks', 'sources', 'corpus', 'compiler', 'runtime', 'shim', 'prompts',
    'models', 'prices', 'payloads', 'generator', 'execution_pins', 'seeds',
    'caps', 'authorization', 'go', 'exposure', 'admission', 'token_count_method',
    'canary_policy', 'custody', 'conformance',
))


def money(value: str) -> Fraction:
    if not isinstance(value, str) or re.fullmatch(r'(0|[1-9][0-9]{0,127})(\.[0-9]{1,128})?', value) is None:
        raise ValueError('nonnegative bounded plain decimal text required')
    return Fraction(value)


def decimal_text(value: Fraction) -> str:
    """Render exact finite decimal money without ambient Decimal rounding."""
    if value < 0:
        raise ValueError('negative money')
    denominator, twos, fives = value.denominator, 0, 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise ValueError('nonfinite decimal')
    scale = max(twos, fives)
    digits = str(value.numerator * 2 ** (scale - twos) * 5 ** (scale - fives))
    if not scale:
        return digits
    digits = digits.zfill(scale + 1)
    return (digits[:-scale] + '.' + digits[-scale:]).rstrip('0').rstrip('.')


@dataclass(frozen=True)
class Commitment:
    name: str
    artifact: ArtifactRef


@dataclass(frozen=True)
class ModelPrice:
    """All-category worst per-call bound; actual approved rates never default."""
    model_id: str | None = None
    input_per_token_usd: str | None = None
    output_per_token_usd: str | None = None
    additional_max_usd: str | None = None
    bounds: CostBounds | None = None
    # Source reference must define cache/reasoning overlaps and every fee.
    category_method: ArtifactRef | None = None


@dataclass(frozen=True)
class Preregistration:
    run_plan: RunPlan
    commitments: tuple[Commitment, ...] = ()
    primary: ModelPrice | None = None
    replication: ModelPrice | None = None
    bootstrap_seed: int = 20261027
    bootstrap_draws: int = 10000
    authorized_headroom_usd: str = '0'
    known_usd: str | None = None
    reserved_unknown_usd: str | None = None
    other_app_usd: str | None = None
    construction_exposure: str = 'private_source_before_admission'


@dataclass(frozen=True)
class PreregReport:
    issues: tuple[str, ...]
    maximum_calls: int
    worst_schedule_usd: str | None
    per_model_call_usd: tuple[str | None, str | None]
    ledger_price_plan: PricePlan | None
    dispatch_allowed: bool = False
    backend_status: str = 'backend_unverified'


def validate_prereg(registration: Preregistration) -> PreregReport:
    plan = registration.run_plan
    build_schedule(plan)
    issues = list(plan.missing_authority())
    pairs = registration.commitments
    names = [c.name for c in pairs]
    if len(names) != len(set(names)) or set(names) - COMMITMENT_KEYS:
        raise ValueError('duplicate or unknown prereg commitment')
    pins = {c.name: c.artifact for c in pairs}
    issues.extend('missing_commitment:' + key for key in sorted(COMMITMENT_KEYS - set(names)))
    if registration.bootstrap_seed != 20261027 or registration.bootstrap_draws != 10000:
        raise ValueError('bootstrap prereg drift')
    if registration.construction_exposure != plan.construction_exposure:
        raise ValueError('construction exposure drift')
    worst = []
    for index, price in enumerate((registration.primary, registration.replication)):
        label = ('primary', 'replication')[index]
        amount = None
        if price is None or any(v is None for v in (
                price.model_id, price.input_per_token_usd, price.output_per_token_usd,
                price.additional_max_usd, price.bounds, price.category_method)):
            issues.append('missing_all_fee_bounds:' + label)
        else:
            if (len(plan.model_ids) != 2 or price.model_id != plan.model_ids[index]
                    or price.bounds.model_id != price.model_id):
                raise ValueError('price/model slot drift')
            if not price.bounds.complete or price.bounds.input_tokens != 6000 or price.bounds.output_tokens != 2500:
                issues.append('incomplete_maximum_bounds:' + label)
            else:
                additional = money(price.additional_max_usd)
                if additional < money(price.bounds.other_fees_usd):
                    raise ValueError('additional bound excludes declared other fees')
                amount = 6000 * money(price.input_per_token_usd) + 2500 * money(price.output_per_token_usd) + additional
        worst.append(amount)
    total = None if any(w is None for w in worst) else 673 * sum(worst)
    if total is not None:
        pair = sum(worst)
        if pair > 1 or 384 * pair > 20 or 288 * pair > 17 or total > 40:
            issues.append('complete_schedule_exceeds_study_envelope')
    current = (registration.known_usd, registration.reserved_unknown_usd, registration.other_app_usd)
    headroom = money(registration.authorized_headroom_usd)
    if any(v is None for v in current):
        issues.append('current_liabilities_unavailable')
    elif total is not None and sum(money(v) for v in current) + total > headroom:
        issues.append('full_schedule_and_liabilities_unfunded')
    if headroom == 0:
        issues.append('current_authorized_headroom_zero')
    ledger_plan = None
    if total is not None and len(plan.model_ids) == 2 and 'prices' in pins:
        ledger_plan = PricePlan(sha256(canonical_json(plan)).hexdigest(), pins['prices'].sha256,
                                plan.model_ids, decimal_text(total))
    # No metadata, hash, flag or purported signature authenticates any of these.
    issues.extend(('external_authority_unverified', 'independent_custodian_missing',
                   'corpus_admission_unverified', 'backend_conformance_unverified',
                   'live_transport_absent'))
    return PreregReport(tuple(issues), 1346, None if total is None else decimal_text(total),
                        tuple(None if w is None else decimal_text(w) for w in worst), ledger_plan)
