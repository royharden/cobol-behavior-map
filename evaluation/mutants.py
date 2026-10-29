"""Twenty DEV operator definitions; no mutant instance or outcome ships here."""
from dataclasses import asdict, dataclass, fields
from fractions import Fraction
from hashlib import sha256
from math import gcd
import re
import json

from .mutant_plan import MutationRefusal, need, parse_candidate


@dataclass(frozen=True)
class MutationOperator:
    operator_id: str
    intended_class: str
    theme: str
    description: str


CATALOGUE_VERSION = 'm10-dev-operators-v1'
CATALOGUE = (
    MutationOperator('M01', 'padding', 'alpha', 'Append one ASCII space to an alpha literal.'),
    MutationOperator('M02', 'padding', 'alpha', 'Remove one trailing ASCII space from an alpha literal.'),
    MutationOperator('M03', 'sign', 'decimal', 'Negate one nonzero numeric literal.'),
    MutationOperator('M04', 'sign', 'decimal', 'Remove negative sign from one signed working VALUE.'),
    MutationOperator('M05', 'scale', 'decimal', 'Multiply one nonzero numeric literal by ten.'),
    MutationOperator('M06', 'scale', 'decimal', 'Divide one nonzero numeric working VALUE by ten.'),
    MutationOperator('M07', 'last_place/truncation', 'decimal', 'Drop the last nonzero fractional literal digit.'),
    MutationOperator('M08', 'last_place/rounding', 'decimal', 'Disable one ROUNDED arithmetic clause.'),
    MutationOperator('M09', 'last_place/rounding', 'decimal', 'Enable one unrounded arithmetic clause.'),
    MutationOperator('M10', 'size_error', 'decimal', 'Disable one arithmetic size-error handler flag.'),
    MutationOperator('M11', 'value', 'decimal', 'Increment one numeric literal by one.'),
    MutationOperator('M12', 'alpha', 'alpha', 'Replace first character of one nonempty alpha literal.'),
    MutationOperator('M13', 'record_count', 'status', 'Delete one WRITE statement from its body.'),
    MutationOperator('M14', 'record_count', 'status', 'Duplicate one WRITE statement in its body.'),
    MutationOperator('M15', 'alpha', 'status', 'Change EOF literal10 to success00 in a status comparison.'),
    MutationOperator('M16', 'alpha', 'status', 'Change working file-status VALUE00 to10.'),
    MutationOperator('M17', 'value', 'window', 'Replace numeric century literal1900 by2000.'),
    MutationOperator('M18', 'value', 'window', 'Increment a0..98 cutoff compared with YEAR/YY reference.'),
    MutationOperator('M19', 'value', 'control', 'Replace one strict less-than comparison with less-or-equal.'),
    MutationOperator('M20', 'value', 'decimal', 'Replace one COMPUTE binary addition by subtraction.'),
)


@dataclass(frozen=True)
class MutationBinding:
    task_id: str
    program_id: str
    family_id: str
    split: str
    original_source_sha256: str
    parent_candidate_sha256: str
    generator_sha256: str
    runtime_sha256: str
    operator_source_sha256: str
    plan_reader_sha256: str


@dataclass(frozen=True)
class MutationArtifact:
    binding: MutationBinding
    catalogue_version: str
    operator_id: str
    operator_sha256: str
    intended_class: str
    target_path: tuple
    byte_start: int
    byte_end: int
    before: bytes
    after: bytes
    before_sha256: str
    after_sha256: str
    changed_candidate: bytes
    changed_candidate_sha256: str
    status: str = 'not_executed'
    validity: str = 'pending_external_nonauthor_review'


def _number(value):
    if type(value) is not str or re.fullmatch(r'[+-]?[0-9]{1,18}(\.[0-9]{1,18})?', value) is None:
        return None
    return Fraction(value)


def _decimal(value: Fraction) -> str:
    negative = value < 0
    value = abs(value)
    denominator, scale = value.denominator, 0
    while denominator != 1 and scale <= 40:
        denominator //= gcd(denominator, 10)
        scale += 1
    need(denominator == 1, 'nonfinite numeric edit')
    units = value * 10 ** scale
    need(units.denominator == 1, 'inexact numeric edit')
    digits = str(units.numerator).zfill(scale + 1)
    text = digits if not scale else (digits[:-scale] + '.' + digits[-scale:]).rstrip('0').rstrip('.')
    return ('-' if negative else '') + text


def _targets(parsed, operator_id):
    """Return actual syntactically eligible single edits, never inferred coverage."""
    result = []
    status_names = {file['status'] for file in parsed.plan['files']}
    arithmetic = {'add', 'subtract', 'multiply', 'divide', 'compute'}
    for path, value in parsed.values.items():
        if type(value) is not dict:
            continue
        kind = value.get('kind')
        if kind == 'literal':
            text = value['value']
            numeric = _number(text) if value['literal_type'] == 'numeric' else None
            change = None
            if value['literal_type'] == 'alpha':
                if operator_id == 'M01': change = text + ' '
                if operator_id == 'M02' and text.endswith(' '): change = text[:-1]
                if operator_id == 'M12' and text: change = ('B' if text[0] == 'A' else 'A') + text[1:]
            if numeric is not None:
                if operator_id == 'M03' and numeric: change = _decimal(-numeric)
                if operator_id == 'M05' and numeric: change = _decimal(numeric * 10)
                if operator_id == 'M07' and '.' in text and text[-1] != '0': change = text[:-1].rstrip('.')
                if operator_id == 'M11': change = _decimal(numeric + 1)
                if operator_id == 'M17' and numeric == 1900: change = '2000'
            if change is not None:
                result.append((path + ('value',), change))
        if set(value) >= {'name', 'pic', 'initial', 'storage'} and value['storage'] == 'working':
            initial = value['initial']
            number = _number(initial) if not value['pic'].startswith('X') else None
            if operator_id == 'M04' and value['pic'].startswith('S') and number is not None and number < 0:
                result.append((path + ('initial',), _decimal(-number)))
            if operator_id == 'M06' and number:
                result.append((path + ('initial',), _decimal(number / 10)))
            if operator_id == 'M16' and value['name'] in status_names and initial == '00':
                result.append((path + ('initial',), '10'))
        if kind in arithmetic:
            if operator_id == 'M08' and value['rounded'] is True:
                result.append((path + ('rounded',), False))
            if operator_id == 'M09' and value['rounded'] is False:
                result.append((path + ('rounded',), True))
            if operator_id == 'M10' and value['has_size_error'] is True:
                result.append((path + ('has_size_error',), False))
        if kind == 'compare':
            left, right = value['left'], value['right']
            for atom, other, side in ((left, right, 'right'), (right, left, 'left')):
                if atom.get('kind') != 'reference' or other.get('kind') != 'literal':
                    continue
                if operator_id == 'M15' and atom['name'] in status_names and other['literal_type'] == 'alpha' and other['value'] == '10':
                    result.append((path + (side, 'value'), '00'))
                number = _number(other['value']) if other['literal_type'] == 'numeric' else None
                # A syntactic window hypothesis, never semantic hazard proof.
                if operator_id == 'M18' and ('YEAR' in atom['name'] or atom['name'] == 'YY') and number is not None and number.denominator == 1 and 0 <= number <= 98:
                    result.append((path + (side, 'value'), _decimal(number + 1)))
            if operator_id == 'M19' and value['op'] == '<':
                result.append((path + ('op',), '<='))
        if operator_id == 'M20' and kind == 'binary' and value['op'] == '+' and 'expression' in path:
            result.append((path + ('op',), '-'))
        if operator_id in ('M13', 'M14') and kind == 'write':
            parent_path, index = path[:-1], path[-1]
            body = parsed.values.get(parent_path)
            if type(body) is list and type(index) is int:
                changed = body[:index] + (body[index + 1:] if operator_id == 'M13' else [value] + body[index:])
                result.append((parent_path, changed))
    return result


def mutate(candidate: bytes, operator_id: str, *, binding: MutationBinding) -> MutationArtifact:
    """Construct exactly one inert edit later; no file writes or candidate execution."""
    need(type(binding) is MutationBinding and set(binding.__dict__) == {f.name for f in fields(MutationBinding)}
         and binding.split == 'dev', 'only exact closed DEV binding accepted')
    need(all(type(v) is str and v for v in (binding.task_id, binding.program_id, binding.family_id)), 'task/program/family identities required')
    for digest in (binding.original_source_sha256, binding.parent_candidate_sha256,
                   binding.generator_sha256, binding.runtime_sha256,
                   binding.operator_source_sha256, binding.plan_reader_sha256):
        need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'actual raw hash pins required')
    operators = {o.operator_id: o for o in CATALOGUE}
    need(operator_id in operators, 'unknown numbered operator')
    need(type(candidate) is bytes and sha256(candidate).hexdigest() == binding.parent_candidate_sha256,
         'parent candidate hash mismatch')
    parsed = parse_candidate(candidate)
    need(parsed.plan['source_sha256'] == binding.original_source_sha256, 'original source identity mismatch')
    eligible = _targets(parsed, operator_id)
    need(len(eligible) == 1, 'operator requires exactly one eligible edit; absent/ambiguous applicability')
    path, changed = eligible[0]
    need(parsed.values[path] != changed, 'no-op mutation refused')
    start, end, before = parsed.segment(path)
    after = repr(changed).encode('utf-8')
    need(before != after, 'identical target bytes refused')
    output = candidate[:start] + after + candidate[end:]
    reparsed = parse_candidate(output)
    need(reparsed.plan['source_sha256'] == parsed.plan['source_sha256']
         and reparsed.plan['filename'] == parsed.plan['filename'], 'source/header hashes cannot be rewritten')
    # One closed subtree edit; every other literal value is inherited unchanged.
    need(reparsed.values[path] == changed, 'changed target mismatch')
    operator = operators[operator_id]
    operator_pin = sha256(json.dumps({'definition': asdict(operator), 'version': CATALOGUE_VERSION,
                         'source_sha256': binding.operator_source_sha256,
                         'plan_reader_sha256': binding.plan_reader_sha256}, sort_keys=True,
                         separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return MutationArtifact(binding, CATALOGUE_VERSION, operator_id, operator_pin, operator.intended_class,
                            path, start, end, before, after, sha256(before).hexdigest(),
                            sha256(after).hexdigest(), output, sha256(output).hexdigest())
