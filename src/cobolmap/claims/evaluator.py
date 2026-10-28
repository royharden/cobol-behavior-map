"""Closed B0 evaluation with exact rational arithmetic, independent of Decimal context."""
from fractions import Fraction

from cobolmap.contracts import (
    Claim, FieldRef, FieldValue, LinearValue, LiteralValue,
)
from .models import ClaimEvaluation, FieldBinding


class Untestable(ValueError):
    """Missing, ambiguous or mixed-type field data cannot satisfy a claim."""


def _number(text: str) -> Fraction:
    # LiteralValue/DecimalText validate grammar; Fraction preserves all decimal digits.
    return Fraction(text)


def _bindings(items: tuple[FieldBinding, ...], scope: str) -> dict[tuple[str, str], LiteralValue]:
    result: dict[tuple[str, str], LiteralValue] = {}
    for item in items:
        key = (item.field.scope, item.field.name)
        if item.field.scope != scope or key in result:
            raise Untestable("ambiguous_or_wrong_scope_binding")
        result[key] = item.value
    return result


def _lookup(field: FieldRef, values: dict[tuple[str, str], LiteralValue]) -> LiteralValue:
    try:
        return values[(field.scope, field.name)]
    except KeyError as error:
        raise Untestable("missing_or_unobservable_field:" + field.scope + ":" + field.name) from error


def _scalar(value: LiteralValue | FieldValue,
            values: dict[tuple[str, str], LiteralValue]) -> LiteralValue:
    return value if isinstance(value, LiteralValue) else _lookup(value.field, values)


def _compare(left: LiteralValue, right: LiteralValue, comparator: str) -> bool:
    if left.value_type != right.value_type:
        raise Untestable("shim_type:mixed_field_types")
    a = _number(left.value) if left.value_type == "decimal" else left.value
    b = _number(right.value) if right.value_type == "decimal" else right.value
    if comparator == "=": return a == b
    if comparator == "!=": return a != b
    if comparator == "<": return a < b
    if comparator == "<=": return a <= b
    if comparator == ">": return a > b
    if comparator == ">=": return a >= b
    raise Untestable("unsupported_comparator")


def _guard(claim: Claim, values: dict[tuple[str, str], LiteralValue]) -> bool:
    # Resolve every guard operand even if an earlier conjunct is false.
    comparisons = tuple(_compare(_lookup(part.left, values), _scalar(part.right, values),
                                 part.comparator) for part in claim.guard)
    return all(comparisons)


def _linear(value: LinearValue, values: dict[tuple[str, str], LiteralValue]) -> Fraction:
    total = _number(value.constant)
    for term in value.terms:
        operand = _lookup(term.field, values)
        if operand.value_type != "decimal":
            raise Untestable("shim_type:linear_alpha_operand")
        total += _number(term.coefficient) * _number(operand.value)
    scaled = abs(total) * (10 ** value.scale)
    units, remainder = divmod(scaled.numerator, scaled.denominator)
    if value.rounding == "nearest_ties_away" and 2 * remainder >= scaled.denominator:
        units += 1
    return Fraction(-units if total < 0 else units, 10 ** value.scale)


def evaluate_claim(claim: Claim, inputs: tuple[FieldBinding, ...],
                   outputs: tuple[FieldBinding, ...]) -> ClaimEvaluation:
    """Evaluate typed data only. Satisfied/violated here carry no empirical status."""
    try:
        values = _bindings(inputs, "input") | _bindings(outputs, "output")
        if not _guard(claim, values):
            return ClaimEvaluation(status="guard_false", guard_satisfied=False)
        actual = _lookup(claim.assertion.field, values)
        expected = claim.assertion.expected
        if isinstance(expected, LinearValue):
            if actual.value_type != "decimal":
                raise Untestable("shim_type:linear_alpha_target")
            equal = _number(actual.value) == _linear(expected, values)
        else:
            equal = _compare(actual, _scalar(expected, values), "=")
        return ClaimEvaluation(status="satisfied" if equal else "violated", guard_satisfied=True)
    except (Untestable, ValueError, ZeroDivisionError) as error:
        return ClaimEvaluation(status="untestable", issues=(str(error),))
