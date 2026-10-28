"""Exact plain-decimal money operations, independent of Decimal context.

Declarations have at most 128 integer and 128 fractional digits. Arithmetic
operands allow 256 integer digits and 128 fractional digits so ledger sums can
grow beyond declaration limits. Results remain exact and are never clamped;
a result beyond the arithmetic input limit cannot become a later operand.
Subtraction may return a debt.
This module performs no pricing or dispatch authorization.
"""

from collections.abc import Iterable
from decimal import Decimal
import re


class MoneyError(ValueError):
    """An invalid money representation."""

    code = "invalid_money"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _parts(value: str | Decimal, *, integer_limit: int = 128) -> tuple[int, int]:
    if isinstance(value, str):
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value) is None:
            raise MoneyError("Money must be nonnegative plain decimal text.")
        whole, _, fraction = value.partition(".")
        if len(whole) > integer_limit or len(fraction) > 128:
            raise MoneyError(f"Money exceeds the {integer_limit} integer/128 fractional digit limits.")
        return int(whole + fraction), len(fraction)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise MoneyError("Money must be finite.")
        sign, digits, exponent = value.as_tuple()
        if sign:
            raise MoneyError("Money must be nonnegative.")
        # Finite Decimal tuples always carry an integer exponent.
        if not isinstance(exponent, int):
            raise MoneyError("Money must have a finite decimal exponent.")
        fraction_length = max(0, -exponent)
        whole_length = max(1, len(digits) + exponent)
        if fraction_length > 128 or whole_length > integer_limit:
            raise MoneyError(f"Money exceeds the {integer_limit} integer/128 fractional digit limits.")
        coefficient = 0
        for digit in digits:
            coefficient = coefficient * 10 + digit
        if exponent >= 0:
            coefficient *= 10**exponent
        return coefficient, fraction_length
    raise MoneyError("Money must be decimal text or Decimal, never float/bool.")


def _render(coefficient: int, scale: int) -> str:
    if coefficient == 0:
        return "0"
    sign = "-" if coefficient < 0 else ""
    digits = str(abs(coefficient))
    if scale:
        digits = digits.zfill(scale + 1)
        digits = (digits[:-scale] + "." + digits[-scale:]).rstrip("0").rstrip(".")
    return sign + digits


def canonical_money(value: str | Decimal) -> str:
    """Validate nonnegative money and emit its minimal exact decimal text."""
    return _render(*_parts(value))


def sum_money(values: Iterable[str]) -> str:
    """Sum nonnegative decimal amounts without rounding."""
    total = 0
    scale = 0
    for value in values:
        coefficient, incoming_scale = _parts(value, integer_limit=256)
        common_scale = max(scale, incoming_scale)
        total = total * 10 ** (common_scale - scale)
        total += coefficient * 10 ** (common_scale - incoming_scale)
        scale = common_scale
    return _render(total, scale)


def add_money(a: str, b: str) -> str:
    """Add two nonnegative amounts exactly."""
    return sum_money((a, b))


def subtract_money(a: str, b: str) -> str:
    """Subtract nonnegative amounts; a negative remaining balance is retained."""
    left, left_scale = _parts(a, integer_limit=256)
    right, right_scale = _parts(b, integer_limit=256)
    scale = max(left_scale, right_scale)
    return _render(
        left * 10 ** (scale - left_scale) - right * 10 ** (scale - right_scale),
        scale,
    )


def compare_money(a: str, b: str) -> int:
    """Return -1, 0 or 1 for two nonnegative amounts."""
    left, left_scale = _parts(a, integer_limit=256)
    right, right_scale = _parts(b, integer_limit=256)
    scale = max(left_scale, right_scale)
    left *= 10 ** (scale - left_scale)
    right *= 10 ** (scale - right_scale)
    return (left > right) - (left < right)
