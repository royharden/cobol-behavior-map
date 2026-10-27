"""Exact decimal construction model; compiler parity is UNVERIFIED.

Hypotheses awaiting pinned probes: intermediates are exact rational values;
assignment truncates toward zero unless ROUNDED uses nearest ties away; signed
zero survives scale conversion; numeric MOVE to unsigned takes magnitude (H5),
while arithmetic to unsigned rejects negative nonzero as a size error.
Overflow and divide-by-zero preserve a supplied previous receiver. A handler
gets a controlled size-error result; without one the result carries a fault.
COMP-3 participates numerically but this module supplies no packed codec.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Context, Decimal, ROUND_DOWN, ROUND_HALF_UP, localcontext
from fractions import Fraction
import re
from typing import Mapping, Sequence


class ShimError(ValueError):
    """Typed refusal, never a successful assignment or oracle observation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class DecimalValue:
    coefficient: int
    scale: int
    negative_zero: bool = False

    def __post_init__(self):
        if type(self.coefficient) is not int or type(self.scale) is not int:
            raise ShimError("shim_type", "coefficient and scale must be integers")
        if not 0 <= self.scale <= 4096 or abs(self.coefficient) >= 10 ** 4096:
            raise ShimError("shim_precision_unpinned", "decimal exceeds construction bound")
        if type(self.negative_zero) is not bool or (self.coefficient and self.negative_zero):
            raise ShimError("shim_type", "negative_zero is valid only for zero")

    @property
    def is_negative(self) -> bool:
        return self.coefficient < 0 or self.negative_zero

    def __str__(self) -> str:
        digits = str(abs(self.coefficient)).zfill(self.scale + 1)
        body = digits if not self.scale else digits[:-self.scale] + "." + digits[-self.scale:]
        return ("-" if self.is_negative else "") + body


def decimal_value(value: str | int | DecimalValue) -> DecimalValue:
    if isinstance(value, DecimalValue):
        return value
    if type(value) is int:
        return DecimalValue(value, 0)
    if not isinstance(value, str):
        raise ShimError("shim_type", "exact decimal text/integer required; floats forbidden")
    if len(value) > 4096 or not re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value):
        raise ShimError("shim_type", "invalid bounded decimal literal")
    negative = value.startswith("-")
    body = value.lstrip("+-")
    whole, _, fraction = body.partition(".")
    coefficient = int(whole + fraction)
    return DecimalValue(-coefficient if negative else coefficient, len(fraction), negative and coefficient == 0)


@dataclass(frozen=True)
class FieldSpec:
    name: str
    pic: str
    usage: str = "DISPLAY"
    sign: str | None = None
    offset: int = 0
    width: int | None = None
    scale: int | None = None
    digits: int | None = None

    def __post_init__(self):
        if not isinstance(self.name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,29}", self.name) or self.name.endswith("-"):
            raise ShimError("shim_layout", "invalid field name")
        if not isinstance(self.pic, str) or len(self.pic) > 64 or not isinstance(self.usage, str):
            raise ShimError("shim_layout", "PIC and usage must be text")
        pic = self.pic.upper()
        usage = self.usage.upper()
        sign = self.sign.upper() if isinstance(self.sign, str) else self.sign
        if sign == "NONE":
            sign = None
        if sign == "SIGN LEADING SEPARATE":
            sign = "LEADING SEPARATE"
        alpha = re.fullmatch(r"X\(([1-9][0-9]*)\)", pic)
        numeric = re.fullmatch(r"(S?)9\(([1-9][0-9]*)\)(?:V9\(([1-9][0-9]*)\))?", pic)
        if not alpha and not numeric:
            raise ShimError("shim_layout", "PIC is outside the bounded subset")
        if usage not in ("DISPLAY", "COMP-3") or type(self.offset) is not int or self.offset < 0:
            raise ShimError("shim_layout", "invalid usage or offset")
        if alpha:
            digits, scale, width = 0, 0, int(alpha.group(1))
            if width > 256 or usage != "DISPLAY" or sign is not None:
                raise ShimError("shim_layout", "invalid alphanumeric layout")
        else:
            whole, scale = int(numeric.group(2)), int(numeric.group(3) or 0)
            digits = whole + scale
            signed = bool(numeric.group(1))
            if digits > 8 or scale > 4:
                raise ShimError("shim_layout", "numeric digit/scale bounds exceeded")
            if sign not in (None, "LEADING SEPARATE") or (sign and (not signed or usage != "DISPLAY")):
                raise ShimError("shim_layout", "invalid sign clause")
            # Internal signed DISPLAY without a separate sign has numeric meaning
            # only here; its embedded-sign bytes are intentionally not modeled.
            width = digits + int(sign == "LEADING SEPARATE") if usage == "DISPLAY" else (digits + 2) // 2
        for label, declared, actual in (("width", self.width, width), ("scale", self.scale, scale), ("digits", self.digits, digits)):
            if declared is not None and (type(declared) is not int or declared != actual):
                raise ShimError("shim_layout", label + " disagrees with PIC/usage")
            object.__setattr__(self, label, actual)
        object.__setattr__(self, "pic", pic)
        object.__setattr__(self, "usage", usage)
        object.__setattr__(self, "sign", sign)

    @property
    def is_alpha(self) -> bool:
        return self.pic.startswith("X")

    @property
    def signed(self) -> bool:
        return self.pic.startswith("S")

    @classmethod
    def from_mapping(cls, mapping: Mapping) -> FieldSpec:
        if not isinstance(mapping, Mapping):
            raise ShimError("shim_layout", "field must be a mapping")
        allowed = {"name", "pic", "usage", "sign", "offset", "width", "scale", "digits"}
        if set(mapping) - allowed or not {"name", "pic"} <= set(mapping):
            raise ShimError("shim_layout", "unknown or missing field attributes")
        return cls(**dict(mapping))


@dataclass(frozen=True)
class AssignmentResult:
    value: DecimalValue | str | None
    stored_bytes_or_null: bytes | None
    size_error: bool = False
    fault_or_null: ShimError | None = None


def _quantize(value, scale, rounding):
    value = decimal_value(value)
    if type(scale) is not int or not 0 <= scale <= 4096:
        raise ShimError("shim_type", "invalid destination scale")
    precision = max(len(str(abs(value.coefficient))), scale + value.scale + 1) + 4
    # Explicit context: the caller's ambient precision and rounding never apply.
    with localcontext(Context(prec=precision, rounding=rounding, Emin=-999999, Emax=999999)):
        number = Decimal(str(value))
        quantized = number.quantize(Decimal((0, (1,), -scale)), rounding=rounding)
        parts = quantized.as_tuple()
        coefficient = int("".join(str(d) for d in parts.digits))
        return DecimalValue(-coefficient if parts.sign else coefficient, scale, bool(parts.sign and coefficient == 0))


def truncate_toward_zero(value, scale) -> DecimalValue:
    return _quantize(value, scale, ROUND_DOWN)


def nearest_ties_away(value, scale) -> DecimalValue:
    return _quantize(value, scale, ROUND_HALF_UP)


def _fraction(value) -> Fraction:
    value = decimal_value(value)
    return Fraction(value.coefficient, 10 ** value.scale)


def _store(value, destination):
    from .codec import format_display
    internal = destination.usage == "COMP-3" or (destination.signed and destination.sign is None)
    return None if internal else format_display(value, destination)


def _failure(code, message, destination, previous, handler=False, size_error=False):
    stored = None
    if previous is not None:
        # Preservation is exact: an invalid previous receiver is a fault, not a repair.
        try:
            stored = _store(previous, destination)
        except ShimError as error:
            return AssignmentResult(previous, None, size_error, error)
    fault = None if handler and size_error else ShimError(code, message)
    return AssignmentResult(previous, stored, size_error, fault)


def _assign_fraction(value, negative_zero, destination, rounded, handler, previous):
    if destination.is_alpha:
        raise ShimError("shim_type", "arithmetic receiver must be numeric")
    numerator = abs(value.numerator) * 10 ** destination.scale
    coefficient, remainder = divmod(numerator, value.denominator)
    if rounded and remainder * 2 >= value.denominator:
        coefficient += 1
    negative = value < 0 or (not value and negative_zero)
    if coefficient >= 10 ** destination.digits or (coefficient and negative and not destination.signed):
        return _failure("size_error", "receiver cannot represent result (unverified preservation policy)", destination, previous, handler, True)
    result = DecimalValue(-coefficient if negative else coefficient, destination.scale, negative and coefficient == 0)
    # Hypothesis: an unsigned receiver loses zero's sign, never its nonzero sign.
    if result.negative_zero and not destination.signed:
        result = DecimalValue(0, destination.scale)
    return AssignmentResult(result, _store(result, destination))


def move(value, source_spec, destination_spec, *, previous_destination=None):
    """Hypotheses: numeric MOVE truncates; unsigned MOVE takes magnitude (H5).

    Alpha MOVE pads/truncates on the right. Internal embedded-sign/packed
    receivers have no codec bytes; their numeric assignment is still modeled.
    """
    destination = destination_spec
    try:
        if source_spec is not None and source_spec.is_alpha != destination.is_alpha:
            raise ShimError("shim_type", "mixed numeric/alphanumeric MOVE refused")
        if destination.is_alpha:
            if not isinstance(value, str) or any(not 32 <= ord(c) <= 126 for c in value):
                raise ShimError("shim_type", "alpha MOVE requires printable ASCII")
            result = value[:destination.width].ljust(destination.width)
            return AssignmentResult(result, _store(result, destination))
        numeric = decimal_value(value)
        if not destination.signed and numeric.is_negative:
            numeric = DecimalValue(abs(numeric.coefficient), numeric.scale)
        return _assign_fraction(_fraction(numeric), numeric.is_negative, destination, False, False, previous_destination)
    except ShimError as error:
        return _failure(error.code, error.message, destination, previous_destination)


def arithmetic(op, operands: Sequence, destination, rounded=False, size_error_handler=False, previous_destination=None):
    """Exact rational construction hypothesis; no intermediate compiler parity claim.

    Subtract operands are (receiver, subtrahend); divide operands are (a,b)
    for a/b. Multiply/add accept exactly two operands. COMPUTE uses compute().
    """
    try:
        if op not in {"add", "subtract", "multiply", "divide"} or len(operands) != 2:
            raise ShimError("unsupported_expression", "unsupported operation or arity")
        left, right = (decimal_value(item) for item in operands)
        a, b = _fraction(left), _fraction(right)
        if op == "divide" and not b:
            return _failure("division_zero", "division by zero", destination, previous_destination, size_error_handler, True)
        if op == "add":
            result, negzero = a + b, left.is_negative and right.is_negative
        elif op == "subtract":
            result, negzero = a - b, left.is_negative and not right.is_negative
        elif op == "multiply":
            result, negzero = a * b, left.is_negative != right.is_negative
        else:
            result, negzero = a / b, left.is_negative != right.is_negative
        return _assign_fraction(result, negzero, destination, rounded, size_error_handler, previous_destination)
    except ShimError as error:
        return _failure(error.code, error.message, destination, previous_destination)


def compute(expression, bindings, destination, rounded=False, size_error_handler=False, previous_destination=None):
    """Evaluate a closed literal/reference/binary tree, at most three operators.

    Exact rational intermediates and operation-specific zero signs are hypotheses.
    There is no eval, executable string, function node or ambient decimal context.
    """
    count = 0
    active = set()

    def visit(node, depth=0):
        nonlocal count
        if not isinstance(node, Mapping) or depth > 7 or id(node) in active:
            raise ShimError("unsupported_expression", "invalid/cyclic expression")
        active.add(id(node))
        try:
            kind = node.get("kind")
            if kind == "literal" and set(node) == {"kind", "value"}:
                value = decimal_value(node["value"])
                return _fraction(value), value.is_negative
            if kind == "reference" and set(node) == {"kind", "name"}:
                name = node["name"]
                if not isinstance(name, str) or name not in bindings:
                    raise ShimError("pointer_unresolved", "unresolved COMPUTE reference")
                value = decimal_value(bindings[name])
                return _fraction(value), value.is_negative
            if kind != "binary" or set(node) != {"kind", "operator", "left", "right"}:
                raise ShimError("unsupported_expression", "unknown expression shape")
            count += 1
            if count > 3:
                raise ShimError("unsupported_expression", "COMPUTE exceeds three operators")
            a, an = visit(node["left"], depth + 1)
            b, bn = visit(node["right"], depth + 1)
            op = node["operator"]
            if op == "+":
                result, negative = a + b, an and bn
            elif op == "-":
                result, negative = a - b, an and not bn
            elif op == "*":
                result, negative = a * b, an != bn
            elif op == "/":
                if not b:
                    raise ShimError("division_zero", "division by zero")
                result, negative = a / b, an != bn
            else:
                raise ShimError("unsupported_expression", "unknown binary operator")
            return result, result < 0 or (not result and negative)
        finally:
            active.remove(id(node))

    try:
        result, negative = visit(expression)
        return _assign_fraction(result, negative, destination, rounded, size_error_handler, previous_destination)
    except ShimError as error:
        zero = error.code == "division_zero"
        return _failure(error.code, error.message, destination, previous_destination, size_error_handler, zero)


def compare(left, comparator, right) -> bool:
    """Compare numeric values or printable ASCII text without mixed coercion.

    Alpha operands are space-padded to equal width (unverified COBOL hypothesis).
    Numeric zero signs compare equal.
    """
    if isinstance(left, DecimalValue) and isinstance(right, DecimalValue):
        a, b = _fraction(left), _fraction(right)
    elif isinstance(left, str) and isinstance(right, str):
        if any(not 32 <= ord(c) <= 126 for c in left + right):
            raise ShimError("shim_type", "comparison requires printable ASCII")
        width = max(len(left), len(right))
        a, b = left.ljust(width), right.ljust(width)
    else:
        raise ShimError("shim_type", "comparison requires a matching typed pair")
    if comparator == "=":
        return a == b
    if comparator in ("<>", "!="):
        return a != b
    if comparator == "<":
        return a < b
    if comparator == "<=":
        return a <= b
    if comparator == ">":
        return a > b
    if comparator == ">=":
        return a >= b
    raise ShimError("unsupported_expression", "unknown comparator")
