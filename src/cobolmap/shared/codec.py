"""Strict ASCII DISPLAY codec; no quantization or external COMP-3 support.

Construction policy, runtime unverified: numeric signs occupy a leading byte,
decimal points are implied, negative zero is preserved for signed receivers.
Record fields must form a contiguous, nonoverlapping layout from offset zero.
"""

from collections.abc import Mapping, Sequence

from .decimal_shim import DecimalValue, FieldSpec, ShimError, decimal_value


def _display(field):
    if not isinstance(field, FieldSpec) or field.usage != "DISPLAY":
        raise ShimError("shim_layout", "external codec requires DISPLAY FieldSpec")
    if field.signed and field.sign != "LEADING SEPARATE":
        raise ShimError("shim_layout", "external signed DISPLAY requires separate sign")


def parse_display(raw: bytes, field: FieldSpec) -> DecimalValue | str:
    _display(field)
    if type(raw) is not bytes or len(raw) != field.width:
        raise ShimError("shim_layout", "field bytes must have exact declared width")
    if field.is_alpha:
        if any(byte < 32 or byte > 126 for byte in raw):
            raise ShimError("shim_type", "alpha field contains nonprintable ASCII")
        return raw.decode("ascii")
    negative = False
    digits = raw
    if field.signed:
        if raw[:1] not in (b"+", b"-"):
            raise ShimError("shim_type", "signed DISPLAY needs explicit leading sign")
        negative, digits = raw[:1] == b"-", raw[1:]
    if not digits or any(byte < 48 or byte > 57 for byte in digits):
        raise ShimError("shim_type", "numeric DISPLAY requires ASCII digits")
    coefficient = int(digits)
    return DecimalValue(-coefficient if negative else coefficient, field.scale, negative and coefficient == 0)


def format_display(value, field: FieldSpec) -> bytes:
    """Encode only exact representable values; rounding belongs to assignment."""
    _display(field)
    if field.is_alpha:
        if not isinstance(value, str) or len(value) > field.width or any(not 32 <= ord(c) <= 126 for c in value):
            raise ShimError("shim_unrepresentable", "alpha value is not representable")
        return value.ljust(field.width).encode("ascii")
    value = decimal_value(value)
    coefficient = abs(value.coefficient)
    if value.scale > field.scale:
        coefficient, remainder = divmod(coefficient, 10 ** (value.scale - field.scale))
        if remainder:
            raise ShimError("shim_unrepresentable", "encoding would quantize numeric value")
    else:
        coefficient *= 10 ** (field.scale - value.scale)
    if coefficient >= 10 ** field.digits or (value.is_negative and not field.signed):
        raise ShimError("shim_unrepresentable", "numeric value/sign exceeds field")
    sign = (b"-" if value.is_negative else b"+") if field.signed else b""
    return sign + str(coefficient).zfill(field.digits).encode("ascii")


def _layout(fields: Sequence[FieldSpec]):
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)) or not fields or len(fields) > 32:
        raise ShimError("shim_layout", "record needs one to 32 declared fields")
    for field in fields:
        _display(field)
    ordered = sorted(fields, key=lambda field: field.offset)
    width, names = 0, set()
    for field in ordered:
        folded = field.name.upper()
        if field.offset != width or folded in names:
            raise ShimError("shim_layout", "record has gaps, overlaps or duplicate names")
        names.add(folded)
        width += field.width
    return ordered, width


def decode_record(raw: bytes, fields: Sequence[FieldSpec]) -> dict:
    ordered, width = _layout(fields)
    if type(raw) is not bytes or len(raw) != width:
        raise ShimError("shim_layout", "record bytes must have exact declared width")
    return {field.name: parse_display(raw[field.offset:field.offset + field.width], field) for field in ordered}


def encode_record(bindings: Mapping, fields: Sequence[FieldSpec]) -> bytes:
    ordered, _ = _layout(fields)
    if not isinstance(bindings, Mapping) or any(field.name not in bindings for field in ordered):
        raise ShimError("pointer_unresolved", "record field missing from bindings")
    return b"".join(format_display(bindings[field.name], field) for field in ordered)
