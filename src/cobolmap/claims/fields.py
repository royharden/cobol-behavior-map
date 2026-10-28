"""Exact external DISPLAY witness decoding; COMP-3 is deliberately unsupported."""
import re
from fractions import Fraction

from cobolmap.contracts import FieldRef, LiteralValue, MapField


def validate_layout(layout: MapField, field: FieldRef, source: bytes, filename: str) -> None:
    declaration = layout.span.resolve(source, filename).decode("utf-8")
    if layout.name != field.name or layout.storage != field.scope:
        raise ValueError("field_layout_name_or_scope")
    if layout.usage != "DISPLAY" or layout.offset is None:
        raise ValueError("external_display_layout_required")
    pic = re.fullmatch(r"(?:(X)\(([1-9][0-9]*)\)|(S)?9\(([1-9][0-9]*)\)(?:V9\(([1-9][0-9]*)\))?)", layout.pic)
    if pic is None:
        raise ValueError("unsupported_field_pic")
    alpha, alpha_width, signed, integer_width, fraction_width = pic.groups()
    digits = 0 if alpha else int(integer_width) + int(fraction_width or "0")
    scale = int(fraction_width or "0")
    width = int(alpha_width) if alpha else digits + bool(signed)
    sign = "leading_separate" if signed else "none"
    if (layout.width != width or layout.scale != scale or layout.digits != digits
            or layout.sign != sign or digits > 8):
        raise ValueError("field_pic_width_scale_sign_disagreement")
    # Resolve both the pointer identity and declaration tokens. Full parser/layout
    # authenticity remains the admitted caller's responsibility, never a hash claim.
    name = re.escape(layout.name)
    pic_text = re.escape(layout.pic)
    if not re.search(r"(?<![A-Z0-9-])" + name + r"\s+PIC(?:TURE)?\s+" + pic_text
                     + r"(?![A-Z0-9(])", declaration, re.IGNORECASE):
        raise ValueError("field_declaration_name_pic_unresolved")
    if signed and not re.search(r"\bSIGN(?:\s+IS)?\s+LEADING\s+SEPARATE(?:\s+CHARACTER)?\b",
                                declaration, re.IGNORECASE):
        raise ValueError("field_declaration_sign_unresolved")
    if re.search(r"\bCOMP(?:UTATIONAL)?(?:-[0-9]+)?\b", declaration, re.IGNORECASE):
        raise ValueError("packed_or_non_display_declaration")


def display_matches(raw: bytes, layout: MapField, value: LiteralValue) -> bool:
    if len(raw) != layout.width:
        return False
    if layout.pic.startswith("X"):
        return (value.value_type == "alpha" and all(32 <= b <= 126 for b in raw)
                and raw == value.value.encode("ascii"))
    if value.value_type != "decimal":
        return False
    negative = False
    digits = raw
    if layout.sign == "leading_separate":
        if raw[:1] not in (b"+", b"-"):
            return False
        negative = raw[:1] == b"-"
        digits = raw[1:]
    if len(digits) != layout.digits or not digits or not all(48 <= b <= 57 for b in digits):
        return False
    unscaled = int(digits)
    decoded = Fraction(-unscaled if negative else unscaled, 10 ** layout.scale)
    # Preserve explicit signed zero correspondence; no silent erasure/normalization.
    if decoded == 0 and value.value.startswith("-") != negative:
        return False
    return decoded == Fraction(value.value)


def validate_decoded_value(layout: MapField, value: LiteralValue) -> None:
    """Check a trusted decoded input against its explicit external field shape."""
    if layout.pic.startswith("X"):
        if value.value_type != "alpha" or len(value.value) != layout.width:
            raise ValueError("decoded_input_alpha_width_or_type")
        return
    if value.value_type != "decimal":
        raise ValueError("decoded_input_numeric_type")
    scaled = Fraction(value.value) * (10 ** layout.scale)
    if (scaled.denominator != 1 or abs(scaled) >= 10 ** layout.digits
            or (layout.sign == "none" and value.value.startswith("-"))):
        raise ValueError("decoded_input_numeric_layout")
