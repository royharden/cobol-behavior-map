"""Ordered, encoding-preserving field proposals; no observations or execution."""
from collections.abc import Callable, Iterator

from cobolmap.contracts import CaseBundle, MapField, sha256
from cobolmap.shared.codec import decode_record, encode_record
from cobolmap.shared.decimal_shim import DecimalValue, FieldSpec


def case_for(records: tuple[bytes, ...], *, input_present: bool) -> CaseBundle:
    preimage = b"M10-CASE-v1\0" + bytes([input_present]) + len(records).to_bytes(4, "big")
    preimage += b"".join(len(record).to_bytes(4, "big") + record for record in records)
    return CaseBundle(input_present=input_present, records=records, case_sha256=sha256(preimage))


def layout(fields: tuple[MapField, ...]) -> tuple[FieldSpec, ...]:
    """Delegate all width/sign/PIC/layout decisions to the accepted codec."""
    if any(field.storage != "input" or field.offset is None for field in fields):
        raise ValueError("input_fields_required")
    specs = tuple(FieldSpec(name=f.name, pic=f.pic, usage=f.usage, sign=f.sign,
                            offset=f.offset, width=f.width, scale=f.scale, digits=f.digits)
                  for f in fields)
    # Encoding followed by decoding also checks contiguity and duplicate names,
    # even for a missing-file or present-empty scenario with no record to decode.
    bindings = {f.name: "" if f.is_alpha else DecimalValue(0, f.scale) for f in specs}
    decode_record(encode_record(bindings, specs), specs)
    return tuple(sorted(specs, key=lambda field: field.offset))


def field_proposals(case: CaseBundle, specs: tuple[FieldSpec, ...], *,
                    permit: Callable[[], bool] | None = None,
                    keepgoing: Callable[[], bool] | None = None) -> Iterator[CaseBundle]:
    """One-field reductions, preserving position, width and fixed point scale.

    Numeric complexity strictly decreases in (magnitude, negative-sign). Alpha
    fields can become spaces. This finite proposal set claims no global minimum.
    """
    for index, record in enumerate(case.records):
        if keepgoing is not None and not keepgoing():
            return
        bindings = decode_record(record, specs)
        for spec in specs:
            if keepgoing is not None and not keepgoing():
                return
            value = bindings[spec.name]
            replacements: list[DecimalValue | str] = []
            if isinstance(value, str):
                if value.strip(" "):
                    replacements.append("")
            else:
                magnitude = abs(value.coefficient)
                replacements.append(DecimalValue(0, value.scale))
                if value.is_negative:
                    replacements.append(DecimalValue(magnitude, value.scale))
                digits = str(magnitude)
                for removed in range(1, len(digits)):
                    smaller = int(digits[removed:])
                    replacements.append(DecimalValue(-smaller if value.is_negative else smaller,
                                                     value.scale))
            for replacement in replacements:
                if keepgoing is not None and not keepgoing():
                    return
                if isinstance(value, DecimalValue) and isinstance(replacement, DecimalValue):
                    if (abs(replacement.coefficient), replacement.is_negative) >= (
                            abs(value.coefficient), value.is_negative):
                        continue
                # Admission/counting precedes encoding and construction, including
                # proposals that later prove byte-identical or previously seen.
                if permit is not None and not permit():
                    return
                if keepgoing is not None and not keepgoing():
                    return
                changed = dict(bindings)
                changed[spec.name] = replacement
                raw = encode_record(changed, specs)
                decode_record(raw, specs)
                if raw != record:
                    if keepgoing is not None and not keepgoing():
                        return
                    records = case.records[:index] + (raw,) + case.records[index + 1:]
                    yield case_for(records, input_present=case.input_present)
