"""Shared construction shim. Runtime and compiler equivalence remain unverified."""

from .decimal_shim import (
    AssignmentResult,
    DecimalValue,
    FieldSpec,
    ShimError,
    arithmetic,
    compare,
    compute,
    decimal_value,
    move,
    nearest_ties_away,
    truncate_toward_zero,
)
from .codec import decode_record, encode_record, format_display, parse_display

__all__ = [
    "AssignmentResult", "DecimalValue", "FieldSpec", "ShimError", "arithmetic",
    "compare", "compute", "decimal_value", "move", "nearest_ties_away",
    "truncate_toward_zero", "decode_record", "encode_record", "format_display",
    "parse_display",
]
