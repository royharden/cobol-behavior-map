"""Closed B0 data language: no Python, expression strings, or model judging."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from .base import DecimalText, FrozenModel, Identifier, SourcePointer


class FieldRef(FrozenModel):
    scope: Literal["input", "output"]
    name: str


class LiteralValue(FrozenModel):
    kind: Literal["literal"] = "literal"
    value_type: Literal["decimal", "alpha"]
    value: str

    @model_validator(mode="after")
    def literal_shape(self) -> Self:
        import re
        if self.value_type == "decimal" and not re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", self.value):
            raise ValueError("exact decimal text required")
        if self.value_type == "alpha" and not all(32 <= ord(c) <= 126 for c in self.value):
            raise ValueError("printable ASCII literal required")
        return self


class FieldValue(FrozenModel):
    kind: Literal["field"] = "field"
    field: FieldRef


ScalarOperand = Annotated[LiteralValue | FieldValue, Field(discriminator="kind")]


class FieldComparison(FrozenModel):
    left: FieldRef
    comparator: Literal["=", "!=", "<", "<=", ">", ">="]
    right: ScalarOperand


class LinearTerm(FrozenModel):
    field: FieldRef
    coefficient: DecimalText


class LinearValue(FrozenModel):
    kind: Literal["linear"] = "linear"
    terms: tuple[LinearTerm, ...]
    constant: DecimalText = "0"
    scale: Annotated[int, Field(ge=0, le=4)]
    rounding: Literal["truncate_toward_zero", "nearest_ties_away"]


ClaimValue = Annotated[LiteralValue | FieldValue | LinearValue, Field(discriminator="kind")]


class OutputEquality(FrozenModel):
    field: FieldRef
    expected: ClaimValue

    @model_validator(mode="after")
    def output_only(self) -> Self:
        if self.field.scope != "output":
            raise ValueError("claim target must be observable output")
        return self


class Claim(FrozenModel):
    claim_id: Identifier
    span: SourcePointer
    guard: tuple[FieldComparison, ...] = ()
    assertion: OutputEquality
    evidence_mode: Literal["static"] = "static"
    status: Literal["untested"] = "untested"
