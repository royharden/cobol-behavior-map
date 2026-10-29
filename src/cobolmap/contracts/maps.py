"""Source-linked static map facade shared with parser/mapping consumers."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from .base import FrozenModel, Sha256, SourcePointer, relative_name
from .claim_models import Claim

HazardId = Literal["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"]


class MapField(FrozenModel):
    name: str
    pic: str
    usage: Literal["DISPLAY", "COMP-3"]
    sign: Literal["none", "leading_separate", "embedded", "packed"]
    offset: Annotated[int, Field(ge=0)] | None
    width: Annotated[int, Field(ge=1)]
    scale: Annotated[int, Field(ge=0, le=4)]
    digits: Annotated[int, Field(ge=0, le=8)]
    initial: str | None = None
    storage: Literal["input", "output", "working"]
    span: SourcePointer
    record_name: str | None = None

    @model_validator(mode="after")
    def representation(self) -> Self:
        import re
        match = re.fullmatch(r"(X|S9|9)\(([1-9][0-9]*)\)(?:V9\(([1-9][0-9]*)\))?", self.pic)
        if match is None or len(match[2]) > 4 or len(match[3] or "") > 1:
            raise ValueError("unsupported map PIC")
        kind, whole, scale = match[1], int(match[2]), int(match[3] or 0)
        if kind == "X":
            if (match[3] is not None or whole > 256 or self.usage != "DISPLAY"
                    or self.sign != "none" or self.scale != 0 or self.digits != 0 or self.width != whole):
                raise ValueError("alpha map layout")
        else:
            digits = whole + scale
            if digits > 8 or scale != self.scale or digits != self.digits:
                raise ValueError("numeric map digits/scale")
            signed = kind == "S9"
            if self.usage == "COMP-3":
                if self.storage != "working" or self.sign != ("packed" if signed else "none"):
                    raise ValueError("packed metadata is working storage only")
                if self.width != (digits + 2) // 2:
                    raise ValueError("packed width declaration hypothesis")
            else:
                allowed = ("leading_separate",) if self.storage != "working" else ("embedded", "leading_separate")
                if self.sign not in (allowed if signed else ("none",)):
                    raise ValueError("DISPLAY sign metadata")
                if self.width != digits + (self.sign == "leading_separate"):
                    raise ValueError("DISPLAY width")
        if self.storage != "working" and self.offset is None:
            raise ValueError("external field offset required")
        return self


class MapParagraph(FrozenModel):
    name: str
    span: SourcePointer
    statement_spans: tuple[SourcePointer, ...] = ()


class ControlEdge(FrozenModel):
    source: str
    target: str
    kind: Literal["perform", "branch", "sequence"]
    span: SourcePointer


class Effect(FrozenModel):
    kind: Literal["read", "write", "assign", "display", "return", "control"]
    span: SourcePointer
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    description: str = ""


class Hazard(FrozenModel):
    hazard_id: HazardId
    span: SourcePointer
    description: str
    fields: tuple[str, ...] = ()
    status: Literal["static_warning"] = "static_warning"


class BehaviorMap(FrozenModel):
    source_sha256: Sha256
    filename: str
    fields: tuple[MapField, ...] = ()
    paragraphs: tuple[MapParagraph, ...] = ()
    edges: tuple[ControlEdge, ...] = ()
    effects: tuple[Effect, ...] = ()
    hazards: tuple[Hazard, ...] = ()
    claims: tuple[Claim, ...] = ()
    evidence_mode: Literal["static"] = "static"
    status: Literal["runtime_unverified"] = "runtime_unverified"

    @model_validator(mode="after")
    def bind_pointers(self) -> Self:
        relative_name(self.filename)
        spans = [f.span for f in self.fields] + [p.span for p in self.paragraphs]
        spans += [s for p in self.paragraphs for s in p.statement_spans]
        spans += [x.span for xs in (self.edges, self.effects, self.hazards, self.claims) for x in xs]
        if any(s.source_sha256 != self.source_sha256 or s.filename != self.filename for s in spans):
            raise ValueError("map contains foreign source pointers")
        if len({f.name for f in self.fields}) != len(self.fields):
            raise ValueError("duplicate map field")
        return self
