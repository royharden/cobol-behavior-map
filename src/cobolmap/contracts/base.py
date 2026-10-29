"""Immutable structural contracts. Hash integrity is never authenticity."""
import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
DecimalText = Annotated[str, StringConstraints(pattern=r"^-?[0-9]+(?:\.[0-9]+)?$")]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              allow_inf_nan=False, ser_json_bytes="hex", val_json_bytes="hex")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(model: FrozenModel) -> bytes:
    """Stable JSON: bytes are lowercase hex, tuples arrays, nulls retained."""
    return json.dumps(model.model_dump(mode="json"), sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def relative_name(name: str) -> str:
    if (not name or "\\" in name or ":" in name or name.startswith("/")
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ("", ".", "..") for p in name.split("/"))
            or str(PurePosixPath(name)) != name):
        raise ValueError("relative forward-slash artifact name required")
    return name


class ArtifactRef(FrozenModel):
    path: str
    sha256: Sha256
    byte_length: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def path_shape(self) -> Self:
        relative_name(self.path)
        return self

    def check_bytes(self, raw: bytes) -> None:
        if sha256(raw) != self.sha256 or (self.byte_length is not None and len(raw) != self.byte_length):
            raise ValueError("artifact raw-byte pin mismatch")


class SourcePointer(FrozenModel):
    source_sha256: Sha256
    filename: str
    line_start: Annotated[int, Field(ge=1)]
    line_end: Annotated[int, Field(ge=1)]
    byte_start: Annotated[int, Field(ge=0)]
    byte_end: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        relative_name(self.filename)
        if self.line_end < self.line_start or self.byte_end < self.byte_start:
            raise ValueError("reversed source span")
        return self

    def resolve(self, source: bytes, filename: str | None = None) -> bytes:
        if sha256(source) != self.source_sha256 or (filename is not None and filename != self.filename):
            raise ValueError("pointer_unresolved: source identity")
        if self.byte_end > len(source):
            raise ValueError("pointer_unresolved: byte bounds")
        source.decode("utf-8")
        source[:self.byte_start].decode("utf-8")
        source[:self.byte_end].decode("utf-8")
        start = source[:self.byte_start].count(b"\n") + 1
        end = source[:max(self.byte_start, self.byte_end - 1)].count(b"\n") + 1
        if (start, end) != (self.line_start, self.line_end):
            raise ValueError("pointer_unresolved: line/byte disagreement")
        return source[self.byte_start:self.byte_end]
