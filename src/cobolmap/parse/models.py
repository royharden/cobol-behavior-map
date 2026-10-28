"""Immutable, source-linked intermediate representation for the bounded grammar."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from cobolmap.contracts import SourcePointer


class ParseRefusal(Exception):
    """A deterministic refusal carrying the original source location."""

    def __init__(self, code: str, message: str, span: SourcePointer) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.span = span


_NODE_KEYS = {
    "literal": {"value", "literal_type"},
    "reference": {"name"},
    "binary": {"op", "left", "right"},
    "compare": {"op", "left", "right"},
    "boolean": {"op", "left", "right"},
    "move": {"value", "target"},
    "add": {"value", "target", "rounded", "has_size_error"},
    "subtract": {"value", "target", "rounded", "has_size_error"},
    "multiply": {"value", "target", "rounded", "has_size_error"},
    "divide": {"left", "right", "target", "rounded", "has_size_error"},
    "compute": {"expression", "target", "rounded", "has_size_error"},
    "if": {"condition"},
    "perform": {"paragraph", "until", "max_iterations"},
    "open": {"file", "mode"},
    "read": {"file"},
    "write": {"record"},
    "close": {"file"},
    "display": {"values"},
    "stop": set(),
}


def _freeze(value: Any) -> Any:
    """Copy containers so callers cannot mutate an IR through retained aliases."""
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("IR argument mapping keys must be strings")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, bool, IRNode)):
        return value
    raise TypeError(f"Unsupported IR argument value: {type(value).__name__}")


@dataclass(frozen=True)
class IRNode:
    kind: str
    span: SourcePointer
    args: Mapping[str, Any]
    body: tuple[IRNode, ...] = ()
    otherwise: tuple[IRNode, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in _NODE_KEYS:
            raise ValueError(f"Unknown IR node kind: {self.kind}")
        if set(self.args) != _NODE_KEYS[self.kind]:
            raise ValueError(f"Invalid argument keys for IR node: {self.kind}")
        object.__setattr__(self, "args", _freeze(self.args))
        object.__setattr__(self, "body", tuple(self.body))
        object.__setattr__(self, "otherwise", tuple(self.otherwise))
        if any(not isinstance(node, IRNode) for node in (*self.body, *self.otherwise)):
            raise TypeError("IR bodies must contain IRNode values")


@dataclass(frozen=True)
class FieldLayout:
    name: str
    pic: str
    usage: str
    sign: str
    offset: int
    width: int
    scale: int
    digits: int
    initial: str | None
    span: SourcePointer
    storage: str
    record_name: str | None = None


@dataclass(frozen=True)
class Paragraph:
    name: str
    span: SourcePointer
    statements: tuple[IRNode, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "statements", tuple(self.statements))
        if any(not isinstance(node, IRNode) for node in self.statements):
            raise TypeError("Paragraph statements must contain IRNode values")


@dataclass(frozen=True)
class FileBinding:
    name: str
    record_name: str
    status_name: str
    direction: str
    path: str


@dataclass(frozen=True)
class ProgramIR:
    source_sha256: str
    filename: str
    fields: tuple[FieldLayout, ...]
    paragraphs: tuple[Paragraph, ...]
    source: str
    files: tuple[FileBinding, ...]
    program_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", tuple(self.fields))
        object.__setattr__(self, "paragraphs", tuple(self.paragraphs))
        object.__setattr__(self, "files", tuple(self.files))
        for values, expected in (
            (self.fields, FieldLayout),
            (self.paragraphs, Paragraph),
            (self.files, FileBinding),
        ):
            if any(not isinstance(value, expected) for value in values):
                raise TypeError(f"ProgramIR requires {expected.__name__} values")
