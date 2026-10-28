"""ASCII free-format tokenizer; it never imports or executes candidate source.

WORD text is uppercased and value preserves source spelling. NUMBER text/value
retain unsigned decimal spelling. STRING text includes source quotes and value
decodes doubled delimiters. SYMBOL text/value are identical; EOF uses empty text.
Signs are separate symbols. Reserved-word and production checks belong to parse.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from cobolmap.contracts import SourcePointer
from cobolmap.parse.models import ParseRefusal


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    value: str
    span: SourcePointer


def tokenize(source: str, filename: str = "program.cbl") -> tuple[Token, ...]:
    """Tokenize all source or raise a source-linked refusal, with EOF included."""
    # surrogatepass gives invalid Python strings a deterministic diagnostic hash;
    # accepted inputs always use ordinary, exact UTF-8 bytes (also ASCII).
    raw = source.encode("utf-8", errors="surrogatepass")
    digest = sha256(raw).hexdigest()
    offsets = [0]
    lines = [1]
    for char in source:
        offsets.append(offsets[-1] + len(char.encode("utf-8", errors="surrogatepass")))
        lines.append(lines[-1] + (char == "\n"))

    def span(start: int, end: int) -> SourcePointer:
        return SourcePointer(
            source_sha256=digest,
            filename=filename,
            line_start=lines[start],
            line_end=lines[end - 1] if end > start else lines[start],
            byte_start=offsets[start],
            byte_end=offsets[end],
        )

    def refuse(code: str, message: str, start: int, end: int) -> None:
        raise ParseRefusal(code, message, span(start, end))

    # Encoding has precedence even when invalid bytes occur in comments/literals.
    for index, char in enumerate(source):
        if char == "\r":
            if index + 1 >= len(source) or source[index + 1] != "\n":
                refuse("source_encoding", "Only LF or CRLF line endings are supported", index, index + 1)
        elif char != "\n" and not (32 <= ord(char) <= 126):
            refuse("source_encoding", "Source must contain printable ASCII and line endings only", index, index + 1)
    physical_lines = source.count("\n") + int(bool(source) and not source.endswith("\n"))
    if physical_lines > 200:
        index = 0
        for _ in range(200):
            index = source.index("\n", index) + 1
        refuse("source_limit", "Source exceeds 200 physical lines", index, len(source))

    tokens: list[Token] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char in " \r\n":
            index += 1
            continue
        if source.startswith("*>", index):
            newline = source.find("\n", index)
            index = len(source) if newline < 0 else newline
            continue
        start = index
        if char in "\"'":
            delimiter = char
            decoded: list[str] = []
            index += 1
            while index < len(source):
                char = source[index]
                if char in "\r\n":
                    refuse("unknown_token", "String literals cannot span lines", start, index)
                if char == delimiter:
                    if index + 1 < len(source) and source[index + 1] == delimiter:
                        decoded.append(delimiter)
                        index += 2
                        continue
                    index += 1
                    break
                decoded.append(char)
                index += 1
            else:
                refuse("unknown_token", "Unterminated string literal", start, len(source))
            tokens.append(Token("STRING", source[start:index], "".join(decoded), span(start, index)))
            continue
        if char.isalpha():
            index += 1
            while index < len(source) and (source[index].isalnum() or source[index] == "-"):
                index += 1
            word = source[start:index]
            if len(word) > 30 or word.endswith("-"):
                refuse("unknown_token", "Identifier exceeds 30 bytes or ends in a hyphen", start, index)
            tokens.append(Token("WORD", word.upper(), word, span(start, index)))
            continue
        if char.isdigit():
            index += 1
            while index < len(source) and source[index].isdigit():
                index += 1
            if index + 1 < len(source) and source[index] == "." and source[index + 1].isdigit():
                index += 2
                while index < len(source) and source[index].isdigit():
                    index += 1
            number = source[start:index]
            tokens.append(Token("NUMBER", number, number, span(start, index)))
            continue
        pair = source[index:index + 2]
        if pair in ("<>", "<=", ">="):
            index += 2
        elif char in "+-*/().=<>":
            index += 1
        else:
            refuse("unknown_token", f"Unsupported token character: {char!r}", start, start + 1)
        symbol = source[start:index]
        tokens.append(Token("SYMBOL", symbol, symbol, span(start, index)))
    tokens.append(Token("EOF", "", "", span(len(source), len(source))))
    return tuple(tokens)
