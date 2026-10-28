"""Closed, source-bound parser for the private M10 subset. Never executes source."""
from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation, localcontext
from hashlib import sha256
from typing import Any

from cobolmap.contracts import SourcePointer

from .lexer import Token, tokenize
from .models import FieldLayout, FileBinding, IRNode, Paragraph, ParseRefusal, ProgramIR


_VERBS = frozenset({"MOVE", "ADD", "SUBTRACT", "MULTIPLY", "DIVIDE", "COMPUTE",
                    "IF", "PERFORM", "OPEN", "READ", "WRITE", "CLOSE", "DISPLAY", "STOP"})
_RESERVED = _VERBS | frozenset("IDENTIFICATION DIVISION PROGRAM-ID ENVIRONMENT INPUT-OUTPUT "
    "SECTION FILE-CONTROL SELECT ASSIGN TO ORGANIZATION IS LINE SEQUENTIAL FILE STATUS DATA "
    "FD WORKING-STORAGE PROCEDURE PIC X S9 V9 USAGE COMP-3 SIGN LEADING SEPARATE VALUE "
    "ROUNDED ON SIZE ERROR END-ADD END-SUBTRACT END-MULTIPLY END-DIVIDE END-COMPUTE "
    "ELSE END-IF UNTIL AT END END-READ INPUT OUTPUT RUN AND OR BY FROM GIVING RETURN-CODE".split())
_FORBIDDEN = frozenset("GO CALL COPY OCCURS REDEFINES EVALUATE VARYING REMAINDER NOT "
    "COMP COMP-5 BINARY ACCEPT CURRENT-DATE FUNCTION EXEC SQL CICS THRU THROUGH "
    "CORRESPONDING EXTEND I-O UPON ADVANCING".split())


class Parser:
    def __init__(self, source: str, filename: str, manifest: Mapping[str, Any] | None):
        self.source = source
        self.filename = filename
        self.tokens = tokenize(source, filename)
        self.digest = sha256(source.encode("utf-8")).hexdigest()
        self.i = 0
        self.fields: list[FieldLayout] = []
        self.files: list[FileBinding] = []
        self.paragraphs: list[Paragraph] = []
        self.names: set[str] = set()
        self.groups: dict[str, str] = {}
        self.working_offset = 0
        self.manifest = manifest
        self.in_handler = False

    @property
    def token(self) -> Token:
        return self.tokens[self.i]

    def span(self, first: Token | SourcePointer, last: Token | SourcePointer | None = None) -> SourcePointer:
        a = first.span if isinstance(first, Token) else first
        z = last or self.tokens[max(0, self.i - 1)]
        b = z.span if isinstance(z, Token) else z
        return SourcePointer(source_sha256=self.digest, filename=self.filename,
                             line_start=a.line_start, line_end=b.line_end,
                             byte_start=a.byte_start, byte_end=b.byte_end)

    def fail(self, code: str, message: str, token: Token | None = None) -> None:
        raise ParseRefusal(code, message, (token or self.token).span)

    def take(self) -> Token:
        token = self.token
        if token.kind != "EOF":
            self.i += 1
        return token

    def at(self, text: str) -> bool:
        return self.token.text == text

    def accept(self, text: str) -> bool:
        if self.at(text):
            self.take()
            return True
        return False

    def expect(self, text: str) -> Token:
        if not self.at(text):
            self.fail("out_of_subset" if self.token.text in _FORBIDDEN else "syntax_error", f"Expected {text}")
        return self.take()

    def words(self, text: str) -> None:
        for word in text.split():
            self.expect(word)

    def identifier(self, *, declare: bool = False, main: bool = False) -> str:
        token = self.token
        if token.kind != "WORD" or token.text in _RESERVED or (token.text == "MAIN" and not main):
            self.fail("syntax_error", "Expected a non-reserved identifier")
        self.take()
        name = token.text
        if declare:
            if name in self.names:
                self.fail("duplicate_name", f"Duplicate name {name}", token)
            self.names.add(name)
        return name

    def node(self, kind: str, start: Token | SourcePointer, args: dict[str, Any],
             body: tuple[IRNode, ...] = (), otherwise: tuple[IRNode, ...] = ()) -> IRNode:
        return IRNode(kind=kind, span=self.span(start), args=args, body=body, otherwise=otherwise)

    def program(self) -> ProgramIR:
        # Forbidden constructs in strings/comments are data; only WORD tokens count.
        for token in self.tokens:
            if token.kind == "WORD" and token.text in _FORBIDDEN:
                self.fail("out_of_subset", f"Unsupported construct {token.text}", token)
        self.words("IDENTIFICATION DIVISION . PROGRAM-ID .")
        program_id = self.identifier(declare=True)
        self.words(". ENVIRONMENT DIVISION . INPUT-OUTPUT SECTION . FILE-CONTROL .")
        selections: list[tuple[str, str, str, str]] = []
        for direction, path in (("input", "input.dat"), ("output", "output.dat")):
            self.expect("SELECT")
            name = self.identifier(declare=True)
            self.words("ASSIGN TO")
            if self.token.kind != "STRING" or self.token.value != path:
                self.fail("external_path", f"Only {path} is supported")
            self.take()
            self.words("ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS")
            status = self.identifier()
            self.expect(".")
            selections.append((name, direction, path, status))
        self.words("DATA DIVISION . FILE SECTION .")
        for name, direction, path, status in selections:
            self.expect("FD")
            fd = self.identifier()
            if fd != name:
                self.fail("file_contract", "FD must match its ordered SELECT")
            self.expect(".")
            self.expect("01")
            record = self.identifier(declare=True)
            self.expect(".")
            self.groups[record] = direction
            offset = 0
            count = 0
            while self.accept("05"):
                field = self.elementary(direction, record, offset)
                offset += field.width
                count += 1
            if not count:
                self.fail("file_contract", "An FD record must have elementary children")
            self.files.append(FileBinding(name=name, record_name=record, status_name=status,
                                          direction=direction, path=path))
        self.words("WORKING-STORAGE SECTION .")
        while self.accept("01"):
            start = self.token
            name = self.identifier(declare=True)
            if self.accept("."):
                self.groups[name] = "working"
                count = 0
                while self.accept("05"):
                    field = self.elementary("working", name, self.working_offset)
                    self.working_offset += field.width
                    count += 1
                if not count:
                    self.fail("syntax_error", "Empty working group", start)
            else:
                field = self.elementary("working", None, self.working_offset, name, start)
                self.working_offset += field.width
        self.words("PROCEDURE DIVISION .")
        start = self.token
        self.expect("MAIN")
        if "MAIN" in self.names:
            self.fail("duplicate_name", "MAIN already declared", start)
        self.names.add("MAIN")
        self.expect(".")
        main: list[IRNode] = []
        while not self.at("STOP"):
            if self.token.kind == "EOF" or self.at("."):
                self.fail("control_flow", "MAIN must end with STOP RUN")
            main.append(self.statement())
        stop = self.take()
        self.words("RUN .")
        main.append(self.node("stop", stop, {}))
        self.paragraphs.append(Paragraph(name="MAIN", span=self.span(start), statements=tuple(main)))
        while self.token.kind != "EOF":
            start = self.token
            name = self.identifier(declare=True)
            self.expect(".")
            body = self.block({"."})
            self.expect(".")
            self.paragraphs.append(Paragraph(name=name, span=self.span(start), statements=body))
            if len(self.paragraphs) > 8:
                self.fail("source_limit", "At most eight paragraphs", start)
        result = ProgramIR(source_sha256=self.digest, filename=self.filename,
            fields=tuple(self.fields), paragraphs=tuple(self.paragraphs), source=self.source,
            files=tuple(self.files), program_id=program_id)
        from .validation import validate_program
        return validate_program(result, self.manifest)

    def integer(self) -> int:
        token = self.token
        if token.kind != "NUMBER" or not token.value.isdigit():
            self.fail("bad_picture", "Expected a positive integer")
        if len(token.value.lstrip("0")) > 3:
            self.fail("field_limit", "Picture length exceeds supported bounds")
        self.take()
        value = int(token.value.lstrip("0") or "0")
        if value < 1:
            self.fail("bad_picture", "Picture lengths must be positive", token)
        return value

    def elementary(self, storage: str, record: str | None, offset: int,
                   name: str | None = None, start: Token | None = None) -> FieldLayout:
        start = start or self.token
        name = name or self.identifier(declare=True)
        self.expect("PIC")
        prefix = self.take().text
        if prefix not in {"X", "9", "S9"}:
            self.fail("bad_picture", "Only X(n), 9(n), S9(n) pictures are supported", start)
        self.expect("(")
        whole = self.integer()
        self.expect(")")
        scale = 0
        if self.accept("V9"):
            if prefix == "X":
                self.fail("bad_picture", "X cannot have scale", start)
            self.expect("(")
            scale = self.integer()
            self.expect(")")
        digits = 0 if prefix == "X" else whole + scale
        if (prefix == "X" and whole > 256) or digits > 8 or scale > 4:
            self.fail("field_limit", "PIC exceeds field bounds", start)
        pic = f"{prefix}({whole})" + (f"V9({scale})" if scale else "")
        usage = "DISPLAY"
        if self.accept("USAGE"):
            self.expect("IS")
            if self.token.text not in {"DISPLAY", "COMP-3"}:
                self.fail("bad_layout_or_sign", "Unsupported USAGE")
            usage = self.take().text
        elif self.token.text in {"DISPLAY", "COMP-3"}:
            usage = self.take().text
        signed = prefix == "S9"
        sign = "embedded" if signed and storage == "working" else "none"
        if self.accept("SIGN"):
            self.words("LEADING SEPARATE")
            if not signed or usage != "DISPLAY":
                self.fail("bad_layout_or_sign", "Separate sign needs signed DISPLAY", start)
            sign = "leading_separate"
        if (storage != "working" and (usage != "DISPLAY" or (signed and sign != "leading_separate"))) or (prefix == "X" and usage != "DISPLAY"):
            self.fail("bad_layout_or_sign", "Unsupported external/alpha representation", start)
        if usage == "COMP-3":
            sign = "packed" if signed else "none"
        initial = None
        if self.accept("VALUE"):
            literal = self.atom()
            if literal.kind != "literal":
                self.fail("literal_range", "VALUE requires a literal", start)
            initial = str(literal.args["value"])
            alpha = literal.args["literal_type"] == "alpha"
            if alpha != (prefix == "X"):
                self.fail("type_mismatch", "VALUE type does not match PIC", start)
            if alpha:
                if len(initial) > whole:
                    self.fail("literal_range", "VALUE exceeds X width", start)
            else:
                try:
                    with localcontext() as context:
                        context.prec = 64
                        value = Decimal(initial)
                        unscaled = value.scaleb(scale)
                        if unscaled != unscaled.to_integral_value() or abs(unscaled) > 10 ** digits - 1 or (not signed and value.is_signed()):
                            self.fail("literal_range", "VALUE is not representable", start)
                except InvalidOperation:
                    self.fail("literal_range", "Invalid VALUE", start)
        self.expect(".")
        width = whole if prefix == "X" else ((digits + 2) // 2 if usage == "COMP-3" else digits + (sign == "leading_separate"))
        field = FieldLayout(name=name, pic=pic, usage=usage, sign=sign, offset=offset,
            width=width, scale=scale, digits=digits, initial=initial, span=self.span(start),
            storage=storage, record_name=record)
        self.fields.append(field)
        if len(self.fields) > 32:
            self.fail("source_limit", "At most32 elementary fields", start)
        return field

    def atom(self) -> IRNode:
        start = self.token
        sign = ""
        if self.token.text in {"+", "-"}:
            sign = self.take().text
            if self.token.kind != "NUMBER":
                self.fail("syntax_error", "A unary sign requires numeric literal")
        if self.token.kind == "NUMBER":
            value = sign + self.take().value
            return self.node("literal", start, {"value": value, "literal_type": "numeric"})
        if self.token.kind == "STRING" and not sign:
            return self.node("literal", start, {"value": self.take().value, "literal_type": "alpha"})
        if not sign:
            name = self.identifier()
            return self.node("reference", start, {"name": name})
        self.fail("syntax_error", "Expected atom")
        raise AssertionError("unreachable")

    def expression(self, minimum: int = 0) -> IRNode:
        if self.accept("("):
            left = self.expression()
            self.expect(")")
        else:
            left = self.atom()
        precedence = {"+": 1, "-": 1, "*": 2, "/": 2}
        while self.token.text in precedence and precedence[self.token.text] >= minimum:
            op = self.take().text
            right = self.expression(precedence[op] + 1)
            left = self.node("binary", left.span, {"op": op, "left": left, "right": right})
        return left

    def comparison(self) -> IRNode:
        left = self.atom()
        if self.token.text not in {"=", "<>", "<", "<=", ">", ">="}:
            self.fail("syntax_error", "Expected explicit comparison")
        op = self.take().text
        right = self.atom()
        return self.node("compare", left.span, {"op": op, "left": left, "right": right})

    def condition(self, minimum: int = 0) -> IRNode:
        left = self.comparison()
        precedence = {"OR": 1, "AND": 2}
        while self.token.text in precedence and precedence[self.token.text] >= minimum:
            op = self.take().text
            right = self.condition(precedence[op] + 1)
            left = self.node("boolean", left.span, {"op": op, "left": left, "right": right})
        return left

    def block(self, ends: set[str]) -> tuple[IRNode, ...]:
        body: list[IRNode] = []
        while self.token.text not in ends:
            if self.token.kind == "EOF":
                self.fail("syntax_error", "Unclosed statement/block")
            body.append(self.statement())
        return tuple(body)

    def statement(self) -> IRNode:
        start = self.token
        verb = self.take().text
        if verb == "MOVE":
            value = self.atom()
            self.expect("TO")
            target = self.take().text if self.at("RETURN-CODE") else self.identifier()
            return self.node("move", start, {"value": value, "target": target})
        if verb in {"ADD", "SUBTRACT", "MULTIPLY", "DIVIDE", "COMPUTE"}:
            if verb == "COMPUTE":
                target = self.identifier()
                self.expect("=")
                expression = self.expression()
                args: dict[str, Any] = {"expression": expression, "target": target}
                def operators(node: IRNode) -> int:
                    return 0 if node.kind != "binary" else 1 + operators(node.args["left"]) + operators(node.args["right"])
                if operators(expression) > 3:
                    self.fail("compute_limit", "At most3 COMPUTE operators", start)
            else:
                value = self.atom()
                self.expect({"ADD": "TO", "SUBTRACT": "FROM", "MULTIPLY": "BY", "DIVIDE": "BY"}[verb])
                if verb == "DIVIDE":
                    right = self.atom()
                    self.expect("GIVING")
                    args = {"left": value, "right": right, "target": self.identifier()}
                else:
                    args = {"value": value, "target": self.identifier()}
            args["rounded"] = self.accept("ROUNDED")
            handler: tuple[IRNode, ...] = ()
            has_handler = self.accept("ON")
            args["has_size_error"] = has_handler
            if has_handler:
                if self.in_handler:
                    self.fail("out_of_subset", "Nested ON SIZE ERROR is unsupported", start)
                self.words("SIZE ERROR")
                self.in_handler = True
                handler = self.block({"END-" + verb})
                self.in_handler = False
            self.expect("END-" + verb)
            return self.node(verb.lower(), start, args, handler)
        if verb == "IF":
            condition = self.condition()
            body = self.block({"ELSE", "END-IF"})
            otherwise = self.block({"END-IF"}) if self.accept("ELSE") else ()
            self.expect("END-IF")
            return self.node("if", start, {"condition": condition}, body, otherwise)
        if verb == "PERFORM":
            paragraph = self.identifier()
            until = self.condition() if self.accept("UNTIL") else None
            return self.node("perform", start, {"paragraph": paragraph, "until": until, "max_iterations": None})
        if verb == "OPEN":
            if self.token.text not in {"INPUT", "OUTPUT"}:
                self.fail("file_contract", "OPEN INPUT/OUTPUT only")
            mode = self.take().text
            return self.node("open", start, {"file": self.identifier(), "mode": mode})
        if verb == "READ":
            name = self.identifier()
            self.words("AT END")
            body = self.block({"END-READ"})
            self.expect("END-READ")
            return self.node("read", start, {"file": name}, body)
        if verb == "WRITE":
            return self.node("write", start, {"record": self.identifier()})
        if verb == "CLOSE":
            return self.node("close", start, {"file": self.identifier()})
        if verb == "DISPLAY":
            values = []
            while self.token.kind == "STRING" or (self.token.kind == "WORD" and self.token.text not in _VERBS | _RESERVED):
                values.append(self.atom())
            if not values:
                self.fail("syntax_error", "DISPLAY requires literal/field", start)
            return self.node("display", start, {"values": tuple(values)})
        if verb == "STOP":
            self.fail("control_flow", "STOP RUN is only MAIN's terminal statement", start)
        self.fail("out_of_subset" if verb in _FORBIDDEN or start.kind == "WORD" else "syntax_error", f"Unsupported statement {verb}", start)
        raise AssertionError("unreachable")


def parse(source: str, filename: str = "program.cbl", *,
          manifest: Mapping[str, Any] | None = None) -> ProgramIR:
    """Parse every source token or raise a stable source-bound refusal."""
    if (not filename or filename.startswith("/") or ":" in filename or "\\" in filename
            or any(part in {"", ".", ".."} for part in filename.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in filename)):
        diagnostic = SourcePointer(source_sha256=sha256(source.encode("utf-8", errors="surrogatepass")).hexdigest(),
            filename="program.cbl", line_start=1, line_end=1, byte_start=0, byte_end=0)
        raise ParseRefusal("external_path", "A safe relative logical filename is required", diagnostic)
    parser = Parser(source, filename, manifest)
    try:
        return parser.program()
    except RecursionError:
        parser.fail("source_limit", "Parser nesting exceeds safe static analysis depth")
        raise AssertionError("unreachable")
