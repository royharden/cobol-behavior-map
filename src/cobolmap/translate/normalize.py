"""Closed conversion from DL1's source-linked IR to inert translation data."""
from collections.abc import Mapping
import hashlib
import re

from cobolmap.parse.models import IRNode, ProgramIR
from cobolmap.shared.decimal_shim import FieldSpec, decimal_value


class TranslationRefusal(ValueError):
    def __init__(self, code, message, span=None):
        super().__init__(message)
        self.code, self.message, self.span = code, message, span


def need(condition, code, message, span=None):
    if not condition:
        raise TranslationRefusal(code, message, span)


KEYS = {
    "literal": {"value", "literal_type"}, "reference": {"name"},
    "binary": {"op", "left", "right"}, "compare": {"op", "left", "right"},
    "boolean": {"op", "left", "right"}, "move": {"value", "target"},
    **{kind: {"value", "target", "rounded", "has_size_error"} for kind in ("add", "subtract", "multiply")},
    "divide": {"left", "right", "target", "rounded", "has_size_error"},
    "compute": {"expression", "target", "rounded", "has_size_error"},
    "if": {"condition"}, "perform": {"paragraph", "until", "max_iterations"},
    "open": {"file", "mode"}, "read": {"file"}, "write": {"record"},
    "close": {"file"}, "display": {"values"}, "stop": set(),
}
ARITHMETIC = frozenset(("add", "subtract", "multiply", "divide", "compute"))


def normalize(program):
    need(isinstance(program, ProgramIR), "ir_type", "ProgramIR from the parser required")
    need(type(program.source) is str and type(program.filename) is str and program.filename,
         "pointer_unresolved", "original source and logical filename required")
    try:
        raw = program.source.encode("ascii")
    except UnicodeError as error:
        raise TranslationRefusal("source_encoding", "bounded source must be ASCII") from error
    digest = hashlib.sha256(raw).hexdigest()
    need(all(byte == 10 or 32 <= byte <= 126 or (byte == 13 and raw[index:index + 2] == b"\r\n")
             for index, byte in enumerate(raw)), "source_encoding", "unsupported control byte")
    need(program.source_sha256 == digest, "source_hash", "IR does not bind original source bytes")
    need(len(program.source.splitlines()) <= 200, "source_limit", "source exceeds 200 lines")

    def span(value):
        keys = ("source_sha256", "filename", "line_start", "line_end", "byte_start", "byte_end")
        data = {key: getattr(value, key, None) for key in keys}
        start, end = data["byte_start"], data["byte_end"]
        need(data["source_sha256"] == digest and data["filename"] == program.filename
             and type(start) is int and type(end) is int and 0 <= start < end <= len(raw),
             "pointer_unresolved", "invalid source pointer", value)
        need(type(data["line_start"]) is int and type(data["line_end"]) is int
             and data["line_start"] == raw[:start].count(b"\n") + 1
             and data["line_end"] == raw[:end - 1].count(b"\n") + 1,
             "pointer_unresolved", "line/byte pointer disagreement", value)
        return data

    def name(value):
        need(type(value) is str and re.fullmatch(r"[A-Z][A-Z0-9-]{0,29}", value)
             and not value.endswith("-"), "unresolved_name", "invalid identifier")
        return value

    need(1 <= len(program.fields) <= 32 and 1 <= len(program.paragraphs) <= 8,
         "source_limit", "field/paragraph count outside subset")
    fields, field_map = [], {}
    for field in program.fields:
        field_name = name(field.name)
        need(field_name not in field_map and field_name != "RETURN-CODE", "duplicate_name", "duplicate field")
        spec = {key: getattr(field, key) for key in ("name", "pic", "usage", "sign", "offset", "width", "scale", "digits")}
        checked = FieldSpec.from_mapping(spec)
        need(field.record_name is None or type(field.record_name) is str,
             "file_contract", "record identity must be text or absent")
        need(field.storage in ("input", "output", "working"), "ir_type", "missing field storage")
        initial = field.initial
        need(initial is None or type(initial) is str, "literal_range", "VALUE must be exact text")
        if initial is not None:
            if checked.is_alpha:
                need(len(initial) <= checked.width and all(32 <= ord(c) <= 126 for c in initial),
                     "literal_range", "alpha VALUE outside field")
            else:
                number = decimal_value(initial)
                scale = 10 ** number.scale
                units = number.coefficient * 10 ** checked.scale
                need(units % scale == 0 and abs(units // scale) < 10 ** checked.digits
                     and (checked.signed or not number.is_negative), "literal_range", "numeric VALUE outside field")
        data = {**spec, "storage": field.storage, "record_name": field.record_name,
                "initial": initial, "span": span(field.span)}
        fields.append(data)
        field_map[field_name] = data
    file_map, records, files = {}, set(), []
    need(len(program.files) == 2, "file_contract", "one input and output binding required")
    for file in program.files:
        name(file.name)
        name(file.record_name)
        name(file.status_name)
        need(file.name not in file_map and file.record_name not in records,
             "file_contract", "duplicate file/record binding")
        need(file.direction in ("input", "output") and file.path == file.direction + ".dat",
             "external_path", "only explicit input.dat/output.dat bindings allowed")
        status = field_map.get(file.status_name)
        need(status is not None and status["pic"] == "X(2)" and status["storage"] == "working",
             "file_contract", "missing working FILE STATUS X(2)")
        selected = [f for f in fields if f["record_name"] == file.record_name and f["storage"] == file.direction]
        offset = 0
        for field in selected:
            need(field["usage"] == "DISPLAY" and field["offset"] == offset,
                 "file_contract", "external record has gap/overlap/non-DISPLAY")
            need(not field["pic"].startswith("S") or field["sign"] == "leading_separate",
                 "file_contract", "external sign must be leading separate")
            offset += field["width"]
        need(selected and offset <= 8192, "file_contract", "empty/oversize record binding")
        data = {"name": file.name, "record": file.record_name, "status": file.status_name,
                "direction": file.direction, "fields": [f["name"] for f in selected]}
        files.append(data)
        file_map[file.name] = data
        records.add(file.record_name)
    need({f["direction"] for f in files} == {"input", "output"}
         and len({f["status"] for f in files}) == 2, "file_contract", "file/status directions must be distinct")
    need(all(f["storage"] == "working" or any(f["name"] in file["fields"] for file in files) for f in fields),
         "file_contract", "unbound external field")
    paragraphs = {name(p.name): p for p in program.paragraphs}
    need(len(paragraphs) == len(program.paragraphs) and program.paragraphs[0].name == "MAIN",
         "control_flow", "unique MAIN-first paragraphs required")
    active, total = set(), [0]

    def node(value, depth=0):
        need(isinstance(value, IRNode) and depth <= 64 and id(value) not in active,
             "ir_type", "unknown, cyclic or deep IR")
        total[0] += 1
        need(total[0] <= 4096, "source_limit", "IR node budget exceeded")
        active.add(id(value))
        try:
            kind, args = value.kind, value.args
            need(kind in KEYS and isinstance(args, Mapping) and set(args) == KEYS[kind],
                 "ir_type", "unknown kind/argument keys", value.span)
            data = {"kind": kind, "span": span(value.span)}
            for key, item in args.items():
                if isinstance(item, IRNode):
                    data[key] = node(item, depth + 1)
                elif key == "values":
                    need(type(item) is tuple and item, "ir_type", "DISPLAY needs ordered values")
                    data[key] = [node(entry, depth + 1) for entry in item]
                else:
                    need(item is None or type(item) in (str, int, bool), "ir_type", "nonliteral IR data")
                    data[key] = item
            data["body"] = [node(entry, depth + 1) for entry in value.body]
            data["otherwise"] = [node(entry, depth + 1) for entry in value.otherwise]
            if kind not in {"if", "read"} | ARITHMETIC:
                need(not data["body"] and not data["otherwise"], "ir_type", "unexpected statement body")
            if kind != "if":
                need(not data["otherwise"], "ir_type", "unexpected ELSE body")
            return data
        finally:
            active.remove(id(value))

    result = {"version": 1, "source_sha256": digest, "filename": program.filename,
              "fields": fields, "files": files, "paragraphs": []}
    for paragraph in program.paragraphs:
        result["paragraphs"].append({"name": paragraph.name, "span": span(paragraph.span),
                                     "body": [node(n) for n in paragraph.statements]})
    validate_nodes(result)
    return result


def validate_nodes(plan):
    fields = {f["name"]: f for f in plan["fields"]}
    files = {f["name"]: f for f in plan["files"]}
    records = {f["record"]: f for f in plan["files"]}
    paragraphs = {p["name"]: p for p in plan["paragraphs"]}

    def expression(n, numeric_only=False):
        kind = n["kind"]
        if kind == "literal":
            need(type(n["value"]) is str and n["literal_type"] in ("numeric", "alpha"), "type_mismatch", "literal type")
            if n["literal_type"] == "numeric":
                decimal_value(n["value"])
            else:
                need(all(32 <= ord(c) <= 126 for c in n["value"]), "literal_range", "non-ASCII literal")
            result = n["literal_type"]
        elif kind == "reference":
            need(n["name"] in fields, "unresolved_name", "unknown field reference")
            result = "alpha" if fields[n["name"]]["pic"].startswith("X") else "numeric"
        elif kind in ("binary", "compare", "boolean"):
            left, right = expression(n["left"]), expression(n["right"])
            need(left == right, "type_mismatch", "mixed expression types")
            if kind == "binary":
                need(left == "numeric" and n["op"] in ("+", "-", "*", "/"), "unsupported_expression", "binary operator")
                result = "numeric"
            elif kind == "compare":
                need(n["left"]["kind"] in ("literal", "reference") and
                     n["right"]["kind"] in ("literal", "reference"), "unsupported_expression", "comparison atoms")
                need(left in ("alpha", "numeric") and n["op"] in ("=", "<>", "<", "<=", ">", ">="),
                     "unsupported_expression", "comparator")
                result = "boolean"
            else:
                need(left == "boolean" and n["op"] in ("AND", "OR"), "unsupported_expression", "boolean operator")
                result = "boolean"
        else:
            raise TranslationRefusal("unsupported_expression", "statement used as expression")
        need(not numeric_only or result == "numeric", "type_mismatch", "numeric expression required")
        return result

    def walk(nodes, paragraph, nested=False):
        for n in nodes:
            kind = n["kind"]
            need(kind not in ("literal", "reference", "binary", "compare", "boolean"), "ir_type", "expression as statement")
            if kind in ARITHMETIC or kind == "move":
                target = n["target"]
                need(target in fields or (target == "RETURN-CODE" and kind == "move"), "unresolved_name", "unknown receiver")
                if kind == "move":
                    actual = expression(n["value"])
                    expected = "numeric" if target == "RETURN-CODE" else (
                        "alpha" if fields[target]["pic"].startswith("X") else "numeric")
                    need(actual == expected and n["value"]["kind"] in ("literal", "reference"), "type_mismatch", "MOVE type")
                    if target == "RETURN-CODE":
                        value = n["value"]
                        need(value["kind"] == "literal" and re.fullmatch(r"[+]?[0-9]+", value["value"])
                             and 0 <= int(value["value"]) <= 255, "return_contract", "RETURN-CODE integer literal required")
                else:
                    need(not fields[target]["pic"].startswith("X") and type(n["rounded"]) is bool
                         and type(n["has_size_error"]) is bool and (n["has_size_error"] or not n["body"]),
                         "type_mismatch", "arithmetic receiver/clauses")
                    for key in (("left", "right") if kind == "divide" else (("expression",) if kind == "compute" else ("value",))):
                        expression(n[key], True)
                        need(kind == "compute" or n[key]["kind"] in ("literal", "reference"),
                             "unsupported_expression", "arithmetic atom required")
                    if kind == "compute":
                        def count(x):
                            return 1 + count(x["left"]) + count(x["right"]) if x["kind"] == "binary" else 0
                        need(count(n["expression"]) <= 3, "compute_limit", "COMPUTE limit")
            elif kind == "if":
                need(expression(n["condition"]) == "boolean", "type_mismatch", "IF condition")
            elif kind == "perform":
                need(n["paragraph"] in paragraphs and n["paragraph"] != "MAIN", "control_flow", "PERFORM target")
                if n["until"] is not None:
                    need(expression(n["until"]) == "boolean" and type(n["max_iterations"]) is int
                         and 1 <= n["max_iterations"] <= 64, "unbounded_perform", "parser-attached proof bound required")
                else:
                    need(n["max_iterations"] is None, "unbounded_perform", "unexpected bound")
            elif kind in ("open", "read", "close"):
                need(n["file"] in files, "file_contract", "unknown file")
                if kind == "open":
                    need(n["mode"] == files[n["file"]]["direction"].upper(), "file_contract", "OPEN mode")
                if kind == "read":
                    need(files[n["file"]]["direction"] == "input", "file_contract", "READ output")
            elif kind == "write":
                need(n["record"] in records and records[n["record"]]["direction"] == "output", "file_contract", "WRITE input")
            elif kind == "display":
                for value in n["values"]:
                    expression(value)
                    need(value["kind"] == "reference" or (value["kind"] == "literal" and value["literal_type"] == "alpha"),
                         "type_mismatch", "DISPLAY field/alpha literal only")
            elif kind == "stop":
                need(paragraph == "MAIN" and not nested and n is nodes[-1], "control_flow", "STOP location")
            else:
                raise TranslationRefusal("ir_type", "unknown statement")
            walk(n["body"], paragraph, True)
            walk(n["otherwise"], paragraph, True)
    for paragraph in plan["paragraphs"]:
        walk(paragraph["body"], paragraph["name"])
    need(paragraphs["MAIN"]["body"] and paragraphs["MAIN"]["body"][-1]["kind"] == "stop", "control_flow", "MAIN must terminate")
    active, done = set(), set()
    def visit(name):
        need(name not in active, "control_flow", "recursive paragraph graph")
        if name in done:
            return
        active.add(name)
        def calls(nodes):
            for n in nodes:
                if n["kind"] == "perform":
                    visit(n["paragraph"])
                calls(n["body"])
                calls(n["otherwise"])
        calls(paragraphs[name]["body"])
        active.remove(name)
        done.add(name)
    for name in paragraphs:
        visit(name)
