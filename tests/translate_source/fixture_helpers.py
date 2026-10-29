"""Original small source fixtures and inert generated-PLAN inspection, no candidate execution."""
import ast
import hashlib

HEADER = '''IDENTIFICATION DIVISION.
PROGRAM-ID. SOURCE-UNIT.
ENVIRONMENT DIVISION.
INPUT-OUTPUT SECTION.
FILE-CONTROL.
SELECT INFILE ASSIGN TO "input.dat" ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS IN-STATUS.
SELECT OUTFILE ASSIGN TO "output.dat" ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS OUT-STATUS.
DATA DIVISION.
FILE SECTION.
FD INFILE.
01 IN-REC.
05 INPUT-N PIC 9(2)V9(2).
05 DENOMINATOR PIC 9(1).
FD OUTFILE.
01 OUT-REC.
05 OUT-N PIC S9(3)V9(2) SIGN LEADING SEPARATE.
WORKING-STORAGE SECTION.
01 IN-STATUS PIC X(2) VALUE "00".
01 OUT-STATUS PIC X(2) VALUE "00".
01 WORK-N PIC S9(3)V9(2) COMP-3 VALUE -1.25.
01 FLAG PIC X(4) VALUE "OLD".
'''

def source(body="DISPLAY FLAG", *, extra="", working="", line_ending="\n"):
    text = HEADER + working + "PROCEDURE DIVISION.\nMAIN.\n" + body + "\nSTOP RUN.\n" + extra
    return text if line_ending == "\n" else text.replace("\n", line_ending)

def parse_source(text, filename="unit.cbl", *, manifest=None):
    from cobolmap.parse import parse
    return parse(text, filename=filename, manifest=manifest)

def _literal(node, depth=0):
    """Decode only inert AST literals; never eval/literal_eval/compile or execute code."""
    if depth > 64:
        raise ValueError("test literal depth")
    if isinstance(node, ast.Constant) and type(node.value) in (str, int, bool, type(None)):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 4096:
        return [_literal(item, depth + 1) for item in node.elts]
    if isinstance(node, ast.Dict) and len(node.keys) <= 4096:
        pairs = [(_literal(key, depth + 1), _literal(value, depth + 1)) for key, value in zip(node.keys, node.values)]
        result = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError("test literal mapping key")
            result[key] = value
        return result
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and type(node.operand.value) is int:
        return -node.operand.value
    raise ValueError("nonliteral generated PLAN")

def plan_from_result(result):
    """AST inspection only; generated Python stays a string, never a loaded module."""
    tree = ast.parse(result.code, filename="inert-generated-source.py")
    plans = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "PLAN"]
    if len(plans) != 1:
        raise ValueError("one inert PLAN required")
    return tree, _literal(plans[0].value)

def walk_ir(program):
    from cobolmap.parse.models import IRNode
    def visit(node):
        yield node
        for value in node.args.values():
            if isinstance(value, IRNode):
                yield from visit(value)
            elif isinstance(value, tuple):
                for item in value:
                    if isinstance(item, IRNode):
                        yield from visit(item)
        for item in node.body + node.otherwise:
            yield from visit(item)
    for paragraph in program.paragraphs:
        for node in paragraph.statements:
            yield from visit(node)

def one_ir(program, kind, spelling):
    raw = program.source.encode("ascii")
    needle = spelling.encode("ascii")
    matches = [node for node in walk_ir(program) if node.kind == kind and raw[node.span.byte_start:node.span.byte_end] == needle]
    if len(matches) != 1:
        raise ValueError("unit target must be unique")
    return matches[0]

def make_change(program, node, operation, before, after, replacement, *, task_id="unit-change"):
    """One source-bound synthetic unit request; never an authenticated/admitted task."""
    raw = program.source.encode("ascii")
    changed = raw[:node.span.byte_start] + replacement.encode("ascii") + raw[node.span.byte_end:]
    # For a byte-identical no-op, a trailing newline gives a distinct synthetic
    # external source commitment so the descriptor passes identity validation.
    # This is unit scaffolding, never a witness that the requested edit occurred.
    if changed == raw:
        changed += b"\n"
    return {"manifest_version": 1, "task_id": task_id, "original_sha256": hashlib.sha256(raw).hexdigest(),
            "target": {"file": program.filename, "line": node.span.line_start,
                       "byte_start": node.span.byte_start, "byte_end": node.span.byte_end, "node_kind": node.kind},
            "operation": operation, "before": before, "after": after,
            "prose": "Original builder structured unit request; no semantic witness claimed.",
            "changed_sha256": hashlib.sha256(changed).hexdigest()}

def walk_plan(plan):
    def visit(value):
        if isinstance(value, dict):
            if "kind" in value and "span" in value:
                yield value
            for child in value.values():
                yield from visit(child)
        elif isinstance(value, list):
            for child in value:
                yield from visit(child)
    yield from visit(plan)

def plan_node(plan, kind, start):
    matches = [node for node in walk_plan(plan) if node["kind"] == kind and node["span"]["byte_start"] == start]
    if len(matches) != 1:
        raise ValueError("one normalized target required")
    return matches[0]
