"""Conservative static name/type/control/file and finite-loop obligations."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import re
from typing import Any

from .models import FieldLayout, IRNode, ParseRefusal, ProgramIR


def integer_value(text: str) -> int:
    """Convert validated short-magnitude decimal text, including leading zeros."""
    return (-1 if text.startswith("-") else 1) * int(text.lstrip("+-").lstrip("0") or "0")


def walk(nodes: tuple[IRNode, ...]):
    for node in nodes:
        yield node
        yield from walk(node.body)
        yield from walk(node.otherwise)


@dataclass(frozen=True)
class _Unknown:
    excluded: frozenset[str | int] = frozenset()


@dataclass
class _Path:
    opened: frozenset[str]
    values: dict[str, int | str | _Unknown]
    exhausted: frozenset[str] = frozenset()


class Validator:
    def __init__(self, program: ProgramIR, manifest: Mapping[str, Any] | None):
        self.program = program
        self.fields = {field.name: field for field in program.fields}
        self.paragraphs = {paragraph.name: paragraph for paragraph in program.paragraphs}
        self.files = {file.name: file for file in program.files}
        self.records = {file.record_name: file for file in program.files}
        self.manifest = manifest
        self.bounds: dict[int, int] = {}
        self.loop_proofs: dict[int, Mapping[str, Any]] = {}
        self.flow_steps = 0
        self.proof_steps = 0
        if manifest is not None and not isinstance(manifest, Mapping):
            self.fail("return_contract", "ProgramManifest must be a mapping")

    def fail(self, code: str, message: str, node: IRNode | None = None) -> None:
        raise ParseRefusal(code, message, node.span if node else self.program.paragraphs[0].span)

    def field(self, name: str, node: IRNode) -> FieldLayout:
        if name not in self.fields:
            self.fail("unresolved_name", f"Unknown elementary field {name}", node)
        return self.fields[name]

    def expression_type(self, node: IRNode) -> str:
        if node.kind == "literal":
            return str(node.args["literal_type"])
        if node.kind == "reference":
            return "alpha" if self.field(node.args["name"], node).pic.startswith("X") else "numeric"
        if node.kind in {"binary", "compare", "boolean"}:
            left = self.expression_type(node.args["left"])
            right = self.expression_type(node.args["right"])
            expected = "boolean" if node.kind == "boolean" else "numeric" if node.kind == "binary" else left
            if left != right or left != expected:
                self.fail("type_mismatch", "Incompatible expression operands", node)
            return "numeric" if node.kind == "binary" else "boolean"
        self.fail("type_mismatch", "Unsupported expression node", node)
        raise AssertionError("unreachable")

    def types(self) -> None:
        statuses = set()
        for binding in self.program.files:
            status = self.fields.get(binding.status_name)
            if status is None or status.storage != "working" or status.pic != "X(2)" or status.usage != "DISPLAY" or status.name in statuses:
                self.fail("file_contract", "FILE STATUS must be distinct working PIC X(2)")
            statuses.add(status.name)
        for paragraph in self.program.paragraphs:
            for node in walk(paragraph.statements):
                args = node.args
                if node.kind in {"move", "add", "subtract", "multiply", "divide", "compute"}:
                    if args["target"] == "RETURN-CODE":
                        self.return_code(node)
                        continue
                    target = self.field(args["target"], node)
                    target_type = "alpha" if target.pic.startswith("X") else "numeric"
                    expressions = ([args["expression"]] if node.kind == "compute" else
                                   [args["left"], args["right"]] if node.kind == "divide" else [args["value"]])
                    if any(self.expression_type(value) != target_type for value in expressions) or (node.kind != "move" and target_type != "numeric"):
                        self.fail("type_mismatch", "Assignment operands do not match destination", node)
                elif node.kind == "if":
                    self.expression_type(args["condition"])
                elif node.kind == "perform":
                    if args["paragraph"] not in self.paragraphs or args["paragraph"] == "MAIN":
                        self.fail("control_flow", "PERFORM must resolve to a non-MAIN paragraph", node)
                    if args["until"] is not None:
                        self.expression_type(args["until"])
                elif node.kind == "display":
                    for value in args["values"]:
                        self.expression_type(value)
                elif node.kind in {"open", "read", "close"}:
                    file = self.files.get(args["file"])
                    if file is None or (node.kind == "read" and file.direction != "input") or (node.kind == "open" and args["mode"].lower() != file.direction):
                        self.fail("file_contract", "File operation does not match declared direction", node)
                elif node.kind == "write" and args["record"] not in self.records:
                    self.fail("file_contract", "WRITE requires output record", node)
                elif node.kind == "write" and self.records[args["record"]].direction != "output":
                    self.fail("file_contract", "Cannot WRITE input record", node)

    def return_code(self, node: IRNode) -> None:
        value = node.args["value"]
        if node.kind != "move" or value.kind != "literal" or value.args["literal_type"] != "numeric":
            self.fail("return_contract", "RETURN-CODE requires MOVE integer", node)
        text = value.args["value"]
        if not text.lstrip("+-").isdigit() or len(text.lstrip("+-0")) > 3:
            self.fail("return_contract", "RETURN-CODE must be an integer literal", node)
        allowed = self.manifest.get("allowed_return_codes") if self.manifest else None
        if not isinstance(allowed, (list, tuple)) or not allowed or any(type(x) is not int or not 0 <= x <= 255 for x in allowed) or list(allowed) != sorted(set(allowed)) or 0 not in allowed or integer_value(text) not in allowed:
            self.fail("return_contract", "Missing/invalid declared RETURN-CODE outcomes", node)

    def cycles(self) -> None:
        visiting: set[str] = set()
        done: set[str] = set()
        def visit(name: str) -> None:
            if name in visiting:
                self.fail("control_flow", "Recursive/cyclic paragraph PERFORM")
            if name in done:
                return
            visiting.add(name)
            for node in walk(self.paragraphs[name].statements):
                if node.kind == "perform":
                    visit(node.args["paragraph"])
            visiting.remove(name)
            done.add(name)
        for name in self.paragraphs:
            visit(name)

    def manifest_proofs(self) -> None:
        loops = sorted((node for paragraph in self.program.paragraphs for node in walk(paragraph.statements)
                        if node.kind == "perform" and node.args["until"] is not None), key=lambda n: n.span.byte_start)
        if self.manifest is not None:
            if self.manifest.get("source_sha256") != self.program.source_sha256:
                self.fail("unbounded_perform" if loops else "return_contract", "Manifest must bind exact original source bytes")
        entries = self.manifest.get("loops") if self.manifest else []
        if not isinstance(entries, (list, tuple)) or len(entries) != len(loops):
            self.fail("unbounded_perform", "Manifest must enumerate every loop once")
        expected = {"target", "paragraph", "induction_field", "initial", "step", "relation", "limit", "max_iterations", "proof"}
        for node, proof in zip(loops, entries):
            if not isinstance(proof, Mapping) or set(proof) != expected:
                self.fail("unbounded_perform", "Invalid closed loop proof", node)
            if not self.matches_span(proof["target"], node.span) or proof["paragraph"] != node.args["paragraph"]:
                self.fail("unbounded_perform", "Loop proof target does not resolve", node)
            if type(proof["max_iterations"]) is not int or not 1 <= proof["max_iterations"] <= 64:
                self.fail("unbounded_perform", "Loop bound must be integer1..64", node)
            for key in ("initial", "step", "limit"):
                text = proof[key]
                if not isinstance(text, str) or re.fullmatch(r"[+-]?[0-9]+", text) is None or len(text.lstrip("+-0")) > 10:
                    self.fail("unbounded_perform", "Loop proof requires integer constants", node)
            if not isinstance(proof["induction_field"], str):
                self.fail("unbounded_perform", "Induction field must be an identifier", node)
            field = self.field(proof["induction_field"], node)
            if field.digits == 0 or field.scale != 0 or integer_value(proof["step"]) == 0:
                self.fail("unbounded_perform", "Loop induction needs integer field and nonzero step", node)
            test = node.args["until"]
            if test.kind != "compare" or test.args["left"].kind != "reference" or test.args["left"].args["name"] != field.name or test.args["right"].kind != "literal" or test.args["right"].args["literal_type"] != "numeric" or test.args["right"].args["value"] != proof["limit"] or test.args["op"] != proof["relation"]:
                self.fail("unbounded_perform", "Declared exit must match actual integer comparison", node)
            spans = proof["proof"]
            if not isinstance(spans, Mapping) or set(spans) != {"initialization_span", "update_spans", "exit_span"} or not self.matches_span(spans["exit_span"], test.span):
                self.fail("unbounded_perform", "Proof exit span must resolve to actual test", node)
            updates = spans["update_spans"]
            if not isinstance(updates, (list, tuple)) or not updates:
                self.fail("unbounded_perform", "Missing update spans", node)
            body = self.paragraphs[node.args["paragraph"]].statements
            writes = self.induction_writes(body, field.name)
            if len(writes) != len(updates) or any(not self.matches_span(span, write.span) for span, write in zip(updates, sorted(writes, key=lambda n: n.span.byte_start))):
                self.fail("unbounded_perform", "Update spans must enumerate actual induction writes", node)
            all_nodes = [item for paragraph in self.program.paragraphs for item in walk(paragraph.statements)]
            initializers = [item for item in all_nodes if self.matches_span(spans["initialization_span"], item.span)]
            if len(initializers) != 1 or initializers[0].kind != "move" or initializers[0].args["target"] != field.name or initializers[0].args["value"].kind != "literal" or initializers[0].args["value"].args["value"] != proof["initial"]:
                self.fail("unbounded_perform", "Initialization span must resolve to exact literal MOVE", node)
            steps = self.steps(body, field.name)
            if steps != {integer_value(proof["step"])}:
                self.fail("unbounded_perform", "Every loop-body path must have the same declared step", node)
            current = integer_value(proof["initial"])
            count = 0
            while not self.compare(current, proof["relation"], integer_value(proof["limit"])):
                current += integer_value(proof["step"])
                count += 1
                if count > proof["max_iterations"] or not self.fits(field, current):
                    self.fail("unbounded_perform", "Loop bound fails or induction overflows", node)
            self.bounds[node.span.byte_start] = count
            self.loop_proofs[node.span.byte_start] = proof

    def matches_span(self, value: Any, span: Any) -> bool:
        return isinstance(value, Mapping) and set(value) == {"file", "line", "byte_start", "byte_end"} and value["file"] == span.filename and type(value["line"]) is int and value["line"] == span.line_start and type(value["byte_start"]) is int and type(value["byte_end"]) is int and value["byte_start"] == span.byte_start and value["byte_end"] == span.byte_end

    def induction_writes(self, nodes: tuple[IRNode, ...], field: str) -> list[IRNode]:
        result = []
        for node in nodes:
            self.proof_visit(node)
            if node.args.get("target") == field:
                result.append(node)
            if node.kind == "perform":
                result.extend(self.induction_writes(self.paragraphs[node.args["paragraph"]].statements, field))
            result.extend(self.induction_writes(node.body, field))
            result.extend(self.induction_writes(node.otherwise, field))
            if node.kind == "read" and self.fields[field].storage == "input":
                self.fail("unbounded_perform", "READ invalidates induction input", node)
        return result

    def steps(self, nodes: tuple[IRNode, ...], field: str) -> set[int]:
        steps = {0}
        for node in nodes:
            self.proof_visit(node)
            delta = {0}
            if node.args.get("target") == field:
                value = node.args.get("value")
                if node.kind == "compute" and not node.args["has_size_error"]:
                    delta = {self.linear_step(node.args["expression"], field, node)}
                elif node.kind == "move" and value.kind == "reference" and value.args["name"] == field:
                    delta = {0}
                elif node.kind not in {"add", "subtract"} or node.args["has_size_error"] or value.kind != "literal" or value.args["literal_type"] != "numeric" or not value.args["value"].lstrip("+-").isdigit():
                    self.fail("unbounded_perform", "Cannot prove monotone induction write", node)
                else:
                    if len(value.args["value"].lstrip("+-0")) > 8:
                        self.fail("unbounded_perform", "Induction step exceeds field bounds", node)
                    delta = {integer_value(value.args["value"]) * (-1 if node.kind == "subtract" else 1)}
            elif node.kind == "perform":
                if node.args["until"] is not None:
                    if self.induction_writes(self.paragraphs[node.args["paragraph"]].statements, field):
                        self.fail("unbounded_perform", "Nested loop induction proof is unresolved", node)
                    delta = {0}
                else:
                    delta = self.steps(self.paragraphs[node.args["paragraph"]].statements, field)
            elif node.kind == "if":
                delta = self.steps(node.body, field) | self.steps(node.otherwise, field)
            elif node.body:
                delta = self.steps(node.body, field) | {0}
            steps = {left + right for left in steps for right in delta}
            if len(steps) > 64:
                self.fail("unbounded_perform", "Induction path proof exceeds bounded domain", node)
        return steps

    def proof_visit(self, node: IRNode) -> None:
        """Bound the pre-flow call-DAG traversals as well as flow unfolding."""
        self.proof_steps += 1
        if self.proof_steps > 100000:
            self.fail("unbounded_perform", "Static induction proof budget exceeded; no partial IR", node)

    def linear_step(self, expression: IRNode, field: str, statement: IRNode) -> int:
        """Prove an integer I +/- literal COMPUTE progression without rounding."""
        def linear(node: IRNode) -> tuple[int, int]:
            if node.kind == "reference" and node.args["name"] == field:
                return 1, 0
            if node.kind == "literal" and node.args["literal_type"] == "numeric" and re.fullmatch(r"[+-]?[0-9]+", node.args["value"]) and len(node.args["value"].lstrip("+-0")) <= 8:
                return 0, integer_value(node.args["value"])
            if node.kind == "binary" and node.args["op"] in {"+", "-"}:
                a, b = linear(node.args["left"]), linear(node.args["right"])
                factor = -1 if node.args["op"] == "-" else 1
                return a[0] + factor * b[0], a[1] + factor * b[1]
            self.fail("unbounded_perform", "Unresolved COMPUTE induction proof", statement)
            raise AssertionError("unreachable")
        coefficient, offset = linear(expression)
        if coefficient != 1:
            self.fail("unbounded_perform", "Induction COMPUTE must preserve unit coefficient", statement)
        return offset

    def known_integer(self, node: IRNode, known: dict[str, int]) -> int | None:
        if node.kind == "reference":
            return known.get(node.args["name"])
        if node.kind == "literal" and node.args["literal_type"] == "numeric" and re.fullmatch(r"[+-]?[0-9]+", node.args["value"]) and len(node.args["value"].lstrip("+-0")) <= 8:
            return integer_value(node.args["value"])
        if node.kind == "binary" and node.args["op"] in {"+", "-"}:
            left = self.known_integer(node.args["left"], known)
            right = self.known_integer(node.args["right"], known)
            if left is not None and right is not None:
                return left + (-right if node.args["op"] == "-" else right)
        return None

    @staticmethod
    def compare(left: int, op: str, right: int) -> bool:
        return {"=": left == right, "<>": left != right, "<": left < right,
                "<=": left <= right, ">": left > right, ">=": left >= right}[op]

    @staticmethod
    def fits(field: FieldLayout, value: int) -> bool:
        maximum = 10 ** field.digits - 1
        return -maximum <= value <= maximum if field.pic.startswith("S") else 0 <= value <= maximum

    def flow_visit(self, node: IRNode) -> None:
        # Count before every path copy, condition expansion and statement visit.
        self.flow_steps += 1
        if self.flow_steps > 100000:
            self.fail("unbounded_perform", "Static flow proof budget exceeded; no partial IR", node)

    def fork(self, path: _Path, node: IRNode) -> _Path:
        self.flow_visit(node)
        return _Path(path.opened, dict(path.values), path.exhausted)

    def append_path(self, paths: list[_Path], path: _Path, node: IRNode) -> None:
        self.flow_visit(node)
        if len(paths) >= 256:
            self.fail("file_contract", "Static path limit256 exceeded; no partial IR", node)
        paths.append(path)

    def scalar(self, node: IRNode, path: _Path) -> int | str | _Unknown:
        if node.kind == "reference":
            return path.values.get(node.args["name"], _Unknown())
        if node.kind == "literal" and node.args["literal_type"] == "alpha":
            return node.args["value"].rstrip(" ")
        integers = {name: value for name, value in path.values.items() if type(value) is int}
        value = self.known_integer(node, integers)
        return value if value is not None else _Unknown()

    def condition(self, node: IRNode, path: _Path, truth: bool) -> list[_Path]:
        self.flow_visit(node)
        if node.kind == "boolean":
            # Disjoint short-circuit alternatives retain field refinements.
            first = node.args["op"] == "AND"
            result = []
            if truth == first:
                for left in self.condition(node.args["left"], path, first):
                    for right in self.condition(node.args["right"], left, first):
                        self.append_path(result, right, node)
            else:
                for left in self.condition(node.args["left"], path, not first):
                    self.append_path(result, left, node)
                for left in self.condition(node.args["left"], path, first):
                    for right in self.condition(node.args["right"], left, not first):
                        self.append_path(result, right, node)
            return result
        left_node, right_node = node.args["left"], node.args["right"]
        left, right = self.scalar(left_node, path), self.scalar(right_node, path)
        op = node.args["op"]
        if not isinstance(left, _Unknown) and not isinstance(right, _Unknown):
            if type(left) is type(right):
                return [self.fork(path, node)] if self.compare(left, op, right) == truth else []
        # Refine alpha equality only. Numeric uncertainty stays conservative;
        # an IF does not substitute for the manifest's dominating integer MOVE.
        reference, domain, literal = left_node, left, right
        if right_node.kind == "reference" and left_node.kind == "literal":
            reference, domain, literal = right_node, right, left
        result = self.fork(path, node)
        if (reference.kind == "reference" and isinstance(domain, _Unknown)
                and isinstance(literal, str) and op in {"=", "<>"}):
            equal = truth == (op == "=")
            if equal and literal in domain.excluded:
                return []
            result.values[reference.args["name"]] = (literal if equal else
                _Unknown(domain.excluded | {literal}))
        return [result]

    def flow(self, nodes: tuple[IRNode, ...], paths: list[_Path]) -> list[_Path]:
        for node in nodes:
            after = []
            for path in paths:
                self.flow_visit(node)
                for result in self.statement(node, path):
                    self.append_path(after, result, node)
            paths = after
        return paths

    def statement(self, node: IRNode, path: _Path) -> list[_Path]:
        args, kind = node.args, node.kind
        if kind == "if":
            result = []
            for truth, body in ((True, node.body), (False, node.otherwise)):
                for branch in self.condition(args["condition"], path, truth):
                    for after in self.flow(body, [branch]):
                        self.append_path(result, after, node)
            return result
        if kind == "perform":
            body = self.paragraphs[args["paragraph"]].statements
            if args["until"] is None:
                return self.flow(body, [path])
            proof = self.loop_proofs[node.span.byte_start]
            field = proof["induction_field"]
            if path.values.get(field) != integer_value(proof["initial"]):
                self.fail("unbounded_perform", "Declared initialization does not dominate loop", node)
            paths = [path]
            for _ in range(self.bounds[node.span.byte_start]):
                paths = self.flow(body, paths)
            expected = integer_value(proof["initial"]) + integer_value(proof["step"]) * self.bounds[node.span.byte_start]
            if any(after.values.get(field) != expected for after in paths):
                self.fail("unbounded_perform", "Induction data-flow proof disagrees", node)
            return paths
        current = self.fork(path, node)
        if kind == "open":
            name = args["file"]
            if name in current.opened:
                self.fail("file_contract", "File already OPEN", node)
            failed = self.fork(current, node)
            status = self.files[name].status_name
            failed.values[status] = _Unknown(frozenset({"00"}))
            current.values[status] = "00"
            current.opened = current.opened | {name}
            current.exhausted = current.exhausted - {name}
            return [current, failed]
        if kind in {"close", "read", "write"}:
            name = args["file"] if kind != "write" else self.records[args["record"]].name
            if name not in current.opened:
                self.fail("file_contract", "IO/CLOSE requires proven successful OPEN", node)
            status = self.files[name].status_name
            if kind == "close":
                # Discharge the source cleanup attempt, not a runtime close claim.
                current.opened = current.opened - {name}
                current.exhausted = current.exhausted - {name}
                current.values[status] = _Unknown()
            elif kind == "write":
                current.values[status] = _Unknown()
            else:
                if name in current.exhausted:
                    self.fail("file_contract", "READ after EOF/unresolved read failure", node)
                for field in self.program.fields:
                    if field.storage == "input" and field.record_name == self.files[name].record_name:
                        current.values.pop(field.name, None)
                end = self.fork(current, node)
                error = self.fork(current, node)
                end.exhausted = error.exhausted = current.exhausted | {name}
                current.values[status] = "00"
                end.values[status] = error.values[status] = _Unknown(frozenset({"00"}))
                result = [current, error]
                for branch in self.flow(node.body, [end]):
                    self.append_path(result, branch, node)
                return result
        elif kind in {"move", "add", "subtract", "multiply", "divide", "compute"}:
            target = args["target"]
            field = self.fields.get(target)
            value = self.scalar(args["value"], path) if "value" in args else _Unknown()
            if kind in {"add", "subtract"}:
                before = path.values.get(target)
                value = (before + value * (-1 if kind == "subtract" else 1)
                         if type(before) is int and type(value) is int else _Unknown())
            elif kind == "compute":
                value = self.scalar(args["expression"], path)
            elif kind != "move":
                value = _Unknown()
            if field is not None and field.pic.startswith("X"):
                if isinstance(value, str):
                    value = value[:field.width].rstrip(" ")
                elif (isinstance(value, _Unknown) and kind == "move"
                      and args["value"].kind == "reference"
                      and self.fields[args["value"].args["name"]].width != field.width):
                    # Truncation may turn an excluded full value into a possible
                    # prefix. Drop exclusions rather than proving a false guard.
                    value = _Unknown()
                elif kind != "move" or not isinstance(value, _Unknown):
                    value = _Unknown()
            elif (field is None or type(value) is not int or field.scale != 0
                  or not self.fits(field, value)):
                value = _Unknown()
            current.values[target] = value
            if node.body:
                # Error-path destination is unspecified; never retain a guessed value.
                error = self.fork(current, node)
                error.values[target] = _Unknown()
                result = [current]
                for branch in self.flow(node.body, [error]):
                    self.append_path(result, branch, node)
                return result
        elif kind == "stop":
            if current.opened:
                self.fail("file_contract", "STOP RUN requires all-path guarded CLOSE", node)
            return []
        return [current]

    def run(self) -> ProgramIR:
        self.types()
        self.cycles()
        self.manifest_proofs()
        # Seed only alpha VALUE facts. Integer loop initialization still requires
        # an analyzed source assignment, not a declaration or guessed input.
        initial = {field.name: field.initial.rstrip(" ") for field in self.program.fields
                   if field.pic.startswith("X") and field.initial is not None
                   and field.storage == "working"}
        remaining = self.flow(self.program.paragraphs[0].statements, [_Path(frozenset(), initial)])
        if any(path.opened for path in remaining):
            self.fail("file_contract", "Main exit requires balanced cleanup")
        # Unreachable performed paragraphs still need loop proofs: no proof can
        # be excused because a current main graph does not reach its source.
        def attach(nodes: tuple[IRNode, ...]) -> tuple[IRNode, ...]:
            result = []
            for node in nodes:
                args = dict(node.args)
                if node.kind == "perform" and args["until"] is not None:
                    args["max_iterations"] = self.loop_proofs[node.span.byte_start]["max_iterations"]
                result.append(replace(node, args=args, body=attach(node.body), otherwise=attach(node.otherwise)))
            return tuple(result)
        return replace(self.program, paragraphs=tuple(replace(p, statements=attach(p.statements)) for p in self.program.paragraphs))


def validate_program(program: ProgramIR, manifest: Mapping[str, Any] | None) -> ProgramIR:
    return Validator(program, manifest).run()
