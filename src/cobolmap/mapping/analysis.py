"""Deterministic static producer; warnings and claims are not execution evidence.

This module deliberately uses exact rational bounds, not compiler arithmetic.
Bounds overapproximate independent field values and may produce false positives.
"""

from __future__ import annotations

from fractions import Fraction
from hashlib import sha256
from typing import Any, Iterator


class MappingRefusal(ValueError):
    """An invalid source binding or IR cannot be converted to a partial map."""

    code = "pointer_unresolved"


def resolve_pointer(program: Any, pointer: Any, *, raw: bytes | None = None) -> bytes:
    """Resolve an exact UTF-8 source span; optionally verify expected raw bytes.

    Neither filename equality nor a matching line number substitutes for byte/hash
    verification. Zero-width source pointers are refused by this producer.
    """
    source = program.source.encode("utf-8")
    if sha256(source).hexdigest() != program.source_sha256:
        raise MappingRefusal("pointer_unresolved: program source hash mismatch")
    if (pointer.source_sha256 != program.source_sha256
            or pointer.filename != program.filename):
        raise MappingRefusal("pointer_unresolved: pointer source identity mismatch")
    start, end = pointer.byte_start, pointer.byte_end
    if (type(start) is not int or type(end) is not int
            or not 0 <= start < end <= len(source)):
        raise MappingRefusal("pointer_unresolved: invalid half-open byte span")
    first = source[:start].count(b"\n") + 1
    last = source[:end - 1].count(b"\n") + 1
    if (pointer.line_start, pointer.line_end) != (first, last):
        raise MappingRefusal("pointer_unresolved: line/byte span disagreement")
    selected = source[start:end]
    if raw is not None and selected != raw:
        raise MappingRefusal("pointer_unresolved: expected source bytes mismatch")
    return selected


def _children(node: Any) -> Iterator[Any]:
    for value in node.args.values():
        if hasattr(value, "kind"):
            yield value
        elif isinstance(value, tuple):
            yield from (child for child in value if hasattr(child, "kind"))


def _references(node: Any) -> set[str]:
    result = {node.args["name"]} if node.kind == "reference" else set()
    for child in _children(node):
        result.update(_references(child))
    return result


def _operators(node: Any) -> int:
    return int(node.kind == "binary") + sum(_operators(c) for c in _children(node))


def _numeric(field: Any) -> bool:
    return not field.pic.upper().startswith("X")


def _signed(field: Any) -> bool:
    return field.pic.upper().startswith("S")


def _limit(field: Any) -> Fraction:
    return Fraction(10 ** field.digits - 1, 10 ** field.scale)


def _bounds(node: Any, fields: dict[str, Any]) -> tuple[Fraction, Fraction] | None:
    if node.kind == "literal" and node.args["literal_type"] == "numeric":
        value = Fraction(node.args["value"])
        return value, value
    if node.kind == "reference":
        field = fields.get(node.args["name"])
        if field is None or not _numeric(field):
            return None
        maximum = _limit(field)
        return (-maximum if _signed(field) else Fraction(0)), maximum
    if node.kind != "binary":
        return None
    left, right = (_bounds(node.args[key], fields) for key in ("left", "right"))
    if left is None or right is None:
        return None
    op = node.args["op"]
    if op == "+":
        return left[0] + right[0], left[1] + right[1]
    if op == "-":
        return left[0] - right[1], left[1] - right[0]
    if op == "*":
        products = [a * b for a in left for b in right]
        return min(products), max(products)
    if op == "/" and not right[0] <= 0 <= right[1]:
        quotients = [a / b for a in left for b in right]
        return min(quotients), max(quotients)
    return None


def _scale(node: Any, fields: dict[str, Any]) -> int | None:
    """Potential exact fractional scale; None denotes unbounded/unknown scale."""
    if node.kind == "reference":
        field = fields.get(node.args["name"])
        return field.scale if field is not None and _numeric(field) else None
    if node.kind == "literal" and node.args["literal_type"] == "numeric":
        value = node.args["value"]
        return len(value.partition(".")[2])
    if node.kind != "binary":
        return None
    left, right = (_scale(node.args[key], fields) for key in ("left", "right"))
    if left is None or right is None or node.args["op"] == "/":
        return None
    return left + right if node.args["op"] == "*" else max(left, right)


def _expression(node: Any) -> Any:
    """Create a private expression view without synthesizing source pointers."""
    if node.kind == "compute":
        return node.args["expression"]
    if node.kind == "move":
        return node.args["value"]
    if node.kind == "divide":
        return _Expr("binary", {"op": "/", "left": node.args["left"],
                                "right": node.args["right"]})
    op = {"add": "+", "subtract": "-", "multiply": "*"}[node.kind]
    return _Expr("binary", {"op": op,
                            "left": _Expr("reference", {"name": node.args["target"]}),
                            "right": node.args["value"]})


class _Expr:
    def __init__(self, kind: str, args: dict[str, Any]) -> None:
        self.kind, self.args = kind, args


def _key(node: Any) -> tuple[Any, ...]:
    if node.kind == "reference":
        return ("field", node.args["name"])
    if node.kind == "literal" and node.args["literal_type"] == "numeric":
        return ("number", Fraction(node.args["value"]))
    return ("unknown",)


def _nonzero(condition: Any, truth: bool) -> set[tuple[Any, ...]]:
    if condition.kind == "boolean":
        left = _nonzero(condition.args["left"], truth)
        right = _nonzero(condition.args["right"], truth)
        both = (condition.args["op"] == "AND") == truth
        return left | right if both else left & right
    if condition.kind != "compare":
        return set()
    left, right = condition.args["left"], condition.args["right"]
    op = condition.args["op"]
    if _key(left) == ("number", Fraction(0)):
        left, right = right, left
        op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)
    if _key(right) != ("number", Fraction(0)):
        return set()
    if (truth and op in {"<>", "<", ">"}) or (not truth and op == "="):
        key = _key(left)
        return {key} if key != ("unknown",) else set()
    return set()


def _divisors(expression: Any) -> Iterator[Any]:
    if expression.kind == "binary" and expression.args["op"] == "/":
        yield expression.args["right"]
    for child in _children(expression):
        yield from _divisors(child)


def _dsl_expression(node: Any) -> dict[str, Any] | None:
    """Only exact constants/fields and linear +- / constant scaling, no eval."""
    if node.kind == "literal":
        return {"kind": "constant", "type": node.args["literal_type"],
                "value": node.args["value"]}
    if node.kind == "reference":
        return {"kind": "field", "name": node.args["name"]}
    if node.kind != "binary":
        return None
    left, right = (_dsl_expression(node.args[k]) for k in ("left", "right"))
    if left is None or right is None:
        return None
    op = node.args["op"]
    numeric_constant = lambda value: value.get("kind") == "constant" and value.get("type") == "numeric"
    if op == "*" and not (numeric_constant(left) or numeric_constant(right)):
        return None
    if op == "/" and not (numeric_constant(right) and Fraction(right["value"]) != 0):
        return None
    if op not in {"+", "-", "*", "/"}:
        return None
    return {"kind": "binary", "op": op, "left": left, "right": right}


def _dsl_guards(condition: Any, truth: bool) -> list[dict[str, Any]] | None:
    if condition.kind == "boolean":
        # B0 is a conjunction; De Morgan is used only when it remains one.
        if (condition.args["op"] == "AND") != truth:
            return None
        left = _dsl_guards(condition.args["left"], truth)
        right = _dsl_guards(condition.args["right"], truth)
        return None if left is None or right is None else left + right
    if condition.kind != "compare":
        return None
    left, right = (_dsl_expression(condition.args[k]) for k in ("left", "right"))
    if left is None or right is None:
        return None
    # Closed B0 guard operands are fields or constants, not arithmetic.
    if left["kind"] == "binary" or right["kind"] == "binary":
        return None
    op = condition.args["op"]
    if not truth:
        op = {"=": "<>", "<>": "=", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}[op]
    return [{"left": left, "op": "!=" if op == "<>" else op, "right": right}]


def produce(program: Any) -> dict[str, Any]:
    """Produce private JSON-shaped components for the shared contract adapter."""
    raw = program.source.encode("utf-8")
    if sha256(raw).hexdigest() != program.source_sha256:
        raise MappingRefusal("pointer_unresolved: source hash mismatch")
    fields = {field.name: field for field in program.fields}
    paragraphs = {paragraph.name: paragraph for paragraph in program.paragraphs}
    if len(fields) != len(program.fields) or len(paragraphs) != len(program.paragraphs):
        raise MappingRefusal("duplicate IR field/paragraph")
    effects: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    hazards: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    bindings = {file.name: file for file in program.files}

    def hazard(code: str, node: Any, message: str) -> None:
        involved = _references(node)
        if "target" in node.args:
            involved.add(node.args["target"])
        if "file" in node.args and node.args["file"] in bindings:
            involved.add(bindings[node.args["file"]].status_name)
        if node.kind == "write":
            involved.update(f.name for f in program.fields if f.record_name == node.args["record"])
        hazards.append({"hazard_id": code, "rule_version": "1",
                        "status": "static_warning", "message": message,
                        "source": node.span, "fields": sorted(involved)})

    def validate(node: Any) -> None:
        spelling = resolve_pointer(program, node.span).decode("utf-8")
        if node.kind == "reference" and spelling.upper() != node.args["name"]:
            raise MappingRefusal("pointer_unresolved: reference/raw span mismatch")
        if node.kind == "literal":
            if node.args["literal_type"] == "numeric":
                # The lexer allows a separate sign token with intervening space.
                literal = "".join(spelling.split())
            else:
                if len(spelling) < 2 or spelling[0] not in {"'", '\"'} or spelling[-1] != spelling[0]:
                    raise MappingRefusal("pointer_unresolved: quoted literal/raw span mismatch")
                literal = spelling[1:-1].replace(spelling[0] * 2, spelling[0])
            if literal != node.args["value"]:
                raise MappingRefusal("pointer_unresolved: literal/raw span mismatch")
        for name in _references(node):
            if name not in fields and name != "RETURN-CODE":
                raise MappingRefusal("unresolved IR field: " + name)
        for child in _children(node):
            validate(child)

    def walk(nodes: tuple[Any, ...], paragraph: str, prefix: str,
             guards: tuple[tuple[Any, bool], ...] = (),
             nonzero: frozenset[tuple[Any, ...]] = frozenset(),
             continuation: str | None = None) -> None:
        for position, node in enumerate(nodes):
            validate(node)
            location = f"{prefix}/{position}"
            identifier = location
            successor = f"{prefix}/{position + 1}" if position + 1 < len(nodes) else continuation
            reads = _references(node)
            writes: set[str] = set()
            kind = node.kind
            if "target" in node.args:
                target = node.args["target"]
                if target not in fields and target != "RETURN-CODE":
                    raise MappingRefusal("unresolved IR target: " + target)
                writes.add(target)
                if kind in {"add", "subtract", "multiply"}:
                    reads.add(target)
            if kind in {"open", "read", "close"}:
                binding = bindings.get(node.args["file"])
                if binding is None:
                    raise MappingRefusal("unresolved IR file")
                writes.add(binding.status_name)
                if kind == "read":
                    writes.update(f.name for f in program.fields if f.record_name == binding.record_name)
                # A later condition does not dominate this operation, and merely
                # testing status does not demonstrate all error paths are handled.
                hazard("H3", node, "File status handling on every relevant path is not established.")
            elif kind == "write":
                record = node.args["record"]
                matching = [b for b in program.files if b.record_name == record]
                if len(matching) != 1:
                    raise MappingRefusal("unresolved IR output record")
                reads.update(f.name for f in program.fields if f.record_name == record)
                writes.add(matching[0].status_name)
                hazard("H3", node, "File status handling on every relevant path is not established.")
            effects.append({"id": identifier, "paragraph": paragraph, "path": location,
                            "kind": kind, "reads": sorted(reads), "writes": sorted(writes),
                            "source": node.span,
                            "observable": "stdout" if kind == "display" else "output_record" if kind == "write" else None,
                            "max_iterations": node.args.get("max_iterations") if kind == "perform" else None})
            if successor is not None and kind not in {"if", "stop"}:
                edges.append({"from": identifier, "to": successor,
                              "kind": ("until_true_or_return" if node.args["until"] is not None else "continuation") if kind == "perform" else "success",
                              "source": node.span})
            if kind == "perform":
                called = node.args["paragraph"]
                if called not in paragraphs:
                    raise MappingRefusal("unresolved IR paragraph: " + called)
                edges.append({"from": identifier, "to": "paragraph:" + called,
                              "kind": "perform_until_false" if node.args["until"] is not None else "perform",
                              "source": node.span})
            if kind in {"move", "add", "subtract", "multiply", "divide", "compute"}:
                target = fields.get(node.args["target"])
                expression = _expression(node)
                if target is not None and _numeric(target):
                    scale = _scale(expression, fields)
                    if not node.args.get("rounded", False) and (scale is None or scale > target.scale):
                        hazard("H1", node, "Assignment may discard a nonzero fractional part without ROUNDED.")
                    if kind != "move" and not node.args["has_size_error"]:
                        bounds = _bounds(expression, fields)
                        low = -_limit(target) if _signed(target) else Fraction(0)
                        if bounds is None or bounds[0] < low or bounds[1] > _limit(target):
                            hazard("H2", node, "Arithmetic may exceed the destination range without ON SIZE ERROR.")
                    if kind == "move" and not _signed(target):
                        value = node.args["value"]
                        source_field = fields.get(value.args.get("name")) if value.kind == "reference" else None
                        negative_literal = value.kind == "literal" and value.args["value"].startswith("-")
                        if (source_field is not None and _signed(source_field)) or negative_literal:
                            hazard("H5", node, "Signed numeric MOVE to an unsigned destination may lose sign, including signed zero.")
                    if kind != "move":
                        year_names = {name for name in reads if name in fields
                                      and fields[name].digits == 2
                                      and ("YEAR" in name or name in {"YY", "YR"}
                                           or name.endswith(("-YY", "-YR")))}
                        for name in sorted(year_names):
                            # Explicit pivot guards must dominate this statement.
                            pivot = any(c.kind == "compare" and c.args["op"] in {"<", "<=", ">", ">="}
                                        and name in _references(c)
                                        and any(child.kind == "literal" and child.args["literal_type"] == "numeric"
                                                and 0 < Fraction(child.args["value"]) < 100
                                                for child in _children(c)) for c, _ in guards)
                            if not pivot:
                                hazard("H4", node, "Two-digit year arithmetic lacks a recognized dominating explicit pivot guard: " + name)
                if kind == "move" and target is not None and not _numeric(target):
                    value = node.args["value"]
                    source_field = fields.get(value.args.get("name")) if value.kind == "reference" else None
                    width = source_field.width if source_field is not None and not _numeric(source_field) else (
                        len(value.args["value"].encode("ascii")) if value.kind == "literal" and value.args["literal_type"] == "alpha" else None)
                    if width is not None and width != target.width:
                        hazard("H6", node, "Alphanumeric MOVE widths differ; padding or truncation is possible.")
                for divisor in _divisors(expression):
                    bounds = _bounds(divisor, fields)
                    proven = bounds is not None and not bounds[0] <= 0 <= bounds[1]
                    if not proven and _key(divisor) not in nonzero:
                        hazard("H7", node, "Divisor lacks a recognized dominating nonzero check.")
                if kind == "compute" and _operators(expression) >= 2:
                    hazard("H8", node, "COMPUTE has multiple binary operators; intermediate precision requires pinned probes.")
                # This is a local assignment relation, never a claim that final
                # output equals a field read earlier or that a path is reachable.
                relation = _dsl_expression(expression)
                closed_guards: list[dict[str, Any]] = []
                for condition, truth in guards:
                    part = _dsl_guards(condition, truth)
                    if part is None:
                        relation = None
                        break
                    closed_guards.extend(part)
                if relation is not None and target is not None and target.storage == "output":
                    claims.append({"source": node.span, "target": target.name,
                                   "guards": closed_guards, "expression": relation,
                                   "scope": "assignment", "status": "claim_untestable",
                                   "reason": "Local symbolic relation only; compiler semantics, reachability and final observability are unverified.",
                                   "rounded": bool(node.args.get("rounded", False)),
                                   "destination_scale": target.scale})
            if kind == "if":
                condition = node.args["condition"]
                for truth, children, label in ((True, node.body, "then"), (False, node.otherwise, "else")):
                    destination = location + "/" + label + "/0" if children else successor
                    if destination is not None:
                        edges.append({"from": identifier, "to": destination,
                                      "kind": label, "source": condition.span})
                    walk(children, paragraph, location + "/" + label,
                         guards + ((condition, truth),), nonzero | frozenset(_nonzero(condition, truth)), successor)
            else:
                # A conditional write can invalidate a guard in the enclosing
                # sequence. Remove facts for every field possibly written below.
                if node.body:
                    edges.append({"from": identifier, "to": location + "/body/0",
                                  "kind": "at_end" if kind == "read" else "size_error",
                                  "source": node.span})
                body_nonzero = frozenset(k for k in nonzero
                                         if not (k[0] == "field" and k[1] in writes))
                body_guards = tuple((c, t) for c, t in guards if not (_references(c) & writes))
                walk(node.body, paragraph, location + "/body", body_guards, body_nonzero, successor)
                walk(node.otherwise, paragraph, location + "/otherwise", body_guards, body_nonzero, successor)
            affected = set(writes)
            def nested_writes(children: tuple[Any, ...]) -> None:
                for child in children:
                    if "target" in child.args:
                        affected.add(child.args["target"])
                    if child.kind in {"read", "perform", "open", "write", "close"}:
                        # Calls and file side effects invalidate all facts here.
                        affected.update(fields)
                    nested_writes(child.body)
                    nested_writes(child.otherwise)
            nested_writes(node.body)
            nested_writes(node.otherwise)
            if kind == "perform":
                affected.update(fields)
            nonzero = frozenset(k for k in nonzero if not (k[0] == "field" and k[1] in affected))
            guards = tuple((c, t) for c, t in guards if not (_references(c) & affected))

    for field in program.fields:
        resolve_pointer(program, field.span)
    for paragraph in program.paragraphs:
        resolve_pointer(program, paragraph.span)
        if paragraph.statements:
            edges.append({"from": "paragraph:" + paragraph.name,
                          "to": "paragraph:" + paragraph.name + "/0",
                          "kind": "entry", "source": paragraph.span})
        walk(paragraph.statements, paragraph.name, "paragraph:" + paragraph.name)
    return {"source_sha256": program.source_sha256, "filename": program.filename,
            "program_id": program.program_id,
            "fields": [{"name": f.name, "pic": f.pic, "usage": f.usage, "sign": f.sign,
                        "offset": f.offset, "width": f.width, "scale": f.scale,
                        "digits": f.digits, "storage": f.storage,
                        "record_name": f.record_name, "initial": f.initial,
                        "source": f.span} for f in program.fields],
            "paragraphs": [{"name": p.name, "source": p.span} for p in program.paragraphs],
            "effects": effects, "control_edges": edges, "hazards": hazards, "claims": claims}
