"""Static source-linked COBOL mapping facade.

No compiler execution, semantic parity, reachable witness, or tested support is
established here. A Claim is an untested hypothesis in the shared closed B0 DSL.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from cobolmap.contracts import (
    BehaviorMap, Claim, ControlEdge, Effect, FieldRef, FieldValue, Hazard,
    LinearTerm, LinearValue, LiteralValue, MapField, MapParagraph, OutputEquality,
)
from cobolmap.parse.models import ProgramIR

from .analysis import MappingRefusal, produce, resolve_pointer

__all__ = ["build_map", "MappingRefusal", "resolve_pointer"]


def _decimal(value: Fraction) -> str | None:
    """Return exact finite decimal text or refuse nonterminating coefficients."""
    denominator = value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        return None
    scale = max(twos, fives)
    coefficient = abs(value.numerator) * 2 ** (scale - twos) * 5 ** (scale - fives)
    digits = str(coefficient).rjust(scale + 1, "0")
    result = digits[:-scale] + "." + digits[-scale:] if scale else digits
    return ("-" if value < 0 else "") + result


def _linear(expression: dict[str, Any], fields: dict[str, Any]) -> tuple[dict[str, Fraction], Fraction] | None:
    kind = expression["kind"]
    if kind == "constant":
        if expression["type"] != "numeric":
            return None
        return {}, Fraction(expression["value"])
    if kind == "field":
        field = fields.get(expression["name"])
        if field is None or field.storage != "input" or field.pic.startswith("X"):
            return None
        return {field.name: Fraction(1)}, Fraction(0)
    if kind != "binary":
        return None
    left, right = (_linear(expression[k], fields) for k in ("left", "right"))
    if left is None or right is None:
        return None
    op = expression["op"]
    if op in {"+", "-"}:
        terms = dict(left[0])
        factor = 1 if op == "+" else -1
        for name, coefficient in right[0].items():
            terms[name] = terms.get(name, Fraction(0)) + factor * coefficient
        return {name: value for name, value in terms.items() if value}, left[1] + factor * right[1]
    if op == "*":
        if left[0] and right[0]:
            return None
        terms, constant = left if not right[0] else right
        scalar = right[1] if not right[0] else left[1]
        return {name: value * scalar for name, value in terms.items()}, constant * scalar
    if op == "/" and not right[0] and right[1] != 0:
        return {name: value / right[1] for name, value in left[0].items()}, left[1] / right[1]
    return None


def _claim_value(candidate: dict[str, Any], fields: dict[str, Any]) -> Any | None:
    target = fields[candidate["target"]]
    expression = candidate["expression"]
    if target.pic.startswith("X"):
        if expression["kind"] == "constant" and expression["type"] == "alpha":
            if len(expression["value"].encode("ascii")) == target.width:
                return LiteralValue(value_type="alpha", value=expression["value"])
        if expression["kind"] == "field":
            source = fields.get(expression["name"])
            if source is not None and source.storage == "input" and source.pic.startswith("X") and source.width == target.width:
                return FieldValue(field=FieldRef(scope="input", name=source.name))
        return None
    linear = _linear(expression, fields)
    if linear is None:
        return None
    terms, constant = linear
    coefficients = {name: _decimal(value) for name, value in terms.items()}
    text = _decimal(constant)
    if text is None or any(value is None for value in coefficients.values()):
        return None
    # Unsigned sign transfer and negative zero have unresolved MOVE semantics.
    # Do not flatten either into the B0 arithmetic rounding functions.
    if not target.pic.startswith("S") and (
            constant < 0 or any(fields[name].pic.startswith("S") or value < 0 for name, value in terms.items())):
        return None
    if expression["kind"] == "constant" and expression["value"].startswith("-") and constant == 0:
        return None
    return LinearValue(terms=tuple(LinearTerm(field=FieldRef(scope="input", name=name), coefficient=coefficients[name])
                                   for name in sorted(coefficients)),
                       constant=text, scale=target.scale,
                       rounding="nearest_ties_away" if candidate["rounded"] else "truncate_toward_zero")


def _final_claims(program: ProgramIR, payload: dict[str, Any]) -> tuple[Claim, ...]:
    """Small final-observability boundary; omission is preferable to wider claims.

    Only one straight-line MAIN output emission is supported. No calls, branches,
    handler bodies, output-state expressions, or mutable input snapshots are
    represented as final-output claims. Other program maps still retain effects
    and warnings. This boundary does not establish compiler arithmetic semantics.
    """
    main = next((p for p in program.paragraphs if p.name == "MAIN"), None)
    if main is None:
        return ()
    nodes = main.statements
    if any(n.kind in {"if", "perform"} or n.body or n.otherwise for n in nodes):
        return ()
    writes = [i for i, n in enumerate(nodes) if n.kind == "write"]
    reads = [i for i, n in enumerate(nodes) if n.kind == "read"]
    if len(writes) != 1 or len(reads) > 1:
        return ()
    write_at = writes[0]
    if reads and reads[0] >= write_at:
        return ()
    fields = {f.name: f for f in program.fields}
    if any(n.args.get("target") in fields and fields[n.args["target"]].storage == "input" for n in nodes):
        return ()
    last_assignment: dict[str, Any] = {}
    for node in nodes[:write_at]:
        if "target" in node.args:
            last_assignment[node.args["target"]] = node
    candidates = {c["source"].byte_start: c for c in payload["claims"]}
    claims: list[Claim] = []
    for name in sorted(last_assignment):
        node = last_assignment[name]
        if fields.get(name) is None or fields[name].storage != "output":
            continue
        candidate = candidates.get(node.span.byte_start)
        if candidate is None or candidate["guards"]:
            continue
        value = _claim_value(candidate, fields)
        if value is None:
            continue
        # A comparison to input means the record read for this emission. Without
        # an actual READ, no input-field value is claimed.
        linear = _linear(candidate["expression"], fields)
        uses_input = (linear is not None and bool(linear[0])) or (
            candidate["expression"]["kind"] == "field")
        if uses_input and (not reads or node.span.byte_start < nodes[reads[0]].span.byte_end):
            continue
        claims.append(Claim(claim_id=f"assignment-{len(claims) + 1:04d}", span=node.span,
                            assertion=OutputEquality(field=FieldRef(scope="output", name=name), expected=value)))
    return tuple(claims)


def build_map(program: ProgramIR) -> BehaviorMap:
    """Construct the shared static-only BehaviorMap or refuse invalid bindings."""
    payload = produce(program)
    mapped_fields = tuple(MapField(
        name=f["name"], pic=f["pic"], usage=f["usage"], sign=f["sign"],
        offset=f["offset"], width=f["width"], scale=f["scale"], digits=f["digits"],
        initial=f["initial"], storage=f["storage"], span=f["source"],
    ) for f in payload["fields"])
    paragraphs = tuple(MapParagraph(
        name=p["name"], span=p["source"],
        statement_spans=tuple(e["source"] for e in payload["effects"] if e["paragraph"] == p["name"]),
    ) for p in payload["paragraphs"])
    edge_kind = {"perform": "perform", "perform_until_false": "perform",
                 "then": "branch", "else": "branch", "size_error": "branch", "at_end": "branch"}
    edges = tuple(ControlEdge(source=e["from"], target=e["to"],
                              kind=edge_kind.get(e["kind"], "sequence"), span=e["source"])
                  for e in payload["control_edges"])
    effect_kind = {"read": "read", "write": "write", "display": "display",
                   "move": "assign", "add": "assign", "subtract": "assign", "multiply": "assign",
                   "divide": "assign", "compute": "assign", "stop": "return"}
    effects = tuple(Effect(kind=effect_kind.get(e["kind"], "control"), span=e["source"],
                           reads=tuple(e["reads"]), writes=tuple(e["writes"]),
                           description=e["path"] + ": " + e["kind"] + (
                               "; emits " + e["observable"] if e["observable"] else ""))
                    for e in payload["effects"])
    hazards = tuple(Hazard(hazard_id=h["hazard_id"], span=h["source"],
                           description="rule-v" + h["rule_version"] + ": " + h["message"],
                           fields=tuple(h["fields"]))
                    for h in payload["hazards"])
    return BehaviorMap(source_sha256=program.source_sha256, filename=program.filename,
                       fields=mapped_fields, paragraphs=paragraphs, edges=edges,
                       effects=effects, hazards=hazards, claims=_final_claims(program, payload))
