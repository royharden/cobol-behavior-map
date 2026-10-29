"""Static candidate-loop reproof after a structured edit; never executes COBOL.

Only the declared subset's constant monotone integer proof form is accepted.
This is compiler input reasoning, never an admission/custody/observed receipt.
"""
from cobolmap.shared.decimal_shim import decimal_value
from .normalize import need


def reprove_edited_loops(plan, changed_byte_start, changed_arithmetic_targets):
    fields = {f["name"]: f for f in plan["fields"]}
    paragraphs = {p["name"]: p["body"] for p in plan["paragraphs"]}
    proofs, budget, visited = [], [0], set()

    def integer(node, known):
        if node["kind"] == "reference":
            return known.get(node["name"])
        if node["kind"] != "literal" or node["literal_type"] != "numeric":
            return None
        value = decimal_value(node["value"])
        quotient, remainder = divmod(value.coefficient, 10 ** value.scale)
        return None if remainder else quotient

    def relation(left, op, right):
        return {"=": left == right, "<>": left != right, "<": left < right,
                "<=": left <= right, ">": left > right, ">=": left >= right}[op]

    def steps(nodes, induction):
        totals = {0}
        for node in nodes:
            kind = node["kind"]
            delta = {0}
            if kind in ("move", "add", "subtract", "multiply", "divide", "compute") and node["target"] == induction:
                value = integer(node.get("value", {"kind": "missing"}), {})
                need(kind in ("add", "subtract") and value is not None and
                     node["value"]["kind"] == "literal" and not node["has_size_error"],
                     "change_requires_proof", "induction update not a constant unhandled ADD/SUBTRACT")
                delta = {value * (-1 if kind == "subtract" else 1)}
            elif kind == "read":
                need(fields[induction]["storage"] != "input", "change_requires_proof", "READ can invalidate induction")
                delta = {0} | steps(node["body"], induction)
            elif kind == "if":
                delta = steps(node["body"], induction) | steps(node["otherwise"], induction)
            elif kind == "perform":
                need(node["until"] is None, "change_requires_proof", "nested induction loop not in proof form")
                delta = steps(paragraphs[node["paragraph"]], induction)
            elif kind in ("add", "subtract", "multiply", "divide", "compute") and node["has_size_error"]:
                delta = {0} | steps(node["body"], induction)
            totals = {left + right for left in totals for right in delta}
            need(len(totals) <= 64, "change_requires_proof", "induction path proof too wide")
        return totals

    def walk(nodes, known):
        known = dict(known)
        for node in nodes:
            budget[0] += 1
            need(budget[0] <= 100000, "change_requires_proof", "static proof budget exceeded")
            kind = node["kind"]
            if kind == "if":
                left, right = walk(node["body"], known), walk(node["otherwise"], known)
                known = {name: value for name, value in left.items() if right.get(name) == value}
            elif kind == "perform":
                body = paragraphs[node["paragraph"]]
                if node["until"] is None:
                    known = walk(body, known)
                    continue
                test = node["until"]
                visited.add(id(node))
                need(test["kind"] == "compare" and test["left"]["kind"] == "reference"
                     and test["right"]["kind"] == "literal", "change_requires_proof", "integer field/literal loop test required")
                field, limit = test["left"]["name"], integer(test["right"], {})
                need(field in fields and fields[field]["scale"] == 0 and fields[field]["digits"] > 0
                     and limit is not None and field in known, "change_requires_proof", "loop initializer/type missing")
                deltas = steps(body, field)
                need(len(deltas) == 1 and next(iter(deltas)) != 0,
                     "change_requires_proof", "all loop paths require one nonzero constant step")
                step, initial = next(iter(deltas)), known[field]
                current, count = initial, 0
                maximum = 10 ** fields[field]["digits"] - 1
                minimum = -maximum if fields[field]["pic"].startswith("S") else 0
                while not relation(current, test["op"], limit):
                    need(count < 64, "change_requires_proof", "edited loop exceeds subset bound or never exits")
                    current += step
                    count += 1
                    need(minimum <= current <= maximum, "change_requires_proof", "induction overflows its PIC")
                for _ in range(count):
                    known = walk(body, known)
                need(known.get(field) == current, "change_requires_proof", "induction data flow disagrees")
                node["max_iterations"] = max(1, count)
                proofs.append({"span": node["span"], "field": field, "initial": initial,
                               "step": step, "limit": limit, "relation": test["op"], "iterations": count})
            elif kind in ("move", "add", "subtract", "multiply", "divide", "compute"):
                before = dict(known)
                target = node["target"]
                value = integer(node.get("value", {"kind": "missing"}), known)
                if kind == "move" and value is not None:
                    known[target] = abs(value) if target in fields and not fields[target]["pic"].startswith("S") else value
                elif kind in ("add", "subtract") and target in known and value is not None and not node["has_size_error"]:
                    known[target] += value * (-1 if kind == "subtract" else 1)
                else:
                    known.pop(target, None)
                if target in known and target in fields:
                    field = fields[target]
                    maximum = 10 ** field["digits"] - 1
                    minimum = -maximum if field["pic"].startswith("S") else 0
                    if field["scale"] != 0 or not minimum <= known[target] <= maximum:
                        known.pop(target, None)
                if kind != "move" and node["has_size_error"]:
                    handled = walk(node["body"], before)
                    known = {name: value for name, value in known.items() if handled.get(name) == value}
            elif kind == "read":
                known = {name: value for name, value in known.items() if fields.get(name, {}).get("storage") != "input"}
                at_end = walk(node["body"], known)
                known = {name: value for name, value in known.items() if at_end.get(name) == value}
        return known
    walk(paragraphs["MAIN"], {})
    def check_unreached(nodes):
        for node in nodes:
            if node["kind"] == "perform" and node["until"] is not None and id(node) not in visited:
                test = node["until"]
                need(test["kind"] == "compare" and test["left"]["kind"] == "reference",
                     "change_requires_proof", "unreached loop proof shape")
                field = test["left"]["name"]
                need(not (test["span"]["byte_start"] <= changed_byte_start < test["span"]["byte_end"])
                     and field not in changed_arithmetic_targets,
                     "change_requires_proof", "edited unreached loop lacks dominating initializer context")
            check_unreached(node["body"])
            check_unreached(node["otherwise"])
    for paragraph in plan["paragraphs"]:
        check_unreached(paragraph["body"])
    plan["candidate_loop_proofs"] = proofs
