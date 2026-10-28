"""Exactly one native structured-edit mapping; never applies arbitrary text."""
from collections.abc import Mapping
import re
from fractions import Fraction

from cobolmap.shared.decimal_shim import decimal_value
from .normalize import ARITHMETIC, TranslationRefusal, need, validate_nodes
from .bounds import reprove_edited_loops


def _all_nodes(plan):
    def visit(node, ancestors):
        yield node, ancestors
        for key in ("value", "left", "right", "expression", "condition", "until"):
            value = node.get(key)
            if isinstance(value, dict):
                yield from visit(value, ancestors + [node])
        for key in ("values", "body", "otherwise"):
            for child in node.get(key, []):
                yield from visit(child, ancestors + [node])
    for paragraph in plan["paragraphs"]:
        for node in paragraph["body"]:
            yield from visit(node, [])


def apply_change(plan, change):
    """Mutate this private normalized copy, preserving original source identity."""
    keys = {"manifest_version", "task_id", "original_sha256", "target", "operation",
            "before", "after", "prose", "changed_sha256"}
    need(isinstance(change, Mapping) and set(change) == keys,
         "unsupported_change", "native structured-edit mapping required")
    need(type(change["manifest_version"]) is int and change["manifest_version"] == 1,
         "unsupported_change", "change version")
    need(type(change["task_id"]) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", change["task_id"]),
         "unsupported_change", "task identifier")
    need(change["original_sha256"] == plan["source_sha256"], "change_source_hash", "original source mismatch")
    need(type(change["changed_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", change["changed_sha256"])
         and change["changed_sha256"] != plan["source_sha256"], "change_source_hash", "changed source commitment required")
    need(type(change["prose"]) is str and change["prose"], "unsupported_change", "change prose required")
    target = change["target"]
    need(isinstance(target, Mapping) and set(target) == {"file", "line", "byte_start", "byte_end", "node_kind"},
         "change_target", "closed source target required")
    matches = []
    entries = list(_all_nodes(plan))
    for node, parents in entries:
        pointer = node["span"]
        if (target["file"] == pointer["filename"] and type(target["line"]) is int
                and target["line"] == pointer["line_start"]
                and type(target["byte_start"]) is int and type(target["byte_end"]) is int
                and target["byte_start"] == pointer["byte_start"]
                and target["byte_end"] == pointer["byte_end"] and target["node_kind"] == node["kind"]):
            matches.append((node, parents))
    need(len(matches) == 1, "change_target", "target must resolve to exactly one IR node")
    node, ancestors = matches[0]
    operation, before, after = change["operation"], change["before"], change["after"]
    fields = {field["name"]: field for field in plan["fields"]}
    if operation in ("replace_numeric_literal", "replace_alpha_literal"):
        category = "numeric" if operation == "replace_numeric_literal" else "alpha"
        allowed = ARITHMETIC | {"compare"} if category == "numeric" else {"move", "compare"}
        need(node["kind"] == "literal" and node["literal_type"] == category
             and any(parent["kind"] in allowed for parent in ancestors), "change_target", "literal context")
        need(type(before) is str and type(after) is str and node["value"] == before,
             "change_target", "literal before/type mismatch")
        need(before != after, "change_noop", "identical replacement")
        if category == "numeric":
            old, new = decimal_value(before), decimal_value(after)
            need(Fraction(old.coefficient, 10 ** old.scale) != Fraction(new.coefficient, 10 ** new.scale)
                 or old.negative_zero != new.negative_zero, "change_noop", "same numeric value/sign")
        else:
            need(before.rstrip(" ") != after.rstrip(" "), "change_noop", "same space-padded alpha value")
            need(all(32 <= ord(c) <= 126 for c in after), "change_out_of_subset", "alpha replacement encoding")
            widths = []
            for parent in ancestors:
                if parent["kind"] == "move":
                    widths.append(fields[parent["target"]]["width"])
                elif parent["kind"] == "compare":
                    widths.extend(fields[parent[key]["name"]]["width"] for key in ("left", "right")
                                  if parent[key]["kind"] == "reference")
            need(widths and len(after) <= min(widths), "change_out_of_subset", "alpha replacement must fit context")
        node["value"] = after
    elif operation == "replace_comparator":
        need(node["kind"] == "compare" and any(parent["kind"] == "if" for parent in ancestors),
             "change_target", "numeric IF comparison required")
        need(all((child["kind"] == "literal" and child["literal_type"] == "numeric") or
                 (child["kind"] == "reference" and not fields[child["name"]]["pic"].startswith("X"))
                 for child in (node["left"], node["right"])), "change_target", "numeric comparison required")
        need(type(before) is str and type(after) is str and node["op"] == before,
             "change_target", "comparator before mismatch")
        need(after in ("=", "<>", "<", "<=", ">", ">="), "unsupported_change", "comparator vocabulary")
        need(before != after, "change_noop", "identical comparator")
        node["op"] = after
    elif operation == "set_rounded":
        need(node["kind"] in ARITHMETIC and type(before) is bool and type(after) is bool
             and node["rounded"] == before, "change_target", "ROUNDED target/before")
        need(before != after, "change_noop", "unchanged ROUNDED")
        node["rounded"] = after
    else:
        raise TranslationRefusal("unsupported_change", "unknown structured operation")
    validate_nodes(plan)
    affected = {parent["target"] for parent in ancestors if parent["kind"] in ARITHMETIC}
    reprove_edited_loops(plan, node["span"]["byte_start"],
                        affected if operation == "replace_numeric_literal" else set())
