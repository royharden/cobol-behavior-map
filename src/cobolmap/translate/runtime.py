"""In-memory candidate runtime; never an oracle or a host execution launcher.

All numeric/file/default-value policies are construction hypotheses. No compiler
probe has established parity. This module exposes no paths, clock, I/O or eval.
"""
from cobolmap.shared.codec import decode_record, encode_record, format_display
from cobolmap.shared.decimal_shim import (DecimalValue, FieldSpec, ShimError,
                                        arithmetic, compare, compute, decimal_value, move)


class RuntimeFault(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def require(condition, code, message):
    if not condition:
        raise RuntimeFault(code, message)


class _State:
    def __init__(self, plan, input_present, records):
        require(type(plan) is dict and plan.get("version") == 1, "runtime_plan", "closed version1 plan required")
        require(type(input_present) is bool and type(records) in (list, tuple)
                and len(records) <= 64 and (input_present or not records), "file_contract", "CaseBundle presence/records")
        require(all(type(row) is bytes and 1 <= len(row) <= 8192 for row in records), "file_contract", "record bytes")
        self.plan, self.present, self.records = plan, input_present, tuple(records)
        self.specs = {field["name"]: FieldSpec.from_mapping({key: field[key] for key in
            ("name", "pic", "usage", "sign", "offset", "width", "scale", "digits")}) for field in plan["fields"]}
        self.values = {}
        for field in plan["fields"]:
            spec = self.specs[field["name"]]
            # Explicit hypothesis, not an observed compiler default.
            value = field["initial"] if field["initial"] is not None else ("" if spec.is_alpha else "0")
            initial = move(value if spec.is_alpha else decimal_value(value), None, spec)
            self.assign(field["name"], initial)
        self.files = {file["name"]: {**file, "open": False, "available": False} for file in plan["files"]}
        self.paragraphs = {p["name"]: p["body"] for p in plan["paragraphs"]}
        require(len(self.files) == 2 and "MAIN" in self.paragraphs, "runtime_plan", "file/MAIN binding")
        self.input_index, self.return_code, self.steps = 0, 0, 0
        self.output_present, self.output_records, self.stdout = False, [], bytearray()
        self.output_size = 0
        self.active = set()

    def assign(self, name, result):
        if result.fault_or_null is not None:
            raise RuntimeFault(result.fault_or_null.code, result.fault_or_null.message)
        require(result.value is not None, "assignment_fault", "assignment produced no value")
        self.values[name] = result.value

    def atom(self, node):
        kind = node["kind"]
        if kind == "literal":
            return decimal_value(node["value"]) if node["literal_type"] == "numeric" else node["value"]
        if kind == "reference":
            require(node["name"] in self.values, "pointer_unresolved", "unknown field")
            return self.values[node["name"]]
        raise RuntimeFault("unsupported_expression", "atom required")

    def condition(self, node):
        if node["kind"] == "compare":
            return compare(self.atom(node["left"]), node["op"], self.atom(node["right"]))
        require(node["kind"] == "boolean", "unsupported_expression", "condition required")
        if node["op"] == "AND":
            return self.condition(node["left"]) and self.condition(node["right"])
        require(node["op"] == "OR", "unsupported_expression", "boolean operator")
        return self.condition(node["left"]) or self.condition(node["right"])

    def numeric_tree(self, node):
        if node["kind"] == "literal":
            require(node["literal_type"] == "numeric", "shim_type", "numeric literal required")
            return {"kind": "literal", "value": node["value"]}
        if node["kind"] == "reference":
            return {"kind": "reference", "name": node["name"]}
        require(node["kind"] == "binary", "unsupported_expression", "closed COMPUTE tree")
        return {"kind": "binary", "operator": node["op"],
                "left": self.numeric_tree(node["left"]), "right": self.numeric_tree(node["right"])}

    def status(self, file, text):
        require(file["status"] in self.specs, "file_contract", "missing status field")
        self.assign(file["status"], move(text, None, self.specs[file["status"]]))

    def record_fields(self, file):
        require(all(name in self.specs for name in file["fields"]), "file_contract", "unresolved record fields")
        return [self.specs[name] for name in file["fields"]]

    def display(self, node):
        output = bytearray()
        for expression in node["values"]:
            value = self.atom(expression)
            if isinstance(value, str):
                output.extend(value.encode("ascii"))
            else:
                require(expression["kind"] == "reference", "unsupported_expression", "DISPLAY numeric field")
                original = self.specs[expression["name"]]
                # Explicit unverified DISPLAY hypothesis for internal numeric items:
                # render picture digits with implied point and a separate sign.
                spec = FieldSpec(name=original.name, pic=original.pic, usage="DISPLAY",
                                 sign="LEADING SEPARATE" if original.signed else None,
                                 width=original.digits + int(original.signed),
                                 digits=original.digits, scale=original.scale)
                output.extend(format_display(value, spec))
        output.extend(b"\n")
        require(len(self.stdout) + len(output) <= 1048576, "output_cap", "stdout cap")
        self.stdout.extend(output)

    def paragraph(self, name):
        require(name in self.paragraphs and name not in self.active, "control_flow", "unknown/recursive PERFORM")
        self.active.add(name)
        try:
            return self.block(self.paragraphs[name])
        finally:
            self.active.remove(name)

    def block(self, nodes):
        for node in nodes:
            self.steps += 1
            require(self.steps <= 100000, "resource_cap", "secondary statement budget")
            kind = node["kind"]
            if kind == "move":
                target, value = node["target"], self.atom(node["value"])
                if target == "RETURN-CODE":
                    require(isinstance(value, DecimalValue), "return_contract", "integer return code required")
                    quotient, remainder = divmod(value.coefficient, 10 ** value.scale)
                    require(not remainder and 0 <= quotient <= 255, "return_contract", "return range")
                    self.return_code = quotient
                else:
                    source_spec = self.specs[node["value"]["name"]] if node["value"]["kind"] == "reference" else None
                    self.assign(target, move(value, source_spec, self.specs[target], previous_destination=self.values[target]))
            elif kind in ("add", "subtract", "multiply", "divide", "compute"):
                target, destination = node["target"], self.specs[node["target"]]
                kwargs = {"rounded": node["rounded"], "size_error_handler": node["has_size_error"],
                          "previous_destination": self.values[target]}
                if kind == "compute":
                    result = compute(self.numeric_tree(node["expression"]), self.values, destination, **kwargs)
                else:
                    operands = (self.atom(node["left"]), self.atom(node["right"])) if kind == "divide" else (
                        self.values[target], self.atom(node["value"]))
                    result = arithmetic(kind, operands, destination, **kwargs)
                self.assign(target, result)
                if result.size_error:
                    require(node["has_size_error"], "size_error", "unhandled size error")
                    if self.block(node["body"]):
                        return True
            elif kind == "if":
                if self.block(node["body"] if self.condition(node["condition"]) else node["otherwise"]):
                    return True
            elif kind == "perform":
                require(node["paragraph"] != "MAIN", "control_flow", "cannot PERFORM MAIN")
                if node["until"] is None:
                    require(not self.paragraph(node["paragraph"]), "control_flow", "STOP in performed paragraph")
                else:
                    bound = node["max_iterations"]
                    require(type(bound) is int and 1 <= bound <= 64, "unbounded_perform", "parser proof bound required")
                    iterations = 0
                    while not self.condition(node["until"]):
                        require(iterations < bound, "unbounded_perform", "declared/proven bound violated")
                        require(not self.paragraph(node["paragraph"]), "control_flow", "STOP in performed paragraph")
                        iterations += 1
            elif kind == "open":
                file = self.files[node["file"]]
                require(not file["open"] and node["mode"] == file["direction"].upper(), "file_contract", "OPEN state/mode")
                if file["direction"] == "input":
                    file["open"], file["available"] = self.present, self.present
                    self.input_index = 0
                    self.status(file, "00" if self.present else "35")
                else:
                    file["open"] = True
                    file["available"], self.output_present, self.output_records = True, True, []
                    self.output_size = 0
                    self.status(file, "00")
            elif kind == "read":
                file = self.files[node["file"]]
                require(file["open"] and file["direction"] == "input", "file_contract", "READ state")
                if not file["available"]:
                    self.status(file, "47")  # Failed-open READ hypothesis, not EOF.
                elif self.input_index >= len(self.records):
                    self.status(file, "10")
                    if self.block(node["body"]):
                        return True
                else:
                    self.values.update(decode_record(self.records[self.input_index], self.record_fields(file)))
                    self.input_index += 1
                    self.status(file, "00")
            elif kind == "write":
                matches = [f for f in self.files.values() if f["record"] == node["record"]]
                require(len(matches) == 1, "file_contract", "WRITE record binding")
                file = matches[0]
                require(file["open"] and file["direction"] == "output", "file_contract", "WRITE state")
                record = encode_record(self.values, self.record_fields(file))
                require(self.output_size + len(record) + 1 <= 1048576,
                        "output_cap", "output-file cap")
                self.output_records.append(record)
                self.output_size += len(record) + 1
                self.status(file, "00")
            elif kind == "close":
                file = self.files[node["file"]]
                require(file["open"], "file_contract", "CLOSE state")
                self.status(file, "00" if file["available"] else "42")
                file["open"] = False
            elif kind == "display":
                self.display(node)
            elif kind == "stop":
                require(not any(file["open"] for file in self.files.values()), "file_contract", "unclosed files at STOP")
                return True
            else:
                raise RuntimeFault("runtime_plan", "unknown instruction")
        return False


def run_plan(plan, input_present, records):
    """Future isolated candidate entry; returns modeled ordinary values, not evidence.

    Caller must validate OS isolation, source/plan authenticity and resource limits.
    This function has never been invoked during current static construction.
    """
    try:
        state = _State(plan, input_present, records)
        require(state.paragraph("MAIN"), "control_flow", "MAIN did not terminate")
        return {"output_present": state.output_present,
                "output_bytes": b"".join(row + b"\n" for row in state.output_records) if state.output_present else None,
                "stdout": bytes(state.stdout), "stderr": b"", "return_code": state.return_code,
                "semantics": "construction_hypothesis", "runtime_verified": False}
    except ShimError as error:
        raise RuntimeFault(error.code, error.message) from error
    except (KeyError, TypeError, AttributeError, RecursionError) as error:
        raise RuntimeFault("runtime_plan", "malformed closed runtime plan") from error
