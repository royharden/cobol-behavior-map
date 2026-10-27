"""Standalone, unexecuted M10 preparation. No compiler or expected answers."""
import hashlib
import json
import re


class AdmissionError(ValueError):
    """Typed refusal; no partition is admitted by this module."""
    def __init__(self, code, pointer=""):
        self.code, self.pointer = code, pointer
        super().__init__(f"{code} at {pointer}")


def require(ok, code, pointer=""):
    if not ok:
        raise AdmissionError(code, pointer)


def at(pointer, function, *args):
    try:
        return function(*args)
    except AdmissionError as error:
        error.pointer = pointer + error.pointer
        raise


def keys(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()), "unknown_key")


def integer(value, low, high, code="field_limit"):
    require(type(value) is int and low <= value <= high, code)
    return value


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value),
            "bad_identifier")
    return value


def hash_value(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "bad_hash")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_document(raw):
    """Strict JSON entrypoint. Mapping API assumes an already strict decoder."""
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_key")
            result[key] = value
        return result

    def reject(_):
        raise AdmissionError("bad_value")

    require(type(raw) is bytes and not raw.startswith(b"\xef\xbb\xbf"), "bad_value")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_float=reject, parse_constant=reject)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdmissionError("bad_value") from exc


def units(value, scale):
    require(type(value) is str and
            re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value), "bad_value")
    whole, dot, fraction = value.lstrip("-").partition(".")
    require(len(fraction) <= scale, "bad_value")
    whole = whole.lstrip("0") or "0"
    require(len(whole) <= 8, "value_out_of_range")
    number = int(whole) * 10 ** scale + int((fraction + "0" * scale)[:scale] or "0")
    return -number if value.startswith("-") else number


def validate_fields(document):
    keys(document, "manifest_version program_id source_sha256 record_width fields")
    integer(document["manifest_version"], 1, 1, "manifest_version")
    identifier(document["program_id"])
    hash_value(document["source_sha256"])
    integer(document["record_width"], 1, 8192)
    fields = document["fields"]
    require(type(fields) is list and 1 <= len(fields) <= 32, "field_limit")
    names, result, offset = set(), [], 0
    for field in fields:
        keys(field, "name pic usage sign offset width scale")
        name = field["name"]
        require(type(name) is str and re.fullmatch(r"[A-Z][A-Z0-9-]{0,29}", name)
                and not name.endswith("-") and name not in names, "bad_identifier")
        names.add(name)
        require(type(field["pic"]) is str, "bad_layout_or_sign")
        match = re.fullmatch(r"(X|S9|9)\(([1-9][0-9]*)\)(?:V9\(([1-9][0-9]*)\))?",
                            field["pic"])
        require(match is not None, "bad_layout_or_sign")
        kind, digits, scale = match[1], int(match[2]), int(match[3] or 0)
        signed = kind == "S9"
        require((kind == "X" and not scale and digits <= 8192) or
                (kind != "X" and digits + scale <= 8 and scale <= 4), "field_limit")
        width = digits + scale + int(signed)
        require(field["usage"] == "DISPLAY" and
                field["sign"] == ("leading_separate" if signed else "none"),
                "bad_layout_or_sign")
        integer(field["offset"], offset, offset, "bad_layout_or_sign")
        integer(field["width"], width, width, "bad_layout_or_sign")
        integer(field["scale"], scale, scale, "bad_layout_or_sign")
        result.append(dict(field, kind=kind, digits=digits + scale, signed=signed))
        offset += width
    require(offset == document["record_width"], "bad_layout_or_sign")
    return result


def encode_value(value, field):
    if field["kind"] == "X":
        require(type(value) is str and len(value) <= field["width"] and
                all(32 <= ord(c) <= 126 for c in value), "bad_value")
        return value.ljust(field["width"]).encode("ascii")
    number = units(value, field["scale"])
    negative = value.startswith("-")
    require(field["signed"] or not negative, "negative_unsigned")
    require(abs(number) < 10 ** field["digits"], "value_out_of_range")
    sign = ("-" if negative else "+") if field["signed"] else ""
    return (sign + str(abs(number)).zfill(field["digits"])).encode("ascii")


def encode_record(record, fields):
    require(type(record) is dict, "bad_value")
    names = {f["name"] for f in fields}
    require(names <= record.keys(), "missing_field")
    require(record.keys() <= names, "unknown_field")
    return b"".join(at("/" + f["name"], encode_value, record[f["name"]], f) for f in fields)


def bundle(present, records):
    require(type(present) is bool and type(records) is list, "bad_scenario")
    require(len(records) <= 64 and (present or not records), "bad_record_count")
    require(all(type(record) is bytes for record in records), "bad_value")
    preimage = b"M10-CASE-v1\0" + bytes([int(present)]) + len(records).to_bytes(4, "big")
    for record in records:
        preimage += len(record).to_bytes(4, "big") + record
    return {"input_present": present, "records": records,
            "case_sha256": hashlib.sha256(preimage).hexdigest()}


def decimal_string(number, scale):
    digits = str(abs(number)).zfill(scale + 1)
    return ("-" if number < 0 else "") + (
        digits[:-scale] + "." + digits[-scale:] if scale else digits)


def seeded_case(fields, seed, counter, max_records):
    def block(field, row, index=0):
        return hashlib.sha256(seed + counter.to_bytes(8, "big") +
                              row.to_bytes(4, "big") + field.to_bytes(4, "big") +
                              index.to_bytes(4, "big")).digest()
    count = 1 + int.from_bytes(block(0xffffffff, 0xffffffff), "big") % max_records
    records = []
    for row in range(count):
        encoded = []
        for index, field in enumerate(fields):
            random = block(index, row)
            if field["kind"] == "X":
                stream = b"".join(block(index, row, i)
                                  for i in range((field["width"] + 31) // 32))
                encoded.append(bytes(32 + b % 95 for b in stream[:field["width"]]))
            else:
                maximum = 10 ** field["digits"] - 1
                low = -maximum if field["signed"] else 0
                number = low + int.from_bytes(random, "big") % (maximum - low + 1)
                encoded.append(encode_value(decimal_string(number, field["scale"]), field))
        records.append(b"".join(encoded))
    return bundle(True, records)


BOUNDARY_KINDS = frozenset(("zero least_unit field_max result_max result_max_plus_ulp "
    "tie non_tie discarded_fraction positive negative negative_zero pivot_minus_one "
    "pivot pivot_plus_one threshold_below threshold threshold_above eof").split())


def _generate(fields_document, recipe, excluded_hashes):
    fields = validate_fields(fields_document)
    keys(recipe, "manifest_version corpus_version family_id program_id task_id partition "
         "fields_sha256 scenario records boundaries fill collision_counter")
    integer(recipe["manifest_version"], 1, 1, "manifest_version")
    for key in ("corpus_version", "family_id", "program_id", "task_id"):
        identifier(recipe[key])
    require(recipe["program_id"] == fields_document["program_id"], "bad_identifier")
    require(hash_value(recipe["fields_sha256"]) == digest(fields_document), "bad_hash")
    partition = recipe["partition"]
    require(partition in ("loop", "verification"), "bad_seed")
    count = 32 if partition == "loop" else 128
    fill = recipe["fill"]
    keys(fill, "algorithm seed_material target_count max_records")
    seed_tuple = [recipe[k] for k in ("corpus_version", "family_id", "program_id", "task_id", "partition")]
    require(fill["algorithm"] == "sha256-counter-v1" and fill["seed_material"] == seed_tuple, "bad_seed")
    integer(fill["target_count"], count, count, "bad_record_count")
    maximum = integer(fill["max_records"], 1, 64, "bad_record_count")
    counter = integer(recipe["collision_counter"], 0, 2 ** 64 - 100001, "bad_seed")
    def explicit(case):
        scenario, rows = case["scenario"], case["records"]
        require(scenario in ("missing", "empty", "records"), "bad_scenario")
        require(type(rows) is list and ((scenario == "records" and 1 <= len(rows) <= 64)
                or (scenario != "records" and not rows)), "bad_record_count")
        return bundle(scenario != "missing", [at("/records/" + str(i), encode_record, r, fields)
                                              for i, r in enumerate(rows)])
    candidates = [explicit(recipe)]
    boundaries = recipe["boundaries"]
    require(type(boundaries) is list and len(boundaries) <= 128, "bad_boundary")
    names = {f["name"]: f for f in fields}
    ids = set()
    for boundary in boundaries:
        keys(boundary, "id field kind scenario records")
        identifier(boundary["id"])
        require(boundary["id"] not in ids and
                ((type(boundary["field"]) is str and boundary["field"] in names) or
                 (boundary["field"] is None and boundary["kind"] == "eof")) and
                type(boundary["kind"]) is str and
                boundary["kind"] in BOUNDARY_KINDS, "bad_boundary")
        ids.add(boundary["id"])
        candidates.append(at("/boundaries/" + str(len(ids) - 1), explicit, boundary))
    require(partition != "verification" or excluded_hashes is not None, "partition_collision")
    excluded = set(excluded_hashes or ())
    require(partition != "verification" or len(excluded) == 32, "partition_collision")
    for value in excluded:
        hash_value(value)
    seen, cases, duplicates = set(excluded), [], []
    for case in candidates:
        require(case["case_sha256"] not in excluded, "partition_collision")
        if case["case_sha256"] not in seen:
            seen.add(case["case_sha256"])
            cases.append(case)
        else:
            duplicates.append({"case_sha256": case["case_sha256"], "stage": "explicit"})
    require(len(cases) <= count, "bad_boundary")
    seed, proposals = hashlib.sha256(canonical(seed_tuple)).digest(), 0
    while len(cases) < count:
        require(proposals < 100000, "case_space_exhausted")
        case = seeded_case(fields, seed, counter, maximum)
        counter, proposals = counter + 1, proposals + 1
        if case["case_sha256"] not in seen:
            seen.add(case["case_sha256"])
            cases.append(case)
        else:
            duplicates.append({"case_sha256": case["case_sha256"], "counter": counter - 1})
    return {"manifest_version": 1, "partition": partition, "cases": cases,
            "ordered_sha256": digest([c["case_sha256"] for c in cases]),
            "fields_sha256": digest(fields_document), "recipe_sha256": digest(recipe),
            "next_collision_counter": counter, "duplicates": duplicates,
            "status": "unexecuted_not_admitted"}


def generate(fields_document, recipe, excluded_hashes=None):
    try:
        return _generate(fields_document, recipe, excluded_hashes)
    except (AdmissionError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        error = exc if isinstance(exc, AdmissionError) else AdmissionError("bad_value")
        error.stage = "generation"
        error.fields_sha256 = digest(fields_document)
        error.recipe_sha256 = digest(recipe)
        raise error from exc


def prepare(fields_document, loop_recipe, verification_recipe):
    require(type(loop_recipe) is dict and type(verification_recipe) is dict, "bad_value")
    require(loop_recipe.get("partition") == "loop" and
            verification_recipe.get("partition") == "verification", "bad_seed")
    for key in ("corpus_version", "family_id", "program_id", "task_id", "fields_sha256"):
        require(loop_recipe.get(key) == verification_recipe.get(key), "bad_seed")
    loop = generate(fields_document, loop_recipe)
    verification = generate(fields_document, verification_recipe,
                            [c["case_sha256"] for c in loop["cases"]])
    return {"loop": loop, "verification": verification}
