"""Pure byte/JSON checks for preparation receipts; never executes producer code."""
import hashlib
import json
import re


def need(condition, message):
    if not condition:
        raise ValueError("generation_receipt: " + message)


def shape(value, keys):
    need(isinstance(value, dict) and set(value) == set(keys.split()), "object keys")


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, "integer range/type")
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_value(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "hash syntax")
    return value


def identifier(value):
    need(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value), "identifier")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("generation_receipt: noninteger JSON number " + value)
    need(isinstance(raw, bytes) and not raw.startswith(b"\xef\xbb\xbf"), "JSON bytes/BOM")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_float=invalid, parse_constant=invalid)


def case_hash(present, records):
    need(type(present) is bool and isinstance(records, list) and len(records) <= 64
         and (present or not records), "case presence/records")
    need(all(type(r) is bytes and 1 <= len(r) <= 8192 for r in records), "record bytes")
    preimage = b"M10-CASE-v1\0" + bytes([present]) + len(records).to_bytes(4, "big")
    return sha(preimage + b"".join(len(r).to_bytes(4, "big") + r for r in records))


def layout(fields):
    shape(fields, "manifest_version program_id source_sha256 record_width fields")
    need(type(fields["manifest_version"]) is int and fields["manifest_version"] == 1, "field version")
    identifier(fields["program_id"])
    hash_value(fields["source_sha256"])
    width = integer(fields["record_width"], 1, 8192)
    entries = fields["fields"]
    need(isinstance(entries, list) and 1 <= len(entries) <= 32, "field count")
    end, names = 0, set()
    for field in entries:
        shape(field, "name pic usage sign offset width scale")
        name = field["name"]
        need(isinstance(name, str) and re.fullmatch(r"[A-Z](?:[A-Z0-9-]{0,28}[A-Z0-9])?", name)
             and name not in names, "field name")
        names.add(name)
        need(field["usage"] == "DISPLAY", "external usage")
        need(integer(field["offset"], 0, 8191) == end, "field offsets")
        size, scale = integer(field["width"], 1, 8192), integer(field["scale"], 0, 4)
        pic = field["pic"]
        need(isinstance(pic, str), "PIC type")
        alpha = re.fullmatch(r"X\(([1-9][0-9]{0,3})\)", pic)
        number = re.fullmatch(r"(S?)9\(([1-9][0-9]?)\)(?:V9\(([1-9][0-9]?)\))?", pic)
        if alpha:
            need(size == int(alpha[1]) and scale == 0 and field["sign"] == "none", "X layout")
        else:
            need(number is not None, "numeric PIC")
            digits = int(number[2]) + int(number[3] or 0)
            need(digits <= 8 and scale == int(number[3] or 0)
                 and size == digits + bool(number[1])
                 and field["sign"] == ("leading_separate" if number[1] else "none"), "numeric layout")
        end += size
    need(end == width, "record width")
    return entries


def explicit_hash(scenario, rows, entries):
    need(scenario in ("missing", "empty", "records") and isinstance(rows, list), "scenario")
    need((1 <= len(rows) <= 64) if scenario == "records" else not rows, "scenario rows")
    records = []
    for row in rows:
        need(isinstance(row, dict) and set(row) == {f["name"] for f in entries}, "row fields")
        record = b""
        for field in entries:
            value, size = row[field["name"]], field["width"]
            need(isinstance(value, str) and value.isascii(), "ASCII value")
            if field["pic"].startswith("X"):
                need(len(value) <= size and all(32 <= ord(c) <= 126 for c in value), "X value")
                encoded = value.ljust(size)
            else:
                need(re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value), "decimal string")
                negative = value.startswith("-")
                signed = field["sign"] == "leading_separate"
                need(signed or not negative, "negative unsigned")
                whole, dot, fraction = value.lstrip("-").partition(".")
                need(len(fraction) <= field["scale"], "fraction scale")
                digits = (whole + fraction.ljust(field["scale"], "0")).lstrip("0") or "0"
                need(len(digits) <= size - signed, "numeric overflow")
                encoded = (("-" if negative else "+") if signed else "") + digits.zfill(size - signed)
            record += encoded.encode("ascii")
        records.append(record)
    return case_hash(scenario != "missing", records)


def record_values(records, entries):
    for record in records:
        for field in entries:
            if field["pic"].startswith("X"):
                continue
            chunk = record[field["offset"]:field["offset"] + field["width"]]
            if field["sign"] == "leading_separate":
                need(chunk[:1] in (b"+", b"-"), "record sign")
                chunk = chunk[1:]
            need(chunk and all(48 <= b <= 57 for b in chunk), "record numeric digits")
