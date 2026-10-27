"""Validate a pinned preparation envelope; execution is deliberately unavailable."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from receipt_validation import validate_envelope_receipts
class Refusal(ValueError):
    """An envelope cannot be admitted for preparation."""
def require(condition, message):
    if not condition:
        raise Refusal(message)
def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "invalid SHA256")
    return value
def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result
def reject_constant(value):
    raise Refusal("nonfinite JSON constant: " + value)
def artifact(root, name):
    require(isinstance(name, str) and name and "\\" not in name and ":" not in name,
            "artifact must be a relative POSIX path")
    parts = PurePosixPath(name).parts
    require(not name.startswith("/") and all(p not in (".", "..") for p in parts),
            "artifact path escapes root")
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink() and not path.is_junction(), "linked artifact")
    require(path.resolve().is_relative_to(root) and path.is_file(), "missing artifact")
    require(path.stat().st_size <= 268435456, "artifact exceeds 256 MiB")
    return path.read_bytes()
def cases(root, name, artifacts):
    partitions = json.loads(artifact(root, name), object_pairs_hook=unique_object,
                            parse_constant=reject_constant)
    require(isinstance(partitions, dict) and set(partitions) == {"loop", "verification"},
            "invalid case partitions")
    seen = set()
    for partition, count in (("loop", 32), ("verification", 128)):
        bundles = partitions[partition]
        require(isinstance(bundles, list) and len(bundles) == count, "case count mismatch")
        for bundle in bundles:
            require(isinstance(bundle, dict) and set(bundle) == {"input_present",
                    "records_hex", "case_sha256", "input_file"}, "invalid case fields")
            present, encoded = bundle["input_present"], bundle["records_hex"]
            require(type(present) is bool and isinstance(encoded, list) and len(encoded) <= 64
                    and (present or not encoded), "invalid presence/records")
            require(all(isinstance(r, str) and re.fullmatch(r"(?:[0-9a-f]{2}){1,8192}", r)
                        for r in encoded), "invalid record hex")
            records = [bytes.fromhex(r) for r in encoded]
            require(all(all(32 <= b <= 126 for b in r) for r in records), "non-ASCII record")
            framed = b"M10-CASE-v1\0" + bytes([present]) + len(records).to_bytes(4, "big")
            framed += b"".join(len(r).to_bytes(4, "big") + r for r in records)
            hashed = hashlib.sha256(framed).hexdigest()
            require(hashed == digest(bundle["case_sha256"]) and hashed not in seen,
                    "case hash mismatch or partition collision")
            seen.add(hashed)
            path = bundle["input_file"]
            require(path is None if not present else isinstance(path, str) and path in artifacts,
                    "input presence/file mismatch")
            if present:
                raw = artifact(root, path)
                require(hashlib.sha256(raw).hexdigest() == artifacts[path]
                        and raw == b"".join(r + b"\n" for r in records), "raw file mismatch")
def validate(request, root, expected_generator_sha256):
    require(isinstance(request, dict), "request must be an object")
    require(set(request) == {"manifest_version", "kind", "artifacts", "pins",
                             "compiler", "runs", "case_hash_contract_sha256"},
            "unknown or missing envelope fields")
    require(type(request["manifest_version"]) is int and request["manifest_version"] == 1,
            "unsupported manifest version")
    require(request["kind"] == "oracle_preparation", "not an oracle request")
    require(request["case_hash_contract_sha256"] ==
            "b0ac6b2d52977025366b75c4ef02435fc70156500eaa2afd5d5eed07476f7f8c",
            "case contract differs from INT-adopted GENERATOR.md")
    artifacts = request["artifacts"]
    require(isinstance(artifacts, dict) and 1 <= len(artifacts) <= 1024,
            "invalid artifact map")
    for name, expected in artifacts.items():
        require(hashlib.sha256(artifact(root, name)).hexdigest() == digest(expected),
                "artifact pin mismatch")
    pins = request["pins"]
    required = {"compiler_source", "compiler_package", "base_image", "libcob",
                "default_conf", "compiler_config", "runtime_config", "tool_info",
                "generator", "fields", "recipes", "subset_spec", "runner", "generation_receipts", "program_manifests", "receipt_validator", "receipt_values"}
    require(isinstance(pins, dict) and set(pins) == required, "incomplete tool pins")
    for pin in pins.values():
        require(pin in artifacts, "tool pin must reference a hashed artifact")
    require(artifacts[pins["runner"]] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "runner pin does not match this source")
    compiler = request["compiler"]
    ordinary = ["cobc", "-x", "-free", "-std=default", "-O0", "-o", "<bin>", "<source>"]
    require(compiler == {"version": "3.2.0", "ordinary_argv": ordinary,
                         "trace_argv": ordinary[:5] + ["-ftraceall"] + ordinary[5:],
                         "environment": {"TZ": "UTC", "LC_ALL": "C", "COB_overrides": {}}},
            "compiler/config contract mismatch")
    runs = request["runs"]
    require(isinstance(runs, list) and 1 <= len(runs) <= 4096, "invalid run schedule")
    seen, tasks = set(), set()
    for run in runs:
        require(isinstance(run, dict) and set(run) == {"task_id", "program_id", "panel", "source",
                "cases", "case_bundle_sha256", "ordinary_repeats", "trace_repeats"},
                "invalid run fields")
        task = run["task_id"]
        require(all(isinstance(i, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", i)
                    for i in (task, run["program_id"])) and task not in tasks,
                "invalid task id")
        require(run["panel"] in ("unchanged", "change"), "invalid panel")
        key = (run["program_id"], run["panel"])
        require(key not in seen, "duplicate task variant")
        seen.add(key)
        tasks.add(task)
        require(run["source"] in artifacts and run["cases"] in artifacts,
                "source/cases must be pinned")
        require(artifacts[run["cases"]] == run["case_bundle_sha256"], "case artifact mismatch")
        cases(root, run["cases"], artifacts)
        require(type(run["ordinary_repeats"]) is int and run["ordinary_repeats"] == 2
                and type(run["trace_repeats"]) is int and run["trace_repeats"] == 2,
                "two ordinary and two trace runs required")
    validate_envelope_receipts(request, lambda name: artifact(root, name), expected_generator_sha256)
    require(all((program, panel) in seen for program, _ in seen
                for panel in ("unchanged", "change")), "missing original/changed pair")
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("--sha256", required=True, help="externally supplied envelope hash")
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--generator-sha256", required=True, help="external actual generator source pin")
    args = parser.parse_args()
    try:
        require(not args.execute, "execution unavailable: validated isolation backend absent")
        require(args.request.stat().st_size <= 1048576, "envelope exceeds 1 MiB")
        raw = args.request.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest(args.sha256), "envelope pin mismatch")
        request = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
        validate(request, args.artifact_root.resolve(strict=True), args.generator_sha256)
        print(json.dumps({"status": "prepared_only", "execution": "unavailable",
                          "request_sha256": args.sha256, "oracle_observations": None}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}), file=sys.stderr)
        return 2
if __name__ == "__main__": sys.exit(main())
