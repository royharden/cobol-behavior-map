"""Pure generator-to-runner transport. No materialization or oracle evidence."""
import hashlib
from pathlib import PurePosixPath

from .generate import (AdmissionError, bundle, canonical, digest, hash_value,
                       identifier, keys, load_document, require, validate_fields)


SPEC_PINS = {
    "case_spec": "b0ac6b2d52977025366b75c4ef02435fc70156500eaa2afd5d5eed07476f7f8c",
    "family_spec": "08c2e2caa5be00c7851e5b3ad37b4f2ce9c6f0be434d2de3ad22b3b9463f7da5",
}
REQUIRED = frozenset(("source fields loop_recipe verification_recipe program_manifest "
                      "generator case_spec family_spec").split())
ACTUAL_PINS = ("compiler_source", "compiler_package", "base_image", "libcob",
               "default_conf", "compiler_config", "runtime_config", "tool_info", "runner")
RECEIPT_KEYS = ("manifest_version recipe_sha256 fields_sha256 partition case_hashes "
                "boundary_case_hashes next_counter fill_proposals_consumed excluded_hashes_sha256")


def path_name(value):
    require(type(value) is str and value and "\\" not in value and ":" not in value
            and not value.startswith("/") and all(32 <= ord(c) <= 126 for c in value), "bad_value")
    parts = value.split("/")
    require(all(part not in ("", ".", "..") for part in parts)
            and str(PurePosixPath(value)) == value, "bad_value")
    return value


def descriptor(path, raw, document=None, spec=False):
    path_name(path)
    require(type(raw) is bytes and len(raw) <= 268435456, "bad_value")
    return {"path": path, "raw_bytes": raw, "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": digest(document) if document is not None else None,
            "spec_lf_sha256": hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() if spec else None}


def adapt_task(binding, generated, artifacts):
    """Return envelope-ready task data, never a runnable envelope or observations.

    Missing actual source documents => pending. Compiler evidence is always external.
    Caller authenticates generated results, artifact provenance and binding authority.
    """
    try:
        return _adapt_task(binding, generated, artifacts)
    except (AdmissionError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        error = exc if isinstance(exc, AdmissionError) else AdmissionError("bad_value")
        error.stage = "transport_adapter"
        raise error from exc


def _adapt_task(binding, generated, artifacts):
    keys(binding, "task_id program_id family_id split panel original_sha256 oracle_source_sha256 change_sha256")
    for key in ("task_id", "program_id", "family_id"):
        identifier(binding[key])
    require(binding["split"] in ("dev", "heldout") and
            binding["panel"] in ("unchanged", "change"), "bad_identifier")
    original, source_hash = hash_value(binding["original_sha256"]), hash_value(binding["oracle_source_sha256"])
    if binding["panel"] == "unchanged":
        require(original == source_hash and binding["change_sha256"] is None, "bad_hash")
    else:
        require(hash_value(binding["change_sha256"]) == source_hash, "bad_hash")
    require(type(artifacts) is dict and not artifacts.keys() - REQUIRED, "unknown_key")
    missing = sorted(REQUIRED - artifacts.keys())
    if missing:
        return {"status": "pending", "missing_artifacts": missing, "binding": dict(binding)}
    output, inputs, documents = {}, {}, {}
    for role, artifact in artifacts.items():
        keys(artifact, "path raw_bytes")
        raw = artifact["raw_bytes"]
        require(type(raw) is bytes and len(raw) <= 268435456, "bad_value")
        document = load_document(raw) if role in (
            "fields", "loop_recipe", "verification_recipe", "program_manifest") else None
        item = descriptor(artifact["path"], raw, document, role in SPEC_PINS)
        require(item["path"] not in output, "duplicate_key")
        output[item["path"]] = item
        inputs[role], documents[role] = item, document
        if role in SPEC_PINS:
            require(item["spec_lf_sha256"] == SPEC_PINS[role], "bad_hash")
    require(inputs["source"]["raw_sha256"] == source_hash, "bad_hash")
    fields, manifest = documents["fields"], documents["program_manifest"]
    validate_fields(fields)
    require(fields["program_id"] == binding["program_id"] and
            fields["source_sha256"] == source_hash, "bad_hash")
    keys(manifest, "manifest_version program_id source_sha256 family_id split input_fields_sha256 "
         "output_fields_sha256 allowed_return_codes loops hazards provenance_sha256")
    require(type(manifest["manifest_version"]) is int and manifest["manifest_version"] == 1,
            "manifest_version")
    require(all(manifest[key] == binding[key] for key in ("program_id", "family_id", "split"))
            and manifest["source_sha256"] == source_hash
            and manifest["input_fields_sha256"] == digest(fields), "bad_hash")
    keys(generated, "loop verification")
    transport, receipts, recipes, seen = {}, {}, {}, set()
    prefix = "prepared/" + binding["task_id"]

    def emit(name, raw, document=None):
        item = descriptor(name, raw, document)
        require(name not in output, "duplicate_key")
        output[name] = item
        return name

    for partition, count in (("loop", 32), ("verification", 128)):
        recipe = documents[partition + "_recipe"]
        require(type(recipe) is dict and all(recipe.get(key) == binding[key]
                for key in ("task_id", "program_id", "family_id")) and
                recipe.get("partition") == partition and recipe.get("fields_sha256") == digest(fields), "bad_hash")
        recipes[partition] = digest(recipe)
        result = generated[partition]
        require(type(result) is dict and result.get("status") == "unexecuted_not_admitted", "bad_value")
        cases, receipt = result["cases"], result["receipt"]
        keys(receipt, RECEIPT_KEYS)
        require(type(receipt["manifest_version"]) is int and receipt["manifest_version"] == 1
                and receipt["partition"] == partition
                and receipt["recipe_sha256"] == digest(recipe)
                and receipt["fields_sha256"] == digest(fields), "bad_hash")
        require(type(cases) is list and len(cases) == count, "bad_record_count")
        rows = []
        hashes = []
        for index, case in enumerate(cases):
            keys(case, "input_present records case_sha256")
            checked = bundle(case["input_present"], case["records"])
            require(all(1 <= len(row) == fields["record_width"] <= 8192
                        and all(32 <= byte <= 126 for byte in row)
                        for row in case["records"]), "bad_value")
            hashed = hash_value(case["case_sha256"])
            require(checked["case_sha256"] == hashed and hashed not in seen, "partition_collision")
            seen.add(hashed)
            hashes.append(hashed)
            file_name = None
            if case["input_present"]:
                file_name = emit(f"{prefix}/inputs/{partition}-{index:03d}.dat",
                                 b"".join(row + b"\n" for row in case["records"]))
            rows.append({"input_present": case["input_present"],
                         "records_hex": [row.hex() for row in case["records"]],
                         "case_sha256": hashed, "input_file": file_name})
        require(receipt["case_hashes"] == hashes and result["ordered_sha256"] == digest(hashes), "bad_hash")
        exclusions = [] if partition == "loop" else [row["case_sha256"] for row in transport["loop"]]
        require(receipt["excluded_hashes_sha256"] == digest(sorted(set(exclusions))), "partition_collision")
        transport[partition], receipts[partition] = rows, receipt
    cases_path = emit(prefix + "/cases.json", canonical(transport), transport)
    receipt_record = {"task_id": binding["task_id"], "program_id": binding["program_id"],
                      "panel": binding["panel"], "source_sha256": source_hash,
                      "fields_sha256": digest(fields), "recipe_sha256": recipes, "partitions": receipts}
    receipt_path = emit(prefix + "/generation-receipts.json", canonical(receipt_record), receipt_record)
    return {"status": "transport_only_execution_pending", "binding": dict(binding),
            "run": {"task_id": binding["task_id"], "program_id": binding["program_id"],
                    "panel": binding["panel"], "source": inputs["source"]["path"],
                    "cases": cases_path, "case_bundle_sha256": output[cases_path]["raw_sha256"],
                    "ordinary_repeats": 2, "trace_repeats": 2},
            "artifacts": output, "generation_receipts": receipt_record,
            "generation_receipts_path": receipt_path, "program_manifest": manifest,
            "role_paths": {role: item["path"] for role, item in inputs.items()},
            "generator_raw_sha256": inputs["generator"]["raw_sha256"],
            "case_hash_contract_sha256": SPEC_PINS["case_spec"], "missing_actual_pins": list(ACTUAL_PINS)}
