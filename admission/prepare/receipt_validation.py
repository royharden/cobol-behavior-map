"""Validate generation declarations against pinned inputs; no generation or execution."""
from pathlib import Path
from receipt_values import (canonical, case_hash, document, explicit_hash, hash_value,
                            identifier, integer, layout, need, record_values, sha, shape)

RECEIPT_KEYS = ("manifest_version recipe_sha256 fields_sha256 partition case_hashes "
                "boundary_case_hashes next_counter fill_proposals_consumed excluded_hashes_sha256")
RECIPE_KEYS = ("manifest_version corpus_version family_id program_id task_id partition "
               "fields_sha256 scenario records boundaries fill collision_counter")
KINDS = set("zero least_unit field_max result_max result_max_plus_ulp tie non_tie "
            "discarded_fraction positive negative negative_zero pivot_minus_one pivot "
            "pivot_plus_one threshold_below threshold threshold_above eof".split())


def validate_receipt(receipt_raw, recipe_raw, fields_raw, bundles, *, task_id,
                     program_id, family_id, source_sha256, partition, excluded_hashes):
    """Check one complete generated partition; supplied hashes are not admission proof."""
    receipt, recipe, fields = map(document, (receipt_raw, recipe_raw, fields_raw))
    shape(receipt, RECEIPT_KEYS)
    shape(recipe, RECIPE_KEYS)
    entries = layout(fields)
    need(partition in ("loop", "verification"), "partition")
    count = 32 if partition == "loop" else 128
    need(type(receipt["manifest_version"]) is int and receipt["manifest_version"] == 1
         and type(recipe["manifest_version"]) is int and recipe["manifest_version"] == 1, "version")
    need(receipt["partition"] == recipe["partition"] == partition, "partition binding")
    need(hash_value(receipt["recipe_sha256"]) == sha(recipe_raw)
         and hash_value(receipt["fields_sha256"]) == sha(fields_raw)
         and hash_value(recipe["fields_sha256"]) == sha(fields_raw), "raw input pins")
    need(identifier(recipe["task_id"]) == identifier(task_id)
         and identifier(recipe["program_id"]) == identifier(program_id) == fields["program_id"]
         and fields["source_sha256"] == hash_value(source_sha256), "task/source binding")
    need(identifier(recipe["family_id"]) == identifier(family_id), "family binding")
    corpus = recipe["corpus_version"]
    need(isinstance(corpus, str) and corpus and corpus.isascii()
         and all(c.isalnum() or c in "_-" for c in corpus), "corpus id")
    fill = recipe["fill"]
    shape(fill, "algorithm seed_material target_count max_records")
    need(fill["algorithm"] == "sha256-counter-v1"
         and fill["seed_material"] == [corpus, recipe["family_id"], program_id, task_id, partition], "seed")
    need(integer(fill["target_count"], 1, 128) == count, "target count")
    integer(fill["max_records"], 1, 64)
    base = integer(recipe["collision_counter"], 0, 0)
    consumed = integer(receipt["fill_proposals_consumed"], 0, 100000)
    need(integer(receipt["next_counter"], 0, (1 << 64) - 1) == base + consumed,
         "cumulative counter mismatch")
    need(isinstance(excluded_hashes, list) and len(excluded_hashes) == (0 if partition == "loop" else 32),
         "final loop exclusions required")
    exclusions = [hash_value(h) for h in excluded_hashes]
    need(len(set(exclusions)) == len(exclusions), "duplicate exclusions")
    need(hash_value(receipt["excluded_hashes_sha256"]) == sha(canonical(sorted(exclusions))),
         "canonical exclusion commitment")
    need(isinstance(bundles, list) and len(bundles) == count, "bundle count")
    actual = []
    for bundle in bundles:
        shape(bundle, "input_present records_hex case_sha256 input_file")
        encoded = bundle["records_hex"]
        need(isinstance(encoded, list) and all(isinstance(r, str) and len(r) <= 16384
             and r and all(c in "0123456789abcdef" for c in r) and len(r) % 2 == 0 for r in encoded),
             "record hex")
        records = [bytes.fromhex(r) for r in encoded]
        need(all(len(r) == fields["record_width"] and all(32 <= b <= 126 for b in r)
                 for r in records), "record width/encoding")
        record_values(records, entries)
        actual.append(case_hash(bundle["input_present"], records))
        need(actual[-1] == hash_value(bundle["case_sha256"]), "bundle hash")
    need(isinstance(receipt["case_hashes"], list)
         and receipt["case_hashes"] == actual and len(set(actual)) == count
         and not set(actual).intersection(exclusions), "case order/count/disjointness")
    explicit = [explicit_hash(recipe["scenario"], recipe["records"], entries)]
    boundaries = recipe["boundaries"]
    need(isinstance(boundaries, list) and len(boundaries) <= 100000, "boundary list")
    mapping = {}
    for boundary in boundaries:
        shape(boundary, "id field kind scenario records")
        name = identifier(boundary["id"])
        need(name not in mapping and boundary["kind"] in KINDS, "boundary id/kind")
        need(boundary["field"] in {f["name"] for f in entries}
             or (boundary["field"] is None and boundary["kind"] == "eof"), "boundary field")
        value = explicit_hash(boundary["scenario"], boundary["records"], entries)
        mapping[name] = value
        explicit.append(value)
    prefix = list(dict.fromkeys(explicit))
    need(not set(prefix).intersection(exclusions) and len(prefix) <= count
         and actual[:len(prefix)] == prefix, "explicit order/collision")
    need(isinstance(receipt["boundary_case_hashes"], dict)
         and receipt["boundary_case_hashes"] == mapping, "boundary mapping/labels")
    need(consumed >= count - len(prefix), "insufficient fill proposals")
    return actual


def validate_envelope_receipts(request, read, expected_generator_sha256):
    """read(path)->bytes must enforce the envelope's pinned artifact root/hash map."""
    pins, artifacts = request["pins"], request["artifacts"]
    def load(name):
        need(isinstance(name, str) and name in artifacts, "unpinned artifact reference")
        raw = read(name)
        need(sha(raw) == hash_value(artifacts[name]), "artifact changed")
        return raw
    expected = hash_value(expected_generator_sha256)
    for pin, filename in (("receipt_validator", "receipt_validation.py"), ("receipt_values", "receipt_values.py")):
        need(sha(load(pins[pin])) == sha(Path(__file__).with_name(filename).read_bytes()), "helper source pin")
    need(sha(load(pins["generator"])) == artifacts[pins["generator"]] == expected,
         "externally pinned actual generator source required")
    index = document(load(pins["generation_receipts"]))
    shape(index, "manifest_version tasks")
    need(type(index["manifest_version"]) is int and index["manifest_version"] == 1, "index version")
    tasks = index["tasks"]
    need(isinstance(tasks, dict) and set(tasks) == {r["task_id"] for r in request["runs"]}, "index tasks")
    manifests = document(load(pins["program_manifests"]))
    shape(manifests, "manifest_version tasks")
    need(type(manifests["manifest_version"]) is int and manifests["manifest_version"] == 1
         and isinstance(manifests["tasks"], dict) and set(manifests["tasks"]) == set(tasks), "manifest index")
    families = {}
    for run in request["runs"]:
        manifest = document(load(manifests["tasks"][run["task_id"]]))
        shape(manifest, "manifest_version program_id source_sha256 family_id split input_fields_sha256 "
              "output_fields_sha256 allowed_return_codes loops hazards provenance_sha256")
        need(type(manifest["manifest_version"]) is int and manifest["manifest_version"] == 1
             and manifest["program_id"] == run["program_id"]
             and manifest["source_sha256"] == artifacts[run["source"]]
             and manifest["split"] in ("dev", "heldout"), "program manifest binding")
        for key in ("input_fields_sha256", "output_fields_sha256", "provenance_sha256"):
            hash_value(manifest[key])
        family = (identifier(manifest["family_id"]), manifest["split"])
        need(families.setdefault(run["program_id"], family) == family, "panel family/split")
        pair = tasks[run["task_id"]]
        shape(pair, "loop verification")
        bundles = document(load(run["cases"]))
        shape(bundles, "loop verification")
        exclusions, corpus_version = [], None
        for partition in ("loop", "verification"):
            refs = pair[partition]
            shape(refs, "recipe fields receipt")
            raw = [load(refs[key]) for key in ("receipt", "recipe", "fields")]
            need(sha(raw[2]) == manifest["input_fields_sha256"], "manifest input fields")
            actual = validate_receipt(*raw, bundles[partition], task_id=run["task_id"],
                program_id=run["program_id"], family_id=manifest["family_id"], source_sha256=artifacts[run["source"]],
                partition=partition, excluded_hashes=exclusions)
            if partition == "loop":
                exclusions = actual
                corpus_version = document(raw[1])["corpus_version"]
            else:
                need(document(raw[1])["corpus_version"] == corpus_version, "partition corpus version")
