"""Pure continuation of unsealed preparation; never decides oracle validity."""
import hashlib

from .generate import (AdmissionError, bundle, canonical, digest, hash_value,
                       integer, keys, require, seeded_case, validate_fields)


RECEIPT_KEYS = ("manifest_version recipe_sha256 fields_sha256 partition case_hashes "
                "boundary_case_hashes next_counter fill_proposals_consumed excluded_hashes_sha256")


def resume(fields_document, recipe, previous, accepted_hashes, quarantine_hashes,
           excluded_hashes=()):
    """Caller supplies oracle-independent decisions, before seal only.

    Accepted hashes retain previous order. Mandatory explicit cases must survive.
    External custody/runner authenticates receipts and enforces unsealed status.
    """
    try:
        return _resume(fields_document, recipe, previous, accepted_hashes,
                       quarantine_hashes, excluded_hashes)
    except (AdmissionError, TypeError, KeyError, AttributeError) as exc:
        error = exc if isinstance(exc, AdmissionError) else AdmissionError("bad_value")
        error.stage = "continuation"
        error.fields_sha256, error.recipe_sha256 = digest(fields_document), digest(recipe)
        raise error from exc


def _resume(fields_document, recipe, previous, accepted_hashes, quarantine_hashes, excluded_hashes):
    fields = validate_fields(fields_document)
    integer(recipe["collision_counter"], 0, 0, "bad_seed")
    receipt = previous["receipt"]
    keys(receipt, RECEIPT_KEYS)
    require(receipt["manifest_version"] == 1 and type(receipt["manifest_version"]) is int,
            "manifest_version")
    require(receipt["recipe_sha256"] == digest(recipe) and
            receipt["fields_sha256"] == digest(fields_document) and
            receipt["partition"] == recipe["partition"], "bad_hash")
    require(previous["status"] == "unexecuted_not_admitted", "bad_value")
    excluded = set(excluded_hashes)
    require(receipt["excluded_hashes_sha256"] == digest(sorted(excluded)), "partition_collision")
    for value in excluded:
        hash_value(value)
    require(recipe["partition"] in ("loop", "verification"), "bad_seed")
    require(recipe["partition"] != "verification" or len(excluded) == 32, "partition_collision")
    count = 32 if recipe["partition"] == "loop" else 128
    require(type(accepted_hashes) is list and len(set(accepted_hashes)) == len(accepted_hashes),
            "duplicate_case")
    prior_cases = previous["cases"]
    hashes = []
    for case in prior_cases:
        checked = bundle(case["input_present"], case["records"])
        require(case["case_sha256"] == checked["case_sha256"] and
                all(len(row) == fields_document["record_width"] for row in case["records"]), "bad_hash")
        hashes.append(case["case_sha256"])
    require(hashes == receipt["case_hashes"] and len(hashes) == count and
            len(set(hashes)) == count, "bad_hash")
    require(set(accepted_hashes) <= set(hashes), "bad_hash")
    cases = [case for case in prior_cases if case["case_sha256"] in accepted_hashes]
    require([case["case_sha256"] for case in cases] == accepted_hashes, "bad_hash")
    seen, quarantine = set(previous["seen_hashes"]), set(quarantine_hashes)
    for value in seen | quarantine:
        hash_value(value)
    require(set(hashes) | excluded <= seen and quarantine <= seen and
            not quarantine.intersection(accepted_hashes), "bad_hash")
    require(set(hashes) - set(accepted_hashes) <= quarantine, "bad_hash")
    mandatory = set(receipt["boundary_case_hashes"].values()) | {hashes[0]}
    require(mandatory <= set(accepted_hashes) and not mandatory.intersection(quarantine), "bad_boundary")
    consumed = integer(receipt["fill_proposals_consumed"], 0, 100000, "bad_seed")
    counter = integer(receipt["next_counter"], 0, 2 ** 64 - 1, "bad_seed")
    require(counter == recipe["collision_counter"] + consumed and
            counter + (100000 - consumed) < 2 ** 64, "bad_seed")
    seed_tuple = [recipe[k] for k in ("corpus_version", "family_id", "program_id", "task_id", "partition")]
    seed = hashlib.sha256(canonical(seed_tuple)).digest()
    maximum = integer(recipe["fill"]["max_records"], 1, 64, "bad_record_count")
    duplicates = list(previous["duplicates"])
    while len(cases) < count:
        require(consumed < 100000, "case_space_exhausted")
        case = seeded_case(fields, seed, counter, maximum)
        counter, consumed = counter + 1, consumed + 1
        if case["case_sha256"] in seen | excluded | quarantine:
            duplicates.append({"case_sha256": case["case_sha256"], "counter": counter - 1})
        else:
            seen.add(case["case_sha256"])
            cases.append(case)
    receipt = dict(receipt, case_hashes=[c["case_sha256"] for c in cases],
                   next_counter=counter, fill_proposals_consumed=consumed)
    return dict(previous, cases=cases, receipt=receipt, duplicates=duplicates,
                ordered_sha256=digest(receipt["case_hashes"]), seen_hashes=sorted(seen),
                next_collision_counter=counter)
