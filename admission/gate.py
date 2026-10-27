"""P2 structural admission checker. No execution, signing, or appointment authority.

The caller supplies a separately Roy-approved authority digest. Run only later in
an authorized custodian environment: referenced private receipts are read locally.
No command-line entry point, imports from product code, or import-time IO.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

VERSION = "m10-p2-v1"
PLAN = "552ddcb9121deb21489a903eaf77979b8068231a94a0fb714b948094c8d4dbed"
SHA = re.compile(r"[0-9a-f]{64}\Z")
DOMAINS = {"decimal", "file_status", "year_window"}
# Every requirement needs its own actual receipt; author fixtures are never evidence.
CHECKS = {
    "compiler_config_notices": "builder",
    "originality_licenses_dev": "builder",
    "dev_preparation": "builder",
    "heldout_originals_recipes_changes": "custodian",
    "case_counts_partitions_quarantine": "custodian",
    "token_template_separation": "custodian",
    "independence_private_seal": "custodian",
    "independent_compiler_probe_rerun": "verifier",
    "three_selected_dev_reruns": "verifier",
    "recipe_reachability_custody": "verifier",
    "licenses_staffing": "roy",
    "manifest_seal_confirmation": "roy",
}
PINS = {
    "subset", "hazards", "families", "changes", "provenance", "shim_api",
    "generator", "compile_runner", "compiler_source_package", "image",
    "compiler_build_version_info", "libcob", "default_conf", "runtime_config",
    "compiler_argv", "quarantine_log", "disputes", "token_template_screen",
    "custody_log", "private_manifest", "heldout_lock",
}


class Invalid(ValueError):
    """Contradictory or malformed evidence: NO-GO."""


class Pending(ValueError):
    """Absent information or execution: PENDING, never GO."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            need(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def nonfinite(value: str) -> None:
        raise Invalid(f"nonfinite number: {value}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def shape(value: Any, schema: dict[str, Any], at: str = "record") -> None:
    """Closed, deliberately small subset used by our bundled JSON schemas only."""
    types = {"object": dict, "array": list, "string": str, "integer": int,
             "boolean": bool}
    need(type(value) is types[schema["type"]], f"{at}: wrong type")
    if "const" in schema:
        need(value == schema["const"], f"{at}: wrong constant")
    if "enum" in schema:
        need(value in schema["enum"], f"{at}: unknown value")
    if isinstance(value, dict):
        properties = schema["properties"]
        need(not (value.keys() - properties.keys()), f"{at}: unknown fields")
        missing = set(schema["required"]) - value.keys()
        if missing:
            raise Pending(f"{at}: missing {sorted(missing)}")
        for key, item in value.items():
            shape(item, properties[key], f"{at}.{key}")
    elif isinstance(value, list):
        need(len(value) >= schema.get("minItems", 0), f"{at}: too few items")
        for index, item in enumerate(value):
            shape(item, schema["items"], f"{at}[{index}]")
    elif isinstance(value, str):
        need(bool(value.strip()), f"{at}: blank value")
        if "pattern" in schema:
            need(re.fullmatch(schema["pattern"], value) is not None, f"{at}: pattern")
    elif type(value) is int:
        need(value >= schema.get("minimum", 0), f"{at}: below minimum")


def stamp(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(parsed.tzinfo is not None, "timestamp requires timezone")


def evaluate(root: Path, record_path: str, authority_path: str,
             authority_sha256: str) -> dict[str, Any]:
    """Return all discovered gate failures. GO is structural eligibility only.

    Does not execute receipts, access network, alter records, or authenticate a
    signature. Caller must authenticate Roy's authority digest out of band.
    """
    problems: list[dict[str, str]] = []
    evidence_root = root.resolve()

    def inspect(label: str, operation: Any) -> Any:
        try:
            return operation()
        except (Pending, FileNotFoundError) as exc:
            problems.append({"item": label, "status": "PENDING", "reason": str(exc)})
        except (Invalid, ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
            problems.append({"item": label, "status": "NO-GO", "reason": str(exc)})
        return None

    def read(relative: str) -> bytes:
        path = PurePosixPath(relative)
        need(bool(relative) and "\\" not in relative and ":" not in relative
             and not path.is_absolute() and all(p not in {".", ".."} for p in relative.split("/"))
             and "//" not in relative, "unsafe evidence path")
        target = (evidence_root / relative).resolve()
        need(target.is_relative_to(evidence_root), "evidence escapes root")
        return target.read_bytes()

    def reference(ref: dict[str, str]) -> bytes:
        need(SHA.fullmatch(ref["sha256"]) is not None, "bad SHA256")
        raw = read(ref["path"])
        need(bool(raw), "empty evidence file")
        need(hashlib.sha256(raw).hexdigest() == ref["sha256"], "evidence hash mismatch")
        return raw

    schema_root = Path(__file__).parent / "schemas"

    def load(relative: str, name: str) -> Any:
        value = strict_json(read(relative))
        schema = strict_json((schema_root / f"{name}.schema.json").read_bytes())
        shape(value, schema)
        return value

    def authority_load() -> Any:
        need(SHA.fullmatch(authority_sha256) is not None, "externally approved digest required")
        need(hashlib.sha256(read(authority_path)).hexdigest() == authority_sha256,
             "authority digest mismatch")
        return load(authority_path, "authority")

    authority = inspect("authority", authority_load)
    record = inspect("record", lambda: load(record_path, "go-record"))
    if authority is not None and record is not None:
        inspect("binding", lambda: need(
            record["authority_sha256"] == authority_sha256
            and record["plan_sha256"] == authority["plan_sha256"] == PLAN
            and record["gate_version"] == VERSION, "authority/plan/version mismatch"))
        actors = {actor["role"]: actor for actor in authority["actors"]}

        def roles() -> None:
            need(len(actors) == len(authority["actors"]) == 4
                 and set(actors) == {"builder", "custodian", "verifier", "roy"}, "four named roles required")
            sessions = [a["session_id"] for a in actors.values()]
            need(len(set(sessions)) == 4, "roles require separate sessions")
            need(len({a["actor_id"] for a in actors.values()}) == 4, "roles require distinct identities")
            need(actors["custodian"]["harness"] != actors["builder"]["harness"],
                 "custodian requires different harness")
            for role in ("custodian", "verifier"):
                actor = actors[role]
                need(actor["session_id"] not in authority["author_sessions"], "custodian/verifier is an author")
                need(not (set(actor["lineage_sessions"] + [actor["session_id"]])
                          & set(actors["builder"]["lineage_sessions"] + [actors["builder"]["session_id"]])),
                     "builder/child/fork cannot be independent")
            need(actors["verifier"]["session_id"] not in actors["custodian"]["lineage_sessions"]
                 and actors["custodian"]["session_id"] not in actors["verifier"]["lineage_sessions"],
                 "verifier cannot be custodian lineage")
            for actor in actors.values():
                reference(actor["appointment"])
                reference(actor["brief"])
            reference(authority["roy_signature"])
            stamp(authority["approved_at"])

        inspect("roles", roles)
        pins = record["pins"]
        inspect("pin_inventory", lambda: need(set(pins) == PINS, "exact tool/file pin inventory required"))
        for name, ref in pins.items():
            inspect(f"pin:{name}", lambda ref=ref: reference(ref))
        inspect("compiler", lambda: need(
            record["compiler"] == {"name": "GnuCOBOL", "version": "3.2.0",
                "argv": ["cobc", "-x", "-free", "-std=default", "-O0", "-o", "<bin>", "<source>"],
                "trace_extra": "-ftraceall", "tz": "UTC", "lc_all": "C", "ambient_cob_cleared": True},
            "compiler invocation/configuration mismatch"))
        for ref in record["frozen_briefs"]:
            inspect("frozen_brief", lambda ref=ref: reference(ref))

        def seal() -> None:
            need(record["seal"]["manifest_sha256"] == pins["private_manifest"]["sha256"]
                 == authority["seal_manifest_sha256"], "Roy seal/manifest mismatch")
            need(record["seal"]["confirmed_at"] == authority["seal_confirmed_at"], "seal date mismatch")
            stamp(record["seal"]["confirmed_at"])
            reference(record["seal"]["roy_confirmation"])

        inspect("seal", seal)
        family_ids: set[str] = set()
        for split, programs in (("dev", 4), ("heldout", 3)):
            def families(split: str = split, programs: int = programs) -> None:
                selected = [f for f in record["families"] if f["split"] == split]
                need(len(selected) == 6, f"{split}: six families required")
                for domain in DOMAINS:
                    need(sum(f["domain"] == domain for f in selected) == 2, "two families per domain")
                for family in selected:
                    need(family["id"] not in family_ids, "duplicate family")
                    family_ids.add(family["id"])
                    need(len(set(family["program_ids"])) == programs
                         and len(family["program_ids"]) == programs, "program count per family")
                    reference(family["template_commitment"])
            inspect(f"families:{split}", families)

        tasks = record["tasks"]
        inspect("task_inventory", lambda: need(
            len(tasks) == 84 and len({t["id"] for t in tasks}) == 84,
            "exactly 48 dev and 36 heldout original/changed task IDs required"))
        declared_programs: set[str] = set()
        for family in record["families"]:
            for program in family["program_ids"]:
                def panels(program: str = program, family: Any = family) -> None:
                    need(program not in declared_programs, "program appears in multiple families")
                    declared_programs.add(program)
                    pair = [t for t in tasks if t["program_id"] == program]
                    need(len(pair) == 2 and {t["panel"] for t in pair} == {"original", "changed"},
                         "original and changed task required per program")
                    need(all(t["family_id"] == family["id"] and t["split"] == family["split"] for t in pair),
                         "task split/family mismatch")
                    need(pair[0]["source"]["sha256"] != pair[1]["source"]["sha256"], "change unchanged")
                inspect(f"panels:{program}", panels)
        inspect("orphan_tasks", lambda: need(all(t["program_id"] in declared_programs for t in tasks), "orphan task"))

        for task in tasks:
            def task_check(task: Any = task) -> None:
                loop, verification = task["loop_hashes"], task["verification_hashes"]
                need(len(loop) == len(set(loop)) == 32, "32 unique loop cases required")
                need(len(verification) == len(set(verification)) == 128, "128 unique verification cases required")
                need(not (set(loop) & set(verification)), "partitions overlap")
                need(task["oracle_runs"] == 2 and task["ordinary_equal"] and task["trace_equal"],
                     "repeat oracle/trace equality required")
                need(len(set(task["hazards"])) >= 2, "two reachable hazards required")
                for name in ("source", "fields", "recipe", "case_manifest", "oracle_receipt", "trace_receipt"):
                    reference(task[name])
                observed = strict_json(reference(task["oracle_receipt"]))
                shape(observed, strict_json((schema_root / "task-oracle.schema.json").read_bytes()))
                need(observed["task_id"] == task["id"]
                     and observed["source_sha256"] == task["source"]["sha256"]
                     and observed["case_manifest_sha256"] == task["case_manifest"]["sha256"]
                     and observed["generator_sha256"] == pins["generator"]["sha256"]
                     and observed["compiler_config_sha256"] == pins["default_conf"]["sha256"]
                     and observed["image_sha256"] == pins["image"]["sha256"], "task oracle binding mismatch")
                expected_actor = actors["builder" if task["split"] == "dev" else "custodian"]
                need(observed["session_id"] == expected_actor["session_id"]
                     and observed["mode"] == "actual" and observed["result"] == "pass",
                     "task needs actual oracle receipt from assigned split owner")
                need(observed["loop_hashes"] == loop and observed["verification_hashes"] == verification,
                     "oracle partition mismatch")
                runs = observed["ordinary_runs"]
                need(len(runs) == 2 and {r["ordinal"] for r in runs} == {1, 2}, "two distinct oracle runs required")
                need(all(r["valid_cases"] == 160 and r["faults"] == 0 for r in runs), "invalid oracle run")
                need(runs[0]["observations"]["sha256"] == runs[1]["observations"]["sha256"]
                     and runs[0]["observations"]["path"] != runs[1]["observations"]["path"],
                     "separate repeated runs must have identical ordinary observations")
                for run in runs:
                    reference(run["observations"])
                    reference(run["execution_log"])
                trace = strict_json(reference(task["trace_receipt"]))
                shape(trace, strict_json((schema_root / "task-trace.schema.json").read_bytes()))
                need(trace["task_id"] == task["id"] and trace["source_sha256"] == task["source"]["sha256"]
                     and trace["oracle_receipt_sha256"] == task["oracle_receipt"]["sha256"]
                     and trace["session_id"] == expected_actor["session_id"]
                     and trace["mode"] == "actual" and trace["result"] == "pass"
                     and trace["valid_cases"] == 160 and trace["faults"] == 0
                     and trace["ordinary_observations"]["sha256"] == runs[0]["observations"]["sha256"],
                     "trace/untraced ordinary observations mismatch")
                reference(trace["ordinary_observations"])
                reference(trace["execution_log"])
            inspect(f"task:{task['id']}", task_check)

        artifact_paths: set[str] = set()
        for artifact in record["artifacts"]:
            def artifact_check(artifact: Any = artifact) -> None:
                path = artifact["file"]["path"]
                need(path not in artifact_paths, "duplicate provenance artifact")
                artifact_paths.add(path)
                reference(artifact["file"])
                actor = actors[artifact["author_role"]]
                need(artifact["author_role"] == ("builder" if artifact["split"] == "dev" else "custodian"),
                     "artifact must be authored by assigned split owner")
                need(artifact["session_id"] == actor["session_id"]
                     and artifact["harness"] == actor["harness"]
                     and artifact["callsign"] == actor["actor_id"], "provenance author mismatch")
                need(artifact["original_source_attestation"] is True, "original-source attestation absent")
                need(artifact["license"] == authority["licenses"][artifact["kind"]], "unapproved artifact license")
                reference(artifact["license_signature"])
                reference(artifact["brief"])
                need(artifact["generator_sha256"] == pins["generator"]["sha256"], "generator mismatch")
                need(any(f["id"] == artifact["family_id"] and f["split"] == artifact["split"]
                         for f in record["families"]), "artifact family/split mismatch")
                stamp(artifact["created_at"])
            inspect("provenance", artifact_check)
        required_artifacts = {t[k]["path"] for t in tasks for k in ("source", "fields", "recipe", "case_manifest")}
        required_artifacts.update(ref["path"] for ref in record["original_artifacts"])
        inspect("provenance_coverage", lambda: need(required_artifacts <= artifact_paths,
                                                   "missing per-artifact provenance"))

        items = {item["id"]: item for item in record["checks"]}
        inspect("check_inventory", lambda: need(len(items) == len(record["checks"])
                and set(items) == set(CHECKS), "exact section 5 checklist required"))
        receipt_paths: set[str] = set()
        receipt_hashes: set[str] = set()
        for check, role in CHECKS.items():
            def receipt_check(check: str = check, role: str = role) -> None:
                if check not in items:
                    raise Pending("required receipt absent")
                item = items[check]
                if item["result"] == "pending":
                    raise Pending("not executed/approved")
                need(item["result"] == "pass", "failed admission item")
                actor = actors[role]
                need(item["checked_by"] == actor["actor_id"] and item["session_id"] == actor["session_id"]
                     and item["harness"] == actor["harness"], "wrong signatory")
                stamp(item["timestamp"])
                reference(item["signature"])
                for ref in item["evidence_paths"]:
                    need(ref["path"] not in artifact_paths
                         and ref["path"] not in {p["path"] for p in pins.values()},
                         "source/pin is not execution evidence")
                    need(ref["path"] not in receipt_paths and ref["sha256"] not in receipt_hashes,
                         "reused receipt is not independent evidence")
                    receipt_paths.add(ref["path"])
                    receipt_hashes.add(ref["sha256"])
                    receipt = strict_json(reference(ref))
                    shape(receipt, strict_json((schema_root / "receipt.schema.json").read_bytes()))
                    need(receipt["check_id"] == check and receipt["session_id"] == actor["session_id"]
                         and receipt["harness"] == actor["harness"] and receipt["checked_by"] == actor["actor_id"],
                         "receipt actor/check mismatch")
                    need(receipt["result"] == "pass" and receipt["mode"] == ("approval" if role == "roy" else "actual"),
                         "fixture/static/authored evidence cannot prove admission")
                    need(receipt["manifest_sha256"] == authority["seal_manifest_sha256"]
                         and receipt["generator_sha256"] == pins["generator"]["sha256"]
                         and receipt["compiler_config_sha256"] == pins["default_conf"]["sha256"], "stale receipt pins")
                    need(receipt["failed"] == receipt["skipped"] == 0 and receipt["executed"] > 0,
                         "receipt requires actual completed checks")
                    stamp(receipt["timestamp"])
                    for observation in receipt["observations"]:
                        reference(observation)
                    if check == "independent_compiler_probe_rerun":
                        need(receipt["admission_probes"] >= 6 and receipt["shim_probes"] >= 24,
                             "insufficient independent probes")
                    if check == "three_selected_dev_reruns":
                        selection = authority["selected_dev_programs"]
                        need(len(selection) == len(set(selection)) == 3
                             and set(receipt["program_ids"]) == set(selection)
                             and all(any(t["program_id"] == p and t["split"] == "dev" for t in tasks) for p in selection),
                             "wrong deterministic three-dev selection")
            inspect(f"check:{check}", receipt_check)

    status = "NO-GO" if any(p["status"] == "NO-GO" for p in problems) else ("PENDING" if problems else "GO")
    return {"gate_version": VERSION, "status": status, "issues": problems,
            "claim": "Structural eligibility only; caller must authenticate signatures, appointments and observations. "
                     "No runtime, product, live-run or publication authorization is conferred."}
