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

VERSION = "m10-p2-v2"
PLAN = "552ddcb9121deb21489a903eaf77979b8068231a94a0fb714b948094c8d4dbed"
SHA = re.compile(r"[0-9a-f]{64}\Z")
DOMAINS = {"decimal_fees", "sequential_status", "year_window"}
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

    need(not raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM forbidden")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=nonfinite, parse_float=nonfinite)


def shape(value: Any, schema: dict[str, Any], at: str = "record") -> None:
    """Closed, deliberately small subset used by our bundled JSON schemas only."""
    types = {"object": dict, "array": list, "string": str, "integer": int,
             "boolean": bool, "null": type(None)}
    declared = schema["type"]
    allowed = declared if isinstance(declared, list) else [declared]
    need(type(value) in [types[name] for name in allowed], f"{at}: wrong type")
    if value is None:
        return
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
        need(len(value) <= schema.get("maxItems", len(value)), f"{at}: too many items")
        for index, item in enumerate(value):
            shape(item, schema["items"], f"{at}[{index}]")
    elif isinstance(value, str):
        need(len(value) >= schema.get("minLength", 0), f"{at}: short string")
        if schema.get("minLength", 1) > 0:
            need(bool(value.strip()), f"{at}: blank value")
        if "pattern" in schema:
            need(re.fullmatch(schema["pattern"], value) is not None, f"{at}: pattern")
    elif type(value) is int:
        need(value >= schema.get("minimum", 0), f"{at}: below minimum")
        need(value <= schema.get("maximum", value), f"{at}: above maximum")


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

    def document(ref: dict[str, str], name: str) -> Any:
        value = strict_json(reference(ref))
        shape(value, strict_json((schema_root / f"{name}.schema.json").read_bytes()))
        return value

    def authority_load() -> Any:
        need(SHA.fullmatch(authority_sha256) is not None, "externally approved digest required")
        raw = read(authority_path)
        need(hashlib.sha256(raw).hexdigest() == authority_sha256,
             "authority digest mismatch")
        value = strict_json(raw)
        shape(value, strict_json((schema_root / "authority.schema.json").read_bytes()))
        return value

    authority = inspect("authority", authority_load)
    record = inspect("record", lambda: load(record_path, "go-record"))
    if authority is not None and record is not None:
        inspect("binding", lambda: need(
            record["authority_sha256"] == authority_sha256
            and record["plan_sha256"] == authority["plan_sha256"] == PLAN
            and record["gate_version"] == VERSION, "authority/plan/version mismatch"))
        actors = {actor["role"]: actor for actor in authority["actors"]}
        authors = {author["session_id"]: author for author in authority["authors"]}

        def roles() -> None:
            need(len(actors) == len(authority["actors"]) == 4
                 and set(actors) == {"builder", "custodian", "verifier", "roy"}, "four named roles required")
            sessions = [a["session_id"] for a in actors.values()]
            need(len(set(sessions)) == 4, "roles require separate sessions")
            need(len({a["actor_id"] for a in actors.values()}) == 4, "roles require distinct identities")
            need(actors["custodian"]["harness"] != actors["builder"]["harness"],
                 "custodian requires different harness")
            need(actors["builder"]["session_id"] in authority["author_sessions"],
                 "builder must be disclosed in author sessions")
            need(len(authors) == len(authority["authors"])
                 and len({a["actor_id"] for a in authors.values()}) == len(authors)
                 and len(set(authority["author_sessions"])) == len(authority["author_sessions"])
                 and set(authors) == set(authority["author_sessions"]), "author profile/session inventory mismatch")
            builder = actors["builder"]
            need(all(authors[builder["session_id"]][k] == builder[k]
                     for k in ("actor_id", "session_id", "harness", "brief", "lineage_sessions")),
                 "builder author profile differs from appointment")
            author_lineage = {session for author in authors.values()
                              for session in [author["session_id"], *author["lineage_sessions"]]}
            for role in ("custodian", "verifier"):
                actor = actors[role]
                need(actor["actor_id"] not in {a["actor_id"] for a in authors.values()},
                     "custodian/verifier identity is a builder author")
                need(not (set(actor["lineage_sessions"] + [actor["session_id"]])
                          & author_lineage), "custodian/verifier has author lineage")
                need(not (set(actor["lineage_sessions"] + [actor["session_id"]])
                          & set(actors["builder"]["lineage_sessions"] + [actors["builder"]["session_id"]])),
                     "builder/child/fork cannot be independent")
            need(not (set(actors["verifier"]["lineage_sessions"] + [actors["verifier"]["session_id"]])
                      & set(actors["custodian"]["lineage_sessions"] + [actors["custodian"]["session_id"]])),
                 "verifier cannot be custodian lineage")
            for actor in actors.values():
                reference(actor["appointment"])
                reference(actor["brief"])
            for author in authors.values():
                reference(author["brief"])
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

        def brief_binding() -> None:
            frozen = [(ref["path"], ref["sha256"]) for ref in record["frozen_briefs"]]
            approved = {(actor["brief"]["path"], actor["brief"]["sha256"]) for actor in actors.values()}
            approved.update((author["brief"]["path"], author["brief"]["sha256"]) for author in authors.values())
            need(len(frozen) == len(set(frozen)) and set(frozen) == approved,
                 "frozen briefs must exactly match approved actor briefs without duplicates")

        inspect("brief_binding", brief_binding)

        def seal() -> None:
            need(record["seal"]["manifest_sha256"] == pins["private_manifest"]["sha256"]
                 == authority["seal_manifest_sha256"], "Roy seal/manifest mismatch")
            need(record["seal"]["confirmed_at"] == authority["seal_confirmed_at"], "seal date mismatch")
            stamp(record["seal"]["confirmed_at"])
            reference(record["seal"]["roy_confirmation"])

        inspect("seal", seal)
        family_records = []
        for envelope in record["families"]:
            metadata = envelope["metadata"]
            family_records.append({**metadata, "template_commitment": envelope["template_commitment"]})
            def family_author(envelope: Any = envelope, metadata: Any = metadata) -> None:
                reference(envelope["author_provenance"])
                need(metadata["author_provenance_sha256"] == envelope["author_provenance"]["sha256"],
                     "family author provenance commitment mismatch")
            inspect("family_author_provenance", family_author)
        family_ids: set[str] = set()
        for split, programs in (("dev", 4), ("heldout", 3)):
            def families(split: str = split, programs: int = programs) -> None:
                selected = [f for f in family_records if f["split"] == split]
                need(len(selected) == 6, f"{split}: six families required")
                for domain in DOMAINS:
                    need(sum(f["domain"] == domain for f in selected) == 2, "two families per domain")
                for family in selected:
                    need(family["family_id"] not in family_ids, "duplicate family")
                    family_ids.add(family["family_id"])
                    need(len(set(family["hazard_ids"])) >= 2, "family requires two distinct hazard IDs")
                    need(len(set(family["program_ids"])) == programs
                         and len(family["program_ids"]) == programs, "program count per family")
                    reference(family["template_commitment"])
            inspect(f"families:{split}", families)

        tasks = [{**envelope, **envelope["binding"]} for envelope in record["tasks"]]
        inspect("task_inventory", lambda: need(
            len(tasks) == 84 and len({t["task_id"] for t in tasks}) == 84,
            "exactly 48 dev and 36 heldout original/changed task IDs required"))
        declared_programs: set[str] = set()
        for family in family_records:
            for program in family["program_ids"]:
                def panels(program: str = program, family: Any = family) -> None:
                    need(program not in declared_programs, "program appears in multiple families")
                    declared_programs.add(program)
                    pair = [t for t in tasks if t["program_id"] == program]
                    need(len(pair) == 2 and {t["panel"] for t in pair} == {"unchanged", "change"},
                         "original and changed task required per program")
                    need(all(t["family_id"] == family["family_id"] and t["split"] == family["split"] for t in pair),
                         "task split/family mismatch")
                    need(pair[0]["oracle_source"]["sha256"] != pair[1]["oracle_source"]["sha256"], "change unchanged")
                    need(pair[0]["original_source"] == pair[1]["original_source"], "panel original-source mismatch")
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
                for name in ("original_source", "oracle_source", "input_fields", "output_fields", "recipe",
                             "program_manifest", "case_manifest", "oracle_receipt", "trace_receipt"):
                    reference(task[name])
                need(task["original_sha256"] == task["original_source"]["sha256"]
                     and task["oracle_source_sha256"] == task["oracle_source"]["sha256"]
                     and task["fields_sha256"] == task["input_fields"]["sha256"]
                     and task["recipe_sha256"] == task["recipe"]["sha256"]
                     and task["generator_sha256"] == pins["generator"]["sha256"], "task binding hash mismatch")
                manifest = document(task["program_manifest"], "program-manifest")
                need(all(manifest[k] == task[k] for k in ("program_id", "family_id", "split"))
                     and manifest["source_sha256"] == task["oracle_source_sha256"]
                     and manifest["input_fields_sha256"] == task["input_fields"]["sha256"]
                     and manifest["output_fields_sha256"] == task["output_fields"]["sha256"],
                     "ProgramManifest/task/field binding mismatch")
                need(manifest["allowed_return_codes"] == sorted(set(manifest["allowed_return_codes"]))
                     and 0 in manifest["allowed_return_codes"], "invalid declared return-code set")
                need(set(task["hazards"]) == {h["hazard_id"] for h in manifest["hazards"]}, "manifest hazard mismatch")
                source = reference(task["oracle_source"])
                def span(target: Any) -> None:
                    need(target["file"] == task["oracle_source"]["path"]
                         and 0 <= target["byte_start"] < target["byte_end"] <= len(source)
                         and target["line"] == source[:target["byte_start"]].count(b"\n") + 1,
                         "manifest span does not resolve against exact oracle source")
                targets = []
                for loop_entry in manifest["loops"]:
                    span(loop_entry["target"])
                    targets.append(loop_entry["target"]["byte_start"])
                    need(int(loop_entry["step"]) != 0, "zero induction step")
                    proof = loop_entry["proof"]
                    for target in [proof["initialization_span"], *proof["update_spans"], proof["exit_span"]]:
                        span(target)
                need(targets == sorted(set(targets)), "loop targets must be unique in source order")
                for hazard in manifest["hazards"]:
                    span(hazard["target"])
                if task["panel"] == "unchanged":
                    need(task["oracle_source"] == task["original_source"]
                         and task["change_sha256"] is None and task["change"] is None, "unchanged task has change")
                else:
                    need(task["change"] is not None and task["change_sha256"] == task["change"]["sha256"],
                         "change panel requires structured edit artifact")
                    change = document(task["change"], "change")
                    need(change["task_id"] == task["task_id"] and change["original_sha256"] == task["original_sha256"]
                         and change["changed_sha256"] == task["oracle_source_sha256"], "structured change binding mismatch")
                    original = reference(task["original_source"])
                    target = change["target"]
                    need(target["file"] == task["original_source"]["path"]
                         and 0 <= target["byte_start"] < target["byte_end"] <= len(original)
                         and target["line"] == original[:target["byte_start"]].count(b"\n") + 1,
                         "change target does not resolve against original source")
                    need(type(change["before"]) is type(change["after"]) and change["before"] != change["after"],
                         "change types differ or edit is a no-op")
                    need((type(change["before"]) is bool) == (change["operation"] == "set_rounded"), "wrong edit value type")
                for name in ("input_fields", "output_fields"):
                    fields = document(task[name], "fields")
                    need(fields["program_id"] == task["program_id"]
                         and fields["source_sha256"] == task["oracle_source_sha256"], "field document source mismatch")
                observed = strict_json(reference(task["oracle_receipt"]))
                shape(observed, strict_json((schema_root / "task-oracle.schema.json").read_bytes()))
                need(observed["task_id"] == task["task_id"]
                     and observed["source_sha256"] == task["oracle_source"]["sha256"]
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
                need(trace["task_id"] == task["task_id"] and trace["source_sha256"] == task["oracle_source"]["sha256"]
                     and trace["oracle_receipt_sha256"] == task["oracle_receipt"]["sha256"]
                     and trace["session_id"] == expected_actor["session_id"]
                     and trace["mode"] == "actual" and trace["result"] == "pass"
                     and trace["valid_cases"] == 160 and trace["faults"] == 0
                     and trace["ordinary_observations"]["sha256"] == runs[0]["observations"]["sha256"],
                     "trace/untraced ordinary observations mismatch")
                reference(trace["ordinary_observations"])
                reference(trace["execution_log"])
            inspect(f"task:{task['task_id']}", task_check)

        artifact_paths: set[str] = set()
        provenance_by_path: dict[str, Any] = {}
        for artifact in record["artifacts"]:
            def artifact_check(artifact: Any = artifact) -> None:
                path = artifact["file"]["path"]
                need(path not in artifact_paths, "duplicate provenance artifact")
                artifact_paths.add(path)
                reference(artifact["file"])
                sidecar = document(artifact["provenance"], "provenance")
                need(sidecar["artifact_path"] == path and sidecar["artifact_sha256"] == artifact["file"]["sha256"],
                     "sidecar does not bind exact artifact bytes")
                role = "custodian" if sidecar["split"] == "heldout" else "builder"
                actor = actors["custodian"] if role == "custodian" else authors[sidecar["author_session_id"]]
                need(sidecar["author_session_id"] == actor["session_id"]
                     and sidecar["author_harness"] == actor["harness"]
                     and sidecar["author_callsign"] == actor["actor_id"], "provenance author mismatch")
                need(sidecar["brief_sha256"] == actor["brief"]["sha256"], "unapproved provenance brief")
                need(sidecar["generator_sha256"] in (None, pins["generator"]["sha256"]), "generator mismatch")
                if sidecar["artifact_kind"] == "input":
                    need(sidecar["generator_sha256"] == pins["generator"]["sha256"], "generated input needs generator pin")
                if sidecar["split"] == "shared":
                    need(sidecar["family_id"] is None, "shared instrument has family")
                else:
                    need(any(f["family_id"] == sidecar["family_id"] and f["split"] == sidecar["split"]
                             for f in family_records), "artifact family/split mismatch")
                if sidecar["source_sha256"] is None:
                    need(sidecar["split"] == "shared" and sidecar["artifact_kind"] == "specification",
                         "only independent shared specification may omit source hash")
                if sidecar["artifact_kind"] == "source":
                    need(sidecar["parent_artifact_sha256"] is None, "original source must have null parent")
                if sidecar["artifact_kind"] == "changed_source":
                    need(sidecar["parent_artifact_sha256"] is not None, "changed source requires original parent")
                stamp(sidecar["created_at"])
                created = datetime.fromisoformat(sidecar["created_at"].replace("Z", "+00:00"))
                need(created.utcoffset().total_seconds() == 0, "provenance timestamp must be UTC")
                for ref in sidecar["evidence_paths"]:
                    reference(ref)
                provenance_by_path[path] = {"file": artifact["file"], "provenance": artifact["provenance"],
                                            "sidecar": sidecar, "role": role}
                if sidecar["license_status"] == "pending":
                    need(sidecar["license_id"] is None and sidecar["license_approval_id"] is None,
                         "pending license must not invent approval")
                    raise Pending("license_pending: Roy has not approved artifact use")
                need(sidecar["license_status"] == "approved", "license denied")
                license_class = artifact["license_class"]
                need(sidecar["license_id"] == authority["licenses"][license_class]
                     and sidecar["license_approval_id"] == authority["license_approval_ids"][license_class]
                     and bool(sidecar["evidence_paths"]), "unapproved license/decision evidence")
            inspect("provenance", artifact_check)
        task_artifacts = ("original_source", "oracle_source", "input_fields", "output_fields", "recipe",
                          "program_manifest", "case_manifest")
        required_artifacts = {t[k]["path"] for t in tasks for k in task_artifacts}
        required_artifacts.update(t["change"]["path"] for t in tasks if t["change"] is not None)
        required_artifacts.update(ref["path"] for ref in record["original_artifacts"])
        inspect("provenance_coverage", lambda: need(required_artifacts <= artifact_paths,
                                                   "missing per-artifact provenance"))
        for ref in record["original_artifacts"]:
            def original_binding(ref: Any = ref) -> None:
                reference(ref)
                need(provenance_by_path[ref["path"]]["file"] == ref,
                     "original artifact digest differs from provenance")
            inspect("original_artifact_binding", original_binding)
        for task in tasks:
            def task_provenance(task: Any = task) -> None:
                role = "builder" if task["split"] == "dev" else "custodian"
                for name in task_artifacts + (("change",) if task["change"] is not None else ()):
                    artifact = provenance_by_path[task[name]["path"]]
                    sidecar = artifact["sidecar"]
                    need(artifact["file"] == task[name] and sidecar["split"] == task["split"]
                         and sidecar["family_id"] == task["family_id"]
                         and artifact["role"] == role, "task provenance split/family/author/digest mismatch")
                    source_hash = task["original_sha256"] if name in ("original_source", "change") else task["oracle_source_sha256"]
                    need(sidecar["source_sha256"] == source_hash, "task artifact source hash mismatch")
                source_entry = provenance_by_path[task["oracle_source"]["path"]]
                manifest = document(task["program_manifest"], "program-manifest")
                need(manifest["provenance_sha256"] == source_entry["provenance"]["sha256"],
                     "ProgramManifest source-sidecar commitment mismatch")
                source_sidecar = source_entry["sidecar"]
                need(source_sidecar["artifact_kind"] == ("source" if task["panel"] == "unchanged" else "changed_source"),
                     "wrong original/changed source artifact kind")
                if task["panel"] == "change":
                    need(source_sidecar["parent_artifact_sha256"] == task["original_sha256"],
                         "changed source parent differs from original")
            inspect(f"task_provenance:{task['task_id']}", task_provenance)

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
