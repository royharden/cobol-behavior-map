"""Read-only, dev-only replay. Artifact bytes never become executable code."""
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any

MODES = frozenset({"not_run", "static", "fixture", "actual"})
KINDS = frozenset({"source", "candidate", "run_result", "observation", "behavior_map", "receipt", "attachment"})
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
POINTER_KEYS = frozenset({"source_sha256", "filename", "line_start", "line_end", "byte_start", "byte_end"})
MAX_MANIFEST = 8 * 1024 * 1024
MAX_JSON = 32 * 1024 * 1024
MAX_ARTIFACT = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
FORBIDDEN = frozenset({".git", ".ssh", ".aws", ".azure", ".thinking", ".chatexports",
                       "credentials", "auth", "heldout", "held-out", "heldout-custody"})


class ReplayRefusal(ValueError):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)


class ReplayUnavailable(ReplayRefusal):
    """Evidence/provider absent; never a synthetic successful replay."""


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ReplayRefusal(code, message)


def guarded_name(name: str) -> str:
    require(type(name) is str and bool(name) and "\\" not in name and ":" not in name
            and not name.startswith("/") and all(32 <= ord(c) <= 126 for c in name),
            "artifact_path", "relative printable-ASCII forward-slash path required")
    parts = name.split("/")
    require(all(part not in {"", ".", ".."} for part in parts)
            and str(PurePosixPath(name)) == name, "artifact_path", "ambiguous or traversing artifact path")
    forbid_sensitive_parts(parts)
    return name


def forbid_sensitive_parts(parts: Any) -> None:
    require(not any(part.endswith((".", " ")) or PureWindowsPath(part).is_reserved() for part in parts),
            "artifact_alias", "Windows dot/space/device aliases are outside the portable artifact profile")
    require(not any(part.lower() in FORBIDDEN or part.lower() == ".env"
                    or part.lower().startswith(".env.") for part in parts),
            "forbidden_artifact", "private, credential or held-out path is outside this CLI")


def local_input(path: Path) -> Path:
    """Explicit local file, without linked parents or credential/private roots."""
    forbid_sensitive_parts(path.parts)
    require(not str(path).startswith(("\\\\", "//")), "remote_path", "local artifact files only")
    absolute = path.absolute()
    for item in (*absolute.parents, absolute):
        require(not item.is_symlink() and not item.is_junction(), "artifact_link", "linked input path refused")
    resolved = absolute.resolve(strict=True)
    forbid_sensitive_parts(resolved.parts)
    require(resolved.is_file(), "artifact_missing", "input must be a regular file")
    return resolved


def strict_json(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate_key", f"duplicate JSON key in {label}")
            result[key] = value
        return result

    def nonfinite(value: str) -> None:
        raise ReplayRefusal("json_number", f"nonfinite JSON number in {label}: {value}")

    require(not raw.startswith(b"\xef\xbb\xbf"), "json_encoding", f"BOM forbidden in {label}")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReplayRefusal("invalid_json", f"strict UTF8 JSON required: {label}") from exc


def exact_keys(value: Any, keys: set[str], label: str) -> None:
    require(type(value) is dict and set(value) == keys, "record_shape", f"closed keys required: {label}")


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    path: str
    sha256: str
    kind: str
    filename: str | None
    byte_length: int

    def summary(self) -> dict[str, Any]:
        return {"artifact_id": self.artifact_id, "path": self.path, "sha256": self.sha256,
                "kind": self.kind, "filename": self.filename, "byte_length": self.byte_length}


@dataclass(frozen=True)
class ReplayEvidence:
    evidence_mode: str
    available: bool
    payload: dict[str, Any]
    artifacts: tuple[dict[str, Any], ...]
    pointers: tuple[dict[str, Any], ...]
    issues: tuple[str, ...]


class _BundleReader:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        forbid_sensitive_parts(self.root.parts)
        self.total = 0
        self.by_id: dict[str, Artifact] = {}
        self.by_path: dict[str, Artifact] = {}

    def path(self, name: str) -> Path:
        guarded_name(name)
        target = self.root
        for part in name.split("/"):
            target = target / part
            require(not target.is_symlink() and not target.is_junction(), "artifact_link", "linked artifact refused")
        resolved = target.resolve()
        forbid_sensitive_parts(resolved.parts)
        require(resolved.is_relative_to(self.root) and resolved.is_file(),
                "artifact_missing", f"artifact is unavailable: {name}")
        return resolved

    def ingest(self, item: Any) -> None:
        exact_keys(item, {"artifact_id", "path", "sha256", "kind", "filename"}, "artifact")
        key = item["artifact_id"]
        require(type(key) is str and IDENTIFIER.fullmatch(key) is not None,
                "artifact_id", "invalid artifact identifier")
        require(type(item["kind"]) is str and item["kind"] in KINDS, "artifact_kind", "unknown artifact kind")
        require(type(item["sha256"]) is str and SHA256.fullmatch(item["sha256"]) is not None,
                "artifact_hash", "lowercase SHA256 required")
        path = self.path(item["path"])
        require(key not in self.by_id and item["path"] not in self.by_path,
                "duplicate_artifact", "duplicate artifact ID or path")
        require(not any(self.path(existing.path).samefile(path) for existing in self.by_id.values()),
                "duplicate_artifact", "aliased artifact files")
        if item["kind"] == "source":
            guarded_name(item["filename"])
        else:
            require(item["filename"] is None, "artifact_filename", "only source artifacts have logical filenames")
        hashed, length = hashlib.sha256(), 0
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                length += len(chunk)
                require(length <= MAX_ARTIFACT and self.total + length <= MAX_TOTAL,
                        "bundle_limit", "replay artifact budget exceeded; nothing is truncated")
                hashed.update(chunk)
        require(hashed.hexdigest() == item["sha256"], "artifact_hash", f"raw byte hash mismatch: {item['path']}")
        if item["kind"] in {"run_result", "observation", "behavior_map", "receipt"}:
            require(length > 0, "empty_evidence", "evidence document cannot be empty")
        self.total += length
        artifact = Artifact(key, item["path"], item["sha256"], item["kind"], item["filename"], length)
        self.by_id[key] = artifact
        self.by_path[artifact.path] = artifact

    def read(self, artifact: Artifact, limit: int = MAX_JSON) -> bytes:
        require(artifact.byte_length <= limit, "bundle_limit", "structured/text artifact exceeds read budget")
        with self.path(artifact.path).open("rb") as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == artifact.byte_length and len(raw) <= limit
                and hashlib.sha256(raw).hexdigest() == artifact.sha256,
                "artifact_changed", "artifact changed after inventory hashing")
        return raw

    def reference(self, ref: Any, kinds: set[str]) -> Artifact:
        require(ref.path in self.by_path, "unlisted_reference", f"reference missing from inventory: {ref.path}")
        artifact = self.by_path[ref.path]
        require(artifact.kind in kinds and artifact.sha256 == ref.sha256
                and (ref.byte_length is None or ref.byte_length == artifact.byte_length),
                "reference_mismatch", "typed artifact reference does not match inventory")
        return artifact


def load_replay(manifest_path: Path) -> ReplayEvidence:
    """Load supplied records. Integrity checks never authenticate an execution."""
    manifest_path = local_input(manifest_path)
    with manifest_path.open("rb") as stream:
        raw_manifest = stream.read(MAX_MANIFEST + 1)
    require(len(raw_manifest) <= MAX_MANIFEST, "bundle_limit", "replay manifest exceeds 8 MiB")
    manifest = strict_json(raw_manifest, "manifest")
    exact_keys(manifest, {"schema_version", "bundle_id", "captured_at", "evidence_mode", "split",
                          "artifacts", "run_result_artifact", "pointers"}, "manifest")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
            "manifest_version", "replay schema_version must be integer1")
    require(type(manifest["bundle_id"]) is str and IDENTIFIER.fullmatch(manifest["bundle_id"]) is not None,
            "bundle_id", "invalid bundle identifier")
    require(type(manifest["evidence_mode"]) is str and manifest["evidence_mode"] in MODES,
            "evidence_mode", "source evidence mode must use shared EvidenceMode")
    require(manifest["split"] == "dev", "heldout_replay", "CLI replay is dev-only")
    try:
        captured = datetime.fromisoformat(manifest["captured_at"].replace("Z", "+00:00"))
        require(captured.tzinfo is not None, "capture_time", "declared capture time needs timezone")
    except (TypeError, AttributeError, ValueError) as exc:
        raise ReplayRefusal("capture_time", "invalid declared capture timestamp") from exc
    require(type(manifest["artifacts"]) is list and 1 <= len(manifest["artifacts"]) <= 4096,
            "artifact_inventory", "bounded nonempty artifact inventory required")
    require(type(manifest["pointers"]) is list and len(manifest["pointers"]) <= 100000,
            "pointer_inventory", "invalid pointer inventory")
    reader = _BundleReader(manifest_path.parent)
    for item in manifest["artifacts"]:
        reader.ingest(item)
    try:
        from cobolmap.contracts import BehaviorMap, ExecutionObservation, RunResult, SourcePointer
    except ImportError as exc:
        raise ReplayUnavailable("contracts_unavailable", "shared evidence contracts are unavailable") from exc

    def contract(model: Any, artifact: Artifact) -> Any:
        raw = reader.read(artifact)
        strict_json(raw, artifact.path)  # Detect duplicate/nonfinite input before Pydantic JSON handling.
        try:
            return model.model_validate_json(raw)
        except ValueError as exc:
            raise ReplayRefusal("evidence_contract", f"shared model refused {artifact.path}") from exc

    key = manifest["run_result_artifact"]
    require(type(key) is str and key in reader.by_id, "run_result_missing", "run result must be inventoried")
    result_artifact = reader.by_id[key]
    require(result_artifact.kind == "run_result", "artifact_kind", "run result artifact has wrong kind")
    result = contract(RunResult, result_artifact)
    require(result.evidence_mode == manifest["evidence_mode"], "evidence_mode", "manifest/result mode disagreement")
    source_artifacts: dict[tuple[str, str], Artifact] = {}
    for artifact in reader.by_id.values():
        if artifact.kind == "source":
            source_key = (artifact.sha256, artifact.filename)
            require(source_key not in source_artifacts, "source_identity", "ambiguous source identity")
            source_artifacts[source_key] = artifact
    source_hashes = {artifact.sha256 for artifact in source_artifacts.values()}
    candidate_hashes = {artifact.sha256 for artifact in reader.by_id.values() if artifact.kind == "candidate"}
    resolved: dict[tuple[Any, ...], dict[str, Any]] = {}

    def pointer_identity(pointer: Any) -> tuple[Any, ...]:
        return tuple(getattr(pointer, name) for name in sorted(POINTER_KEYS))

    for item in manifest["pointers"]:
        exact_keys(item, {"source_artifact_id", "pointer"}, "pointer inventory entry")
        require(type(item["source_artifact_id"]) is str and item["source_artifact_id"] in reader.by_id,
                "pointer_source", "pointer source must be inventoried")
        artifact = reader.by_id[item["source_artifact_id"]]
        require(artifact.kind == "source", "pointer_source", "pointer must bind source bytes")
        try:
            pointer = SourcePointer.model_validate(item["pointer"])
            pointer.resolve(reader.read(artifact), artifact.filename)
        except (ValueError, UnicodeError) as exc:
            raise ReplayRefusal("pointer_unresolved", "pointer source/hash/UTF8/span/line disagreement") from exc
        identity = pointer_identity(pointer)
        require(identity not in resolved, "duplicate_pointer", "duplicate pointer declaration")
        resolved[identity] = {"source_artifact_id": artifact.artifact_id, "pointer": pointer.model_dump(mode="json")}

    def inspect_pointers(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) == POINTER_KEYS:
                pointer = SourcePointer.model_validate(value)
                require(pointer_identity(pointer) in resolved, "unlisted_pointer", "model pointer lacks resolved inventory binding")
            for child in value.values():
                inspect_pointers(child)
        elif isinstance(value, list):
            for child in value:
                inspect_pointers(child)

    observations, maps, texts, issues = [], [], [], list(result.issues)
    seen_observations: set[str] = set()
    for ref in result.observations:
        artifact = reader.reference(ref, {"observation"})
        require(artifact.path not in seen_observations, "duplicate_observation", "duplicate observation reference")
        seen_observations.add(artifact.path)
        observation = contract(ExecutionObservation, artifact)
        require(observation.source_sha256 in source_hashes, "observation_source", "observation source bytes are absent")
        require(observation.candidate_sha256 is None or observation.candidate_sha256 in candidate_hashes,
                "observation_candidate", "candidate byte identity is absent")
        require(observation.evidence.mode == result.evidence_mode, "evidence_mode", "mixed source evidence modes refused")
        if observation.evidence.mode in {"not_run", "static"}:
            require(observation.ordinary is None and observation.outcome == "not_run",
                    "evidence_mode", "unmeasured mode cannot carry a completed observation")
        if observation.evidence.mode == "actual":
            missing = observation.evidence.missing_actual()
            if missing:
                raise ReplayUnavailable("actual_evidence_missing", ", ".join(missing))
        for evidence_ref in (observation.evidence.runtime_receipt, observation.evidence.admission_authority):
            if evidence_ref is not None:
                reader.reference(evidence_ref, {"receipt"})
        if observation.trace_artifact is not None:
            reader.reference(observation.trace_artifact, {"receipt", "attachment"})
        observations.append(observation.model_dump(mode="json"))
        if observation.outcome not in {"completed", "handled", "not_run"}:
            issues.append(f"{observation.task_id}/{observation.case_sha256}: {observation.outcome}")
    for artifact in reader.by_id.values():
        if artifact.kind == "behavior_map":
            model = contract(BehaviorMap, artifact)
            require((model.source_sha256, model.filename) in source_artifacts,
                    "map_source", "behavior map source bytes are absent")
            data = model.model_dump(mode="json")
            inspect_pointers(data)
            maps.append(data)
        elif artifact.kind in {"source", "candidate"}:
            try:
                text = reader.read(artifact).decode("utf-8")
            except UnicodeError as exc:
                raise ReplayRefusal("text_encoding", "source/candidate text must be UTF8") from exc
            texts.append({"artifact_id": artifact.artifact_id, "kind": artifact.kind,
                          "filename": artifact.filename, "sha256": artifact.sha256, "text": text})
    available = (any(item["outcome"] != "not_run" for item in observations)
                 and result.evidence_mode in {"fixture", "actual"})
    if not available:
        issues.append("No recorded runtime observations available; measurement remains not_run.")
    payload = {"bundle_id": manifest["bundle_id"], "declared_capture_time": manifest["captured_at"],
               "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(), "split": "dev",
               "run_result": result.model_dump(mode="json"), "observations": observations,
               "behavior_maps": maps, "source_and_candidate_text": texts}
    return ReplayEvidence(result.evidence_mode, available, payload,
                          tuple(item.summary() for item in reader.by_id.values()),
                          tuple(resolved.values()), tuple(issues))
