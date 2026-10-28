"""Re-enumerate an actually supplied dev bundle; never fabricate run artifacts."""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from cobolmap.cli.replay import (MAX_MANIFEST, ReplayRefusal, load_replay,
                                 local_input, strict_json)


@dataclass(frozen=True)
class ManifestEnumeration:
    manifest_bytes: bytes
    supplied_manifest_raw_sha256: str
    enumerated_manifest_sha256: str
    artifacts: tuple[dict, ...]
    source_evidence_mode: str
    available: bool
    issues: tuple[str, ...]
    processing_mode: str = 'replay'
    authenticity: str = 'unverified'
    admission: str = 'unverified'


def enumerate_manifest(manifest_path: Path) -> ManifestEnumeration:
    """Validate existing supplied raw files with the accepted CLI and enumerate them.

    The input inventory is indispensable: kind, source logical filename, capture time
    and evidence mode cannot truthfully be guessed from filenames. No directories are
    swept, files written, results/candidates synthesized or code executed. Original
    result/observation bytes remain untouched; canonicalization concerns ONLY the
    replay manifest, whose raw and canonical identities are reported separately.
    """
    path = local_input(manifest_path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise ReplayRefusal('bundle_limit', 'supplied manifest exceeds byte budget')
    supplied = strict_json(raw, 'supplied manifest')
    evidence = load_replay(path)
    # Detect a manifest changing between the first read and CLI validation.
    if sha256(raw).hexdigest() != evidence.payload['manifest_sha256']:
        raise ReplayRefusal('artifact_changed', 'manifest changed during enumeration')
    inventory = []
    for artifact in evidence.artifacts:
        inventory.append({key: artifact[key] for key in
                          ('artifact_id', 'path', 'sha256', 'kind', 'filename')})
    manifest = {'schema_version': 1, 'bundle_id': supplied['bundle_id'],
                'captured_at': supplied['captured_at'], 'evidence_mode': evidence.evidence_mode,
                'split': 'dev', 'artifacts': inventory,
                'run_result_artifact': supplied['run_result_artifact'],
                'pointers': list(evidence.pointers)}
    encoded = json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(encoded) > MAX_MANIFEST:
        raise ReplayRefusal('bundle_limit', 'enumerated manifest exceeds byte budget')
    return ManifestEnumeration(encoded, sha256(raw).hexdigest(), sha256(encoded).hexdigest(),
                               evidence.artifacts, evidence.evidence_mode,
                               evidence.available, evidence.issues)
