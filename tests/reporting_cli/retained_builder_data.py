"""Exclusive retained builder metadata, never historical model/oracle evidence."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path
from uuid import uuid4

from cobolmap.cli import main
from cobolmap.contracts import RunResult, canonical_json

DISCLOSURE = 'Synthetic builder unmeasured metadata; no model, oracle, candidate, observation or receipt.'
SOURCE = b'builder <tag>& data\n'


@lru_cache(maxsize=1)
def artifact_root():
    allowed = (Path.cwd() / '.agent-work' / 'reporting-cli-diagnostics').resolve()
    run = Path(os.environ['M10_REPORTING_CLI_RUN_ROOT']).resolve()
    if run.parent != allowed or not run.is_dir():
        raise ValueError('parent-provisioned fresh owned run directory required')
    root = run / 'vectors'
    root.mkdir(exist_ok=False)
    print('BUILDER_RETAINED_INPUTS=' + str(root))
    return root


def fresh_dir():
    path = artifact_root() / ('builder-' + uuid4().hex)
    path.mkdir(exist_ok=False)
    return path


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    return path


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode()


def bundle_spec(mode='not_run', *, result_mode=None):
    """Every result is not_run, all measured metrics null, no observations.

    'actual' may be used only as an inconsistent manifest claim in negative tests;
    no authored result/observation/receipt is labeled actual.
    """
    if mode == 'actual' and result_mode != 'not_run':
        raise ValueError('actual fixture records forbidden; negative manifest claim only')
    result = RunResult(run_id='builder_not_run', evidence_mode=result_mode or mode,
                       issues=(DISCLOSURE,))
    artifacts = {'run-result.json': canonical_json(result), 'builder-source.txt': SOURCE}
    manifest = {
        'schema_version': 1, 'bundle_id': 'builder_' + uuid4().hex,
        # This is the real builder file-creation timestamp, not a historical run.
        'captured_at': datetime.now(timezone.utc).isoformat(), 'evidence_mode': mode,
        'split': 'dev', 'run_result_artifact': 'builder_result',
        'artifacts': [
            {'artifact_id': 'builder_result', 'path': 'run-result.json',
             'sha256': sha256(artifacts['run-result.json']).hexdigest(), 'kind': 'run_result', 'filename': None},
            {'artifact_id': 'builder_source', 'path': 'builder-source.txt',
             'sha256': sha256(SOURCE).hexdigest(), 'kind': 'source', 'filename': 'builder-source.txt'},
        ],
        'pointers': [{'source_artifact_id': 'builder_source', 'pointer': {
            'source_sha256': sha256(SOURCE).hexdigest(), 'filename': 'builder-source.txt',
            'line_start': 1, 'line_end': 1, 'byte_start': 0, 'byte_end': 7,
        }}],
    }
    return manifest, artifacts


def persist_bundle(manifest, artifacts):
    root = fresh_dir()
    for name, raw in artifacts.items():
        if name not in ('run-result.json', 'builder-source.txt'):
            raise ValueError('closed builder file names required')
        write_new(root / name, raw)
    path = write_new(root / 'bundle.json', encoded(manifest))
    return path


def invoke(arguments):
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = main(arguments)
        except SystemExit as error:
            code = error.code
    return code, stdout.getvalue(), stderr.getvalue()
