"""Retained unmeasured metadata/refusal vectors; no authentic replay is fabricated."""
from hashlib import sha256
import json
import unittest

from cobolmap.cli.replay import ReplayRefusal, guarded_name, load_replay, strict_json
from cobolmap.contracts import RunResult
from evaluation.replay_manifest import enumerate_manifest
from retained_builder_data import (DISCLOSURE, SOURCE, artifact_root, bundle_spec,
                                   encoded, fresh_dir, invoke, persist_bundle, write_new)


class ReplayBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifact_root()

    def test_unmeasured_modes_preserve_source_and_processing_without_success(self):
        for mode in ('not_run', 'static', 'fixture'):
            with self.subTest(mode=mode):
                manifest, artifacts = bundle_spec(mode)
                path = persist_bundle(manifest, artifacts)
                evidence = load_replay(path)
                self.assertFalse(evidence.available)
                self.assertEqual(evidence.evidence_mode, mode)
                self.assertEqual(evidence.payload['run_result']['processing_mode'], 'not_run')
                self.assertEqual(evidence.payload['manifest_sha256'], sha256(path.read_bytes()).hexdigest())
                self.assertEqual(evidence.payload['source_and_candidate_text'][0]['text'], SOURCE.decode())
                self.assertEqual(evidence.pointers[0]['pointer'], manifest['pointers'][0]['pointer'])
                self.assertIn(DISCLOSURE, evidence.payload['run_result']['issues'])
                code, output, error = invoke(['report', '--bundle', str(path)])
                self.assertEqual(code, 3)
                self.assertFalse(error)
                document = json.loads(output)
                self.assertEqual(document['status'], 'unavailable')
                self.assertEqual(document['processing_mode'], 'replay')
                self.assertEqual(document['source_evidence_mode'], mode)
                self.assertIsNone(document['recorded_claims']['passed'])
                self.assertIsNone(document['current_live_run']['known_usd'])
                self.assertEqual(document['source_pointers'][0]['pointer'], manifest['pointers'][0]['pointer'])

    def test_actual_claim_disagrees_with_unmeasured_builder_result_and_refuses(self):
        # Only manifest claim is actual; no authored actual observation or result.
        manifest, artifacts = bundle_spec('actual', result_mode='not_run')
        path = persist_bundle(manifest, artifacts)
        code, output, error = invoke(['report', '--bundle', str(path)])
        self.assertEqual(code, 2)
        self.assertFalse(output)
        document = json.loads(error)
        self.assertEqual(document['status'], 'refused')
        self.assertEqual(document['source_evidence_mode'], 'not_run')
        self.assertEqual(document['failures_and_issues'][0]['code'], 'evidence_mode')

    def test_native_actual_completion_without_observation_refs_refuses(self):
        with self.assertRaisesRegex(ValueError, 'completed result requires explicit observed'):
            RunResult(run_id='builder_missing_actual', evidence_mode='actual', status='completed')

    def test_raw_source_hash_and_pointer_span_mismatch_refuse(self):
        for kind in ('hash', 'span', 'pointer-hash'):
            manifest, artifacts = bundle_spec()
            if kind == 'hash': manifest['artifacts'][1]['sha256'] = sha256(b'wrong builder pin').hexdigest()
            elif kind == 'span': manifest['pointers'][0]['pointer']['byte_end'] = len(SOURCE) + 1
            else: manifest['pointers'][0]['pointer']['source_sha256'] = sha256(b'foreign pointer').hexdigest()
            path = persist_bundle(manifest, artifacts)
            with self.subTest(kind=kind):
                with self.assertRaises(ReplayRefusal):
                    load_replay(path)

    def test_closed_manifest_and_duplicate_inventory_refuse(self):
        for kind in ('extra', 'duplicate', 'duplicate-pointer', 'wrong-version'):
            manifest, artifacts = bundle_spec()
            if kind == 'extra': manifest['authority'] = 'builder label is not authority'
            elif kind == 'duplicate': manifest['artifacts'].append(dict(manifest['artifacts'][0]))
            elif kind == 'duplicate-pointer': manifest['pointers'].append(dict(manifest['pointers'][0]))
            else: manifest['schema_version'] = '1'
            with self.subTest(kind=kind):
                with self.assertRaises(ReplayRefusal):
                    load_replay(persist_bundle(manifest, artifacts))

    def test_missing_result_inventory_and_file_are_unavailable_or_refused(self):
        manifest, artifacts = bundle_spec()
        manifest['run_result_artifact'] = 'not_in_inventory'
        path = persist_bundle(manifest, artifacts)
        with self.assertRaises(ReplayRefusal):
            load_replay(path)
        manifest, artifacts = bundle_spec()
        path = persist_bundle(manifest, {'builder-source.txt': artifacts['builder-source.txt']})
        with self.assertRaisesRegex(ReplayRefusal, 'artifact is unavailable'):
            load_replay(path)
        missing = fresh_dir() / 'missing-bundle.json'
        code, output, error = invoke(['demo', '--bundle', str(missing)])
        self.assertEqual(code, 3)
        self.assertFalse(output)
        self.assertEqual(json.loads(error)['status'], 'unavailable')

    def test_json_and_relative_path_contracts_refuse_before_use(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xef\xbb\xbf{}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ReplayRefusal): strict_json(raw, 'builder metadata')
        for path in ('../builder.txt', './builder.txt', 'a//builder.txt', 'builder.txt.', 'C:builder.txt'):
            with self.subTest(path=path):
                with self.assertRaises(ReplayRefusal): guarded_name(path)

    def test_enumeration_preserves_unavailable_source_bytes_and_separate_manifest_hash(self):
        manifest, artifacts = bundle_spec('fixture')
        # Noncanonical spacing is deliberately an input byte edition, not outcome data.
        root = fresh_dir()
        for name, raw in artifacts.items(): write_new(root / name, raw)
        raw_manifest = json.dumps(manifest, indent=1).encode()
        path = write_new(root / 'bundle.json', raw_manifest)
        result = enumerate_manifest(path)
        self.assertFalse(result.available)
        self.assertEqual(result.source_evidence_mode, 'fixture')
        self.assertEqual(result.processing_mode, 'replay')
        self.assertEqual(result.authenticity, 'unverified')
        self.assertEqual(result.admission, 'unverified')
        self.assertEqual(result.supplied_manifest_raw_sha256, sha256(raw_manifest).hexdigest())
        self.assertEqual(result.enumerated_manifest_sha256, sha256(result.manifest_bytes).hexdigest())
        self.assertNotEqual(result.supplied_manifest_raw_sha256, result.enumerated_manifest_sha256)
        self.assertEqual(path.read_bytes(), raw_manifest)
        self.assertEqual((root / 'builder-source.txt').read_bytes(), SOURCE)
        self.assertEqual(json.loads(result.manifest_bytes)['evidence_mode'], 'fixture')
