"""Public CLI refusal routes; no model/backend/guest or candidate invocation."""
import json
import unittest

from retained_builder_data import artifact_root, fresh_dir, invoke, write_new


class CliRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifact_root()

    def assert_unmeasured(self, document):
        self.assertEqual(document['current_live_run']['status'], 'not_run')
        self.assertTrue(all(value is None for key, value in document['current_live_run'].items() if key != 'status'))
        self.assertEqual(document['admission_status'], 'pending')
        self.assertEqual(document['authenticity_status'], 'not_established')

    def test_help_is_bounded_and_lists_public_commands(self):
        code, output, error = invoke(['--help'])
        self.assertEqual(code, 0)
        self.assertFalse(error)
        for name in ('map', 'translate', 'report', 'demo'):
            self.assertIn(name, output)

    def test_missing_unknown_command_mode_and_format_refuse(self):
        for args in ([], ['unknown'], ['report', '--mode', 'actual'], ['report', '--format', 'invalid']):
            with self.subTest(args=args):
                code, output, error = invoke(args)
                self.assertEqual(code, 2)
                self.assertFalse(output)
                self.assertIn('usage:', error)

    def test_no_bundle_is_not_run_not_a_demo(self):
        for command in ('report', 'demo'):
            with self.subTest(command=command):
                code, output, error = invoke([command])
                self.assertEqual(code, 3)
                self.assertFalse(error)
                document = json.loads(output)
                self.assertEqual(document['status'], 'unavailable')
                self.assertEqual(document['source_evidence_mode'], 'not_run')
                self.assertEqual(document['processing_mode'], 'replay')
                self.assert_unmeasured(document)

    def test_live_oracle_flags_cannot_authorize_or_read_missing_bundle(self):
        path = fresh_dir() / 'not-created.json'
        for mode in ('live', 'oracle'):
            with self.subTest(mode=mode):
                code, output, error = invoke(['report', '--mode', mode, '--bundle', str(path)])
                self.assertEqual(code, 3)
                self.assertFalse(error)
                document = json.loads(output)
                self.assertEqual(document['status'], 'mode_blocked')
                self.assertEqual(document['processing_mode'], 'not_run')
                self.assert_unmeasured(document)
        self.assertFalse(path.exists())

    def test_missing_input_and_invalid_utf8_refuse_without_generated_code(self):
        root = fresh_dir()
        invalid = write_new(root / 'invalid-builder.txt', b'\xff')
        for command in ('map', 'translate'):
            for path, expected in ((root / 'not-created.txt', 3), (invalid, 2)):
                with self.subTest(command=command, path=path.name):
                    code, output, error = invoke([command, str(path)])
                    self.assertEqual(code, expected)
                    self.assertFalse(output)
                    document = json.loads(error)
                    self.assert_unmeasured(document)
                    self.assertNotIn('translation', document.get('payload') or {})

    def test_fresh_output_is_exclusive_and_existing_bytes_retained(self):
        path = fresh_dir() / 'builder-output.json'
        code, output, error = invoke(['report', '--output', str(path)])
        self.assertEqual(code, 3)
        self.assertFalse(output or error)
        original = path.read_bytes()
        self.assert_unmeasured(json.loads(original))
        # Reviewed native emitter uses open('x'); this requests only refusal,
        # never a destructive test-helper write or overwrite.
        code, output, error = invoke(['report', '--output', str(path)])
        self.assertEqual(code, 2)
        self.assertFalse(output)
        self.assertEqual(json.loads(error)['status'], 'refused')
        self.assertEqual(path.read_bytes(), original)

    def test_windows_output_alias_refuses_before_file_creation(self):
        path = fresh_dir() / 'builder-output.json.'
        code, output, error = invoke(['report', '--output', str(path)])
        self.assertEqual(code, 2)
        self.assertFalse(output)
        self.assertEqual(json.loads(error)['status'], 'refused')
