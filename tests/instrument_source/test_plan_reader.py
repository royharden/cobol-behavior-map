"""Hostile SOURCE refusal vectors; their text is never imported/compiled/executed."""
import unittest

from evaluation.mutant_plan import MAX_BYTES, MutationRefusal, parse_candidate
from instrument_fixtures import HEADER, plan, source


class ClosedPlanReader(unittest.TestCase):
    def test_fixed_wrapper_roundtrip_and_original_identity(self):
        value = plan()
        self.assertEqual(parse_candidate(source(value)).plan, value)

    def test_executable_module_and_wrapper_shapes_refuse_as_data(self):
        original = source(plan())
        vectors = {
            'top-level': original + b"raise RuntimeError('NEVER EXECUTE THIS SOURCE')\n",
            'runtime-import-alias': original.replace(b'import run_plan\n', b'import run_plan as run_plan\n'),
            'foreign-import': original.replace(b'cobolmap.translate.runtime', b'os'),
            'default-argument': original.replace(b'input_present, records):', b'input_present, records=()):'),
            'decorator': original.replace(b'def run_case', b'@print\ndef run_case'),
            'extra-call': original.replace(b'    return run_plan', b'    print("NEVER EXECUTE")\n    return run_plan'),
            'foreign-return': original.replace(b'return run_plan(PLAN, input_present, records)', b'return __import__("os")'),
            'header': original.replace(HEADER.encode(), b'foreign builder header'),
        }
        for name, raw in vectors.items():
            with self.subTest(vector=name):
                with self.assertRaises(MutationRefusal):
                    parse_candidate(raw)

    def test_duplicate_unknown_and_executable_plan_values_refuse(self):
        original = source(plan())
        vectors = [original.replace(b"'version': 1", b"'version': 1, 'version': 1"),
                   original.replace(b"'version': 1", b"'version': 1, 'unknown': None"),
                   original.replace(b"'version': 1", b"'version': __import__('os')")]
        for raw in vectors:
            with self.subTest(raw=raw[:70]):
                with self.assertRaises(MutationRefusal):
                    parse_candidate(raw)

    def test_closed_node_and_source_pointer_binding(self):
        for change in ('unknown-node', 'extra-key', 'foreign-source'):
            value = plan()
            stop = value['paragraphs'][0]['body'][0]
            if change == 'unknown-node': stop['kind'] = 'execute'
            elif change == 'extra-key': stop['command'] = 'NEVER EXECUTE'
            else: stop['span']['source_sha256'] = 'not-a-source-hash'
            with self.subTest(change=change):
                with self.assertRaises(MutationRefusal):
                    parse_candidate(source(value))

    def test_small_deep_literal_and_byte_ceiling_refuse(self):
        raw = (repr(HEADER) + '\nfrom cobolmap.translate.runtime import run_plan\nPLAN = '
               + '[' * 66 + 'None' + ']' * 66 + '\ndef run_case(input_present, records):\n'
               '    return run_plan(PLAN, input_present, records)\n').encode()
        with self.assertRaisesRegex(MutationRefusal, 'depth budget'):
            parse_candidate(raw)
        # Bounded2MiB allocation; rejected before parsing, no AST stress vector.
        with self.assertRaisesRegex(MutationRefusal, 'bounded actual candidate bytes'):
            parse_candidate(b' ' * (MAX_BYTES + 1))

    def test_invalid_utf8_and_wrong_root_type_refuse(self):
        for raw in (b'\xff', source(plan()).decode(), b''):
            with self.subTest(kind=type(raw).__name__):
                with self.assertRaises(MutationRefusal):
                    parse_candidate(raw)
