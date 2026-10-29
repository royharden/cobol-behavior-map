"""Native DEV scripted-control journeys, never compiler/model study results."""
from dataclasses import replace
import unittest

from cobolmap.contracts import canonical_json
from cobolmap.providers import ScriptedMock
from evaluation.arms import prepare_arm
from evaluation.prompts import build_fixture_initial_prompt
from evaluation.run import run_dev_fixture
from fixture_data import IDS, fixture_unit


class ControlJourneyTests(unittest.TestCase):
    def assert_control_only(self, trace):
        self.assertEqual(trace.evidence_mode, 'fixture')
        self.assertEqual(trace.processing_mode, 'dev_fixture_control')
        self.assertEqual(trace.count_provenance, 'caller_scripted_control_not_measurement')
        self.assertFalse(trace.dispatch_allowed)
        self.assertFalse(trace.study_complete)
        self.assertIsNone(trace.actual_efficacy)
        self.assertIsNone(trace.actual_cost_usd)
        for call in trace.calls:
            self.assertEqual(call.result.provenance, 'fixture')
            self.assertIs(call.result.sent, False)
            self.assertIsNone(call.result.model_id)
            self.assertIsNone(call.result.cost_usd)
            self.assertIsNone(call.result.usage.input_tokens)
            self.assertIsNone(call.result.usage.output_tokens)
            self.assertEqual(call.candidate.evidence_mode, 'fixture')
            self.assertIsNone(call.candidate.model_id)
            self.assertIsNone(call.candidate.known_usd)
            self.assertIsNone(call.candidate.reserved_unknown_usd)

    def test_zero_repair_inherits_exact_shared_c_in_both_forks(self):
        unit = fixture_unit(c_pass=True)
        trace = run_dev_fixture(unit)
        self.assertEqual(trace.status, 'control_complete')
        self.assertEqual([(x.arm, x.attempt) for x in trace.calls], [('B', 0), ('C', 0)])
        shared = trace.calls[1].candidate
        for state in trace.repair_states:
            self.assertIs(state.shared_c, shared)
            self.assertIs(state.selected, shared)
            self.assertEqual(state.attempts, ())
            self.assertEqual(state.loop_failures, (0,))
            self.assertEqual(state.stopped, 'loop_pass')
            self.assertFalse(state.verification_disclosed)
        self.assertEqual(trace.shared_c_inheritance, (('D', IDS['C', 0]), ('R', IDS['C', 0])))
        self.assert_control_only(trace)

    def test_failed_c_diagnostic_then_simulated_first_repair_pass(self):
        trace = run_dev_fixture(fixture_unit())
        self.assertEqual(trace.status, 'control_complete')
        self.assertEqual([(x.arm, x.attempt) for x in trace.calls],
                         [('B', 0), ('C', 0), ('D', 1), ('R', 1)])
        self.assertEqual(trace.calls[1].candidate.status, 'refused')
        for state in trace.repair_states:
            self.assertIs(state.shared_c, trace.calls[1].candidate)
            self.assertEqual(state.loop_failures, (32, 0))
            self.assertEqual(state.selected.attempt, 1)
            self.assertEqual(state.stopped, 'loop_pass')
        self.assert_control_only(trace)

    def test_maximum_three_uses_last_allowed_not_earlier_candidate(self):
        unit = fixture_unit(d_statuses=('refused', 'failed', 'generated'), d_failures=(3, 2, 1),
                            r_failures=(3, 2, 1))
        trace = run_dev_fixture(unit)
        self.assertEqual(trace.status, 'control_complete')
        self.assertEqual(len(trace.calls), 8)
        for state in trace.repair_states:
            self.assertEqual(state.stopped, 'maximum_repairs')
            self.assertEqual(state.selected.attempt, 3)
            self.assertIs(state.selected, state.attempts[-1])
            self.assertEqual(state.loop_failures, (32, 3, 2, 1))
            self.assertFalse(state.verification_disclosed)
        self.assert_control_only(trace)

    def test_r_repeat_stops_before_later_script_or_count(self):
        label = 'BUILDER NONCODE REPEATED R FIXTURE LABEL'
        unit = fixture_unit(r_texts=(label, label), r_failures=(4, 0))
        trace = run_dev_fixture(unit)
        self.assertEqual(trace.status, 'control_complete')
        d, r = trace.repair_states
        self.assertEqual(d.stopped, 'loop_pass')
        self.assertEqual(r.stopped, 'repeated_candidate')
        self.assertEqual(r.selected.attempt, 2)
        self.assertEqual(r.loop_failures, (32, 4))
        self.assertEqual(r.selected.candidate_sha256, r.attempts[0].candidate_sha256)
        self.assert_control_only(trace)

    def test_run_preserves_all_input_scripts_packets_slots_and_controls(self):
        unit = fixture_unit()
        before = (canonical_json(unit.mock), canonical_json(unit.initial_b), canonical_json(unit.initial_c),
                  unit.calls, unit.controls, unit.loop_hashes)
        trace = run_dev_fixture(unit)
        self.assertEqual(before, (canonical_json(unit.mock), canonical_json(unit.initial_b),
            canonical_json(unit.initial_c), unit.calls, unit.controls, unit.loop_hashes))
        self.assertEqual(unit.mock.position, 0)
        self.assertEqual(trace.next_mock.position, 4)
        self.assertEqual(trace.next_mock.entries, unit.mock.entries)
        self.assertIsNot(trace.next_mock, unit.mock)

    def test_fixture_wrapper_and_arm_preparation_leave_actual_authority_unset(self):
        unit = fixture_unit(c_pass=True)
        wrapper = build_fixture_initial_prompt(unit.initial_b, task=unit.task, loop_hashes=unit.loop_hashes)
        self.assertIs(wrapper.admitted, False)
        self.assertIs(wrapper.transport_authorized, False)
        self.assertEqual(wrapper.evidence_mode, 'fixture')
        self.assertEqual(wrapper.processing_mode, 'dev_fixture_control')
        self.assertEqual(wrapper.count_provenance, 'caller_scripted_control_not_measurement')
        prepared = prepare_arm(unit.calls[0], unit.initial_b, task=unit.task,
                               loop_hashes=unit.loop_hashes, fixture_control=True)
        self.assertEqual(prepared.status, 'prepared')
        self.assertIsNone(prepared.payload)
        self.assertEqual(prepared.request.messages, wrapper.messages)
        for field in ('model_id', 'run_plan_sha256', 'prices_sha256', 'input_tokens', 'token_count_receipt'):
            self.assertIsNone(getattr(prepared.request, field))
        self.assertEqual(prepared.control_payload_sha256, prepared.request.request_sha256())

    def test_missing_first_script_blocks_without_consuming_cursor(self):
        unit = replace(fixture_unit(), mock=ScriptedMock(entries=()))
        trace = run_dev_fixture(unit)
        self.assertEqual(trace.status, 'blocked')
        self.assertEqual(trace.issues, ('caller_script_missing',))
        self.assertEqual(trace.calls, ())
        self.assertEqual(trace.next_mock.position, 0)
        self.assert_control_only(trace)

    def test_request_hash_mismatch_blocks_without_consumption(self):
        unit = fixture_unit()
        entry = type(unit.mock.entries[0])(**{**unit.mock.entries[0].model_dump(), 'request_sha256': '0' * 64})
        unit = replace(unit, mock=ScriptedMock(entries=(entry,) + unit.mock.entries[1:]))
        trace = run_dev_fixture(unit)
        self.assertEqual(trace.status, 'blocked')
        self.assertEqual(trace.issues, ('script_missing_mismatched_or_malformed',))
        self.assertEqual(trace.next_mock.position, 0)

    def test_script_call_identity_mismatch_blocks(self):
        unit = fixture_unit()
        entry = type(unit.mock.entries[0])(**{**unit.mock.entries[0].model_dump(), 'call_id': IDS['R', 3]})
        trace = run_dev_fixture(replace(unit, mock=ScriptedMock(entries=(entry,) + unit.mock.entries[1:])))
        self.assertEqual(trace.issues, ('script_missing_mismatched_or_malformed',))
        self.assertEqual(trace.calls, ())

    def test_script_format_mismatch_blocks_before_response(self):
        unit = fixture_unit()
        entry = type(unit.mock.entries[0])(**{**unit.mock.entries[0].model_dump(), 'format': 'anthropic_messages'})
        trace = run_dev_fixture(replace(unit, mock=ScriptedMock(entries=(entry,) + unit.mock.entries[1:])))
        self.assertEqual(trace.issues, ('script_wire_format_mismatch',))
        self.assertEqual(trace.next_mock.position, 0)

    def test_malformed_script_response_does_not_consume(self):
        unit = fixture_unit()
        entry = type(unit.mock.entries[0])(**{**unit.mock.entries[0].model_dump(), 'raw_response_json': b'{broken'})
        trace = run_dev_fixture(replace(unit, mock=ScriptedMock(entries=(entry,) + unit.mock.entries[1:])))
        self.assertEqual(trace.issues, ('script_missing_mismatched_or_malformed',))
        self.assertEqual(trace.next_mock.position, 0)

    def test_missing_repair_script_preserves_completed_b_c_prefix(self):
        unit = fixture_unit()
        trace = run_dev_fixture(replace(unit, mock=ScriptedMock(entries=unit.mock.entries[:2])))
        self.assertEqual(trace.status, 'partial')
        self.assertEqual(trace.issues, ('caller_script_missing',))
        self.assertEqual([(x.arm, x.attempt) for x in trace.calls], [('B', 0), ('C', 0)])
        self.assertEqual(trace.next_mock.position, 2)
        self.assert_control_only(trace)

    def test_missing_shared_c_control_halts_after_exact_c_fork(self):
        unit = fixture_unit()
        trace = run_dev_fixture(replace(unit, controls=tuple(x for x in unit.controls if x.arm != 'C')))
        self.assertEqual(trace.status, 'partial')
        self.assertEqual(trace.issues, ('shared_C_scripted_control_missing_or_mismatched',))
        self.assertEqual(len(trace.calls), 2)
        self.assertIs(trace.repair_states[0].shared_c, trace.repair_states[1].shared_c)

    def test_shared_c_hash_mismatch_halts_before_repair(self):
        unit = fixture_unit()
        controls = tuple(replace(x, candidate_sha256='0' * 64) if x.arm == 'C' else x for x in unit.controls)
        trace = run_dev_fixture(replace(unit, controls=controls))
        self.assertEqual(trace.issues, ('shared_C_scripted_control_missing_or_mismatched',))
        self.assertEqual(len(trace.calls), 2)

    def test_missing_loop_count_halts_without_fabricated_measurement(self):
        unit = fixture_unit()
        controls = tuple(replace(x, failures=None) if x.arm == 'C' else x for x in unit.controls)
        trace = run_dev_fixture(replace(unit, controls=controls))
        self.assertEqual(trace.issues, ('scripted_loop_control_unavailable_not_measurement',))
        self.assertEqual(trace.repair_states[0].stopped, 'measurement_unavailable')
        self.assert_control_only(trace)

    def test_refused_c_cannot_be_declared_passing(self):
        unit = fixture_unit()
        controls = tuple(replace(x, failures=0) if x.arm == 'C' else x for x in unit.controls)
        trace = run_dev_fixture(replace(unit, controls=controls))
        self.assertEqual(trace.issues, ('invalid_shared_C_control:ScheduleError',))
        self.assertEqual(len(trace.calls), 2)

    def test_missing_typed_d_feedback_refuses_without_new_attempt(self):
        unit = fixture_unit()
        controls = tuple(replace(x, counterexample=None) if x.arm == 'C' else x for x in unit.controls)
        trace = run_dev_fixture(replace(unit, controls=controls))
        self.assertEqual(trace.issues, ('caller_typed_repair_feedback_missing',))
        self.assertEqual(len(trace.calls), 2)

    def test_r_count_drift_refuses_after_d_prefix(self):
        unit = fixture_unit()
        controls = []
        for x in unit.controls:
            if x.arm == 'C':
                packet = type(x.count_only)(**{**x.count_only.model_dump(), 'failed_cases': 31})
                x = replace(x, count_only=packet)
            controls.append(x)
        trace = run_dev_fixture(replace(unit, controls=tuple(controls)))
        self.assertEqual(trace.issues, ('R_scripted_count_projection_mismatch',))
        self.assertEqual([(x.arm, x.attempt) for x in trace.calls], [('B', 0), ('C', 0), ('D', 1)])

    def test_missing_post_repair_control_stops_selection(self):
        unit = fixture_unit()
        trace = run_dev_fixture(replace(unit, controls=tuple(x for x in unit.controls if x.arm != 'D')))
        self.assertEqual(trace.issues, ('scripted_loop_control_unavailable_not_measurement',))
        self.assertEqual(trace.repair_states[0].stopped, 'measurement_unavailable')

    def test_post_repair_hash_mismatch_is_not_ignored(self):
        unit = fixture_unit()
        controls = tuple(replace(x, candidate_sha256='0' * 64) if x.arm == 'D' else x for x in unit.controls)
        trace = run_dev_fixture(replace(unit, controls=controls))
        self.assertEqual(trace.issues, ('scripted_control_candidate_mismatch',))
        self.assertEqual(trace.repair_states[0].selected.attempt, 1)

    def test_context_allowlist_blocks_first_call(self):
        unit = fixture_unit()
        first = unit.calls[0]
        policy = type(first.policy)(**{**first.policy.model_dump(), 'allowed_context_hashes': frozenset({'0' * 64})})
        trace = run_dev_fixture(replace(unit, calls=(replace(first, policy=policy),) + unit.calls[1:]))
        self.assertEqual(trace.status, 'blocked')
        self.assertIn('context_not_in_authorized_allowlist', trace.issues)
        self.assertEqual(trace.calls, ())


if __name__ == '__main__':
    unittest.main()
