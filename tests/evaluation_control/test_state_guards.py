"""Native slot/phase/arm guards over disclosed caller control data."""
from dataclasses import replace
import unittest

from evaluation.run import run_dev_fixture
from evaluation.schedule import (ScheduleError, append_repair, disclose_verification,
                                  fork_shared_c, record_loop)
from fixture_data import candidate, fixture_unit


class UnitIdentityGuards(unittest.TestCase):
    def test_duplicate_call_ids_refuse_before_any_script_consumption(self):
        unit = fixture_unit()
        second = replace(unit.calls[1], slot=replace(unit.calls[1].slot, call_id=unit.calls[0].slot.call_id))
        with self.assertRaisesRegex(ValueError, 'slot_task_arm_sample_or_identity_drift'):
            run_dev_fixture(replace(unit, calls=(unit.calls[0], second) + unit.calls[2:]))
        self.assertEqual(unit.mock.position, 0)

    def test_wrong_shared_c_id_refuses(self):
        unit = fixture_unit()
        third = replace(unit.calls[2], slot=replace(unit.calls[2].slot, shared_c_call_id=unit.calls[0].slot.call_id))
        with self.assertRaisesRegex(ValueError, 'native_shared_C_identity_drift'):
            run_dev_fixture(replace(unit, calls=unit.calls[:2] + (third,) + unit.calls[3:]))

    def test_duplicate_loop_control_refuses(self):
        unit = fixture_unit()
        with self.assertRaisesRegex(ValueError, 'duplicate_or_invalid_control'):
            run_dev_fixture(replace(unit, controls=unit.controls + (unit.controls[0],)))

    def test_cross_arm_feedback_cannot_occupy_d_control(self):
        unit = fixture_unit()
        r_packet = next(x.count_only for x in unit.controls if x.arm == 'C')
        controls = tuple(replace(x, count_only=r_packet) if x.arm == 'D' else x for x in unit.controls)
        with self.assertRaisesRegex(ValueError, 'control_cross_arm_feedback_forbidden'):
            run_dev_fixture(replace(unit, controls=controls))

    def test_incomplete_original32_declaration_refuses(self):
        unit = fixture_unit()
        with self.assertRaisesRegex(ValueError, 'immutable_native_slots_original32_controls_required'):
            run_dev_fixture(replace(unit, loop_hashes=frozenset(tuple(unit.loop_hashes)[:31])))

    def test_other_task_slot_refuses(self):
        unit = fixture_unit()
        first = replace(unit.calls[0], slot=replace(unit.calls[0].slot, task_id='another_builder_task'))
        with self.assertRaisesRegex(ValueError, 'slot_task_arm_sample_or_identity_drift'):
            run_dev_fixture(replace(unit, calls=(first,) + unit.calls[1:]))


class NativeSelectionPhases(unittest.TestCase):
    def test_append_before_loop_refuses_and_initial_state_is_immutable(self):
        shared = candidate('C', 0)
        state = fork_shared_c(shared)[0]
        with self.assertRaises(ScheduleError):
            append_repair(state, candidate('D', 1))
        self.assertEqual(state.attempts, ())
        self.assertEqual(state.loop_failures, ())
        self.assertIs(state.selected, shared)

    def test_repeated_loop_phase_refuses(self):
        state = record_loop(fork_shared_c(candidate('C', 0))[0], 2)
        with self.assertRaises(ScheduleError):
            record_loop(state, 1)
        self.assertEqual(state.loop_failures, (2,))

    def test_cross_arm_repair_refuses_without_altering_selected_c(self):
        state = record_loop(fork_shared_c(candidate('C', 0))[0], 2)
        with self.assertRaises(ScheduleError):
            append_repair(state, candidate('R', 1))
        self.assertEqual(state.attempts, ())
        self.assertIs(state.selected, state.shared_c)

    def test_repeated_generated_label_is_selected_and_closes_repairs(self):
        label = 'BUILDER NONCODE REPEATED NATIVE STATE LABEL'
        shared = candidate('C', 0, text=label)
        state = record_loop(fork_shared_c(shared)[0], 1)
        next_state = append_repair(state, candidate('D', 1, text=label))
        self.assertEqual(next_state.stopped, 'repeated_candidate')
        self.assertEqual(next_state.selected.attempt, 1)
        self.assertEqual(state.attempts, ())
        with self.assertRaises(ScheduleError):
            append_repair(next_state, candidate('D', 2))

    def test_verification_cannot_precede_loop_selection(self):
        state = fork_shared_c(candidate('C', 0))[0]
        with self.assertRaises(ScheduleError):
            disclose_verification(state)
        self.assertFalse(state.verification_disclosed)

    def test_disclosure_phase_closes_selection_and_cannot_repeat(self):
        selected = record_loop(fork_shared_c(candidate('C', 0))[0], 0)
        disclosed = disclose_verification(selected)
        self.assertTrue(disclosed.verification_disclosed)
        self.assertFalse(selected.verification_disclosed)
        self.assertIs(disclosed.selected, selected.selected)
        with self.assertRaises(ScheduleError):
            disclose_verification(disclosed)
        with self.assertRaises(ScheduleError):
            record_loop(disclosed, 0)
        with self.assertRaises(ScheduleError):
            append_repair(disclosed, candidate('D', 1))


if __name__ == '__main__':
    unittest.main()
