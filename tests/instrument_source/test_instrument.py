"""Synthetic builder regressions: no execution evidence or admission is supplied.

Hashes name test metadata only. No corpus, case bundle, observation, receipt,
seal, authority implementation, or passing baseline is manufactured here.
"""
from dataclasses import replace
from hashlib import sha256
import unittest

from cobolmap.contracts import ArtifactRef, ExecutionPins, TaskBinding
from evaluation.instrument import (
    CATALOGUE, INSTRUMENT_EDITION, FrozenVerification, InstrumentPolicy,
    MutantAssessment, evaluate_instrument,
)


TARGET_CLASSES = frozenset({
    'padding', 'sign', 'scale', 'last_place/truncation',
    'last_place/rounding', 'size_error', 'value', 'alpha', 'record_count',
})


def builder_hash(label):
    return sha256(('synthetic-builder-only:' + label).encode('ascii')).hexdigest()


def builder_ref(label):
    return ArtifactRef(path='synthetic-builder/' + label + '.txt',
                       sha256=builder_hash(label))


def builder_tasks():
    """Six invented DEV families, four programs each, both panel declarations."""
    tasks = []
    for family in range(6):
        for program in range(4):
            name = f'dev_f{family}_p{program}'
            original = builder_ref(name + '-original')
            for panel in ('unchanged', 'change'):
                tasks.append(TaskBinding(
                    task_id=name + '-' + panel, program_id=name,
                    family_id=f'dev_family_{family}', split='dev', panel=panel,
                    original=original,
                    oracle_source=(original if panel == 'unchanged'
                                   else builder_ref(name + '-changed-source')),
                    change=(None if panel == 'unchanged'
                            else builder_ref(name + '-raw-edit')),
                ))
    return tuple(tasks)


def builder_policy():
    pins = ExecutionPins(
        compiler_version='synthetic-builder-no-compiler',
        **{name: builder_hash('pin-' + name)
           for name in ExecutionPins.model_fields if name != 'compiler_version'},
    )
    return InstrumentPolicy(
        edition=INSTRUMENT_EDITION,
        instrument_source_sha256=builder_hash('instrument-source'),
        catalogue_source_sha256=builder_hash('catalogue-source'),
        generator_sha256=builder_hash('translator-source'),
        runtime_sha256=builder_hash('runtime-source'),
        plan_reader_sha256=builder_hash('plan-reader-source'),
        preparation_generator_sha256=pins.generator_sha256,
        dev_tasks=builder_tasks(), oracle_pins=pins, candidate_pins=pins,
    )


def edited_task(task, **updates):
    """Revalidate metadata; do not use unchecked native model copies."""
    values = {name: getattr(task, name) for name in TaskBinding.model_fields}
    return TaskBinding(**(values | updates))


class InstrumentBuilderTests(unittest.TestCase):
    def setUp(self):
        self.policy = builder_policy()

    def pending_report(self, policy=None, assessments=()):
        report = evaluate_instrument(policy or self.policy, (), (), assessments)
        self.assertEqual(report.status, 'pending')
        self.assertFalse(report.product_go)
        self.assertFalse(report.dispatch_allowed)
        self.assertEqual(report.scheduled, 20)
        self.assertEqual(report.killed, 0)
        self.assertEqual(report.survived, 0)
        self.assertEqual(report.invalid, 0)
        self.assertEqual(report.equivalent_with_written_proof, 0)
        self.assertEqual(set(report.missing_classes), TARGET_CLASSES)
        return report

    def test_no_evidence_requires_authority_and_all_48_task_obligations(self):
        report = self.pending_report()
        self.assertEqual(report.pending, 20)
        self.assertIn('missing_authorization', report.issues)
        self.assertIn('missing_independent_review', report.issues)
        self.assertIn('external_nonauthor_authority_missing', report.issues)
        for task in self.policy.dev_tasks:
            self.assertIn('missing_frozen_partition:' + task.task_id, report.issues)
            self.assertIn('missing_passing_A:' + task.task_id, report.issues)

    def test_catalogue_is_exactly_twenty_with_nine_required_classes(self):
        self.assertEqual(tuple(o.operator_id for o in CATALOGUE),
                         tuple(f'M{i:02}' for i in range(1, 21)))
        self.assertEqual({o.intended_class for o in CATALOGUE}, TARGET_CLASSES)
        report = self.pending_report()
        self.assertEqual(sum(i.startswith('missing_operator:') for i in report.issues), 20)
        self.assertEqual(sum(i.startswith('missing_target_class:') for i in report.issues), 9)

    def test_pending_labels_cannot_shrink_denominator_or_cover_classes(self):
        for status in ('pending', 'not_executed'):
            for count in (1, 19, 20):
                with self.subTest(status=status, count=count):
                    assessments = tuple(MutantAssessment(o.operator_id, status=status)
                                        for o in CATALOGUE[:count])
                    report = self.pending_report(assessments=assessments)
                    self.assertEqual(report.pending, 20)
                    self.assertEqual(sum(i.startswith('missing_operator:')
                                         for i in report.issues), 20 - count)
                    for assessment in assessments:
                        self.assertIn(assessment.operator_id + ':' + status, report.issues)

    def test_generation_zero_and_one_require_genuine_external_proofs(self):
        initial = self.pending_report()
        self.assertNotIn('missing_reseal', initial.issues)
        improved = self.pending_report(replace(self.policy, generation_round=1))
        for field in ('improvement_authorization', 'revalidation', 'reseal', 'renewed_go'):
            self.assertIn('missing_' + field, improved.issues)

    def test_second_improvement_and_noninteger_rounds_refuse(self):
        for generation in (2, -1, True, '1'):
            with self.subTest(generation=generation):
                with self.assertRaisesRegex(ValueError, 'only one DEV generator improvement'):
                    evaluate_instrument(replace(self.policy, generation_round=generation), (), (), ())

    def test_incomplete_duplicate_and_unbalanced_dev_frames_refuse(self):
        tasks = self.policy.dev_tasks
        vectors = (
            tasks[:-1],
            (tasks[0],) + tasks[:-1],
            (edited_task(tasks[0], family_id='dev_extra_family'),) + tasks[1:],
            (edited_task(tasks[0], program_id='dev_unpaired_program'),) + tasks[1:],
        )
        for index, frame in enumerate(vectors):
            with self.subTest(vector=index):
                with self.assertRaises(ValueError):
                    evaluate_instrument(replace(self.policy, dev_tasks=frame), (), (), ())

    def test_paired_original_source_drift_refuses_even_with_valid_panel_metadata(self):
        tasks = self.policy.dev_tasks
        changed = edited_task(tasks[1], original=builder_ref('dev-drifted-original'))
        with self.assertRaisesRegex(ValueError, 'paired original source drift'):
            evaluate_instrument(replace(self.policy, dev_tasks=(tasks[0], changed) + tasks[2:]), (), (), ())

    def test_changed_panel_cannot_claim_original_as_compiled_oracle_source(self):
        task = self.policy.dev_tasks[1]
        with self.assertRaisesRegex(ValueError, 'changed task requires separate source'):
            edited_task(task, oracle_source=task.original)
        with self.assertRaisesRegex(ValueError, 'changed task requires separate source'):
            edited_task(task, change=None)

    def test_reused_program_across_families_refuses(self):
        tasks = list(self.policy.dev_tasks)
        for index in (8, 9):
            tasks[index] = edited_task(tasks[index], program_id=tasks[0].program_id)
        with self.assertRaisesRegex(ValueError, 'program reused across families'):
            evaluate_instrument(replace(self.policy, dev_tasks=tuple(tasks)), (), (), ())

    def test_pin_role_drift_refuses_but_distinct_image_metadata_stays_pending(self):
        changed_image = ExecutionPins(**{
            name: (builder_hash('candidate-image') if name == 'image_sha256'
                   else getattr(self.policy.candidate_pins, name))
            for name in ExecutionPins.model_fields})
        self.pending_report(replace(self.policy, candidate_pins=changed_image))
        with self.assertRaisesRegex(ValueError, 'preparation generator execution pin drift'):
            evaluate_instrument(replace(self.policy,
                preparation_generator_sha256=self.policy.generator_sha256), (), (), ())
        changed_shim = ExecutionPins(**{
            name: (builder_hash('different-shim') if name == 'shim_sha256'
                   else getattr(changed_image, name))
            for name in ExecutionPins.model_fields})
        with self.assertRaisesRegex(ValueError, 'shared oracle/candidate execution pins drift'):
            evaluate_instrument(replace(self.policy, candidate_pins=changed_shim), (), (), ())

    def test_empty_partition_declaration_is_not_frozen128_evidence(self):
        task = self.policy.dev_tasks[0]
        declaration = FrozenVerification(task.task_id, task.program_id,
            task.oracle_source.sha256, builder_ref('dev-empty-partition-declaration'), ())
        with self.assertRaisesRegex(ValueError, 'exact actual 128-case frozen task partition required'):
            evaluate_instrument(self.policy, (), (declaration,), ())

    def test_duplicate_unknown_and_missing_status_labels_refuse(self):
        vectors = (
            (MutantAssessment('M01'), MutantAssessment('M01')),
            (MutantAssessment('M21'),),
            (MutantAssessment('M01', status=''),),
            (MutantAssessment('M01', status='claimed_kill'),),
            (MutantAssessment('M01', status=None),),
        )
        for index, assessments in enumerate(vectors):
            with self.subTest(vector=index):
                with self.assertRaises(ValueError):
                    evaluate_instrument(self.policy, (), (), assessments)

    def test_terminal_claims_without_mutation_or_actual_artifacts_refuse(self):
        for status in ('killed', 'survived', 'invalid', 'equivalent-with-written-proof'):
            with self.subTest(status=status):
                assessment = MutantAssessment('M01', status=status)
                with self.assertRaisesRegex(ValueError, 'exact closed instrument record required'):
                    evaluate_instrument(self.policy, (), (), (assessment,))

    def test_pending_cannot_discard_claimed_kill_metadata(self):
        assessment = MutantAssessment('M01', status='pending', observed_class='padding')
        with self.assertRaisesRegex(ValueError, 'kill evidence cannot be discarded'):
            evaluate_instrument(self.policy, (), (), (assessment,))

    def test_lists_cannot_replace_closed_immutable_record_tuples(self):
        for args in (([], (), ()), ((), [], ()), ((), (), [])):
            with self.subTest(vector=args):
                with self.assertRaisesRegex(ValueError, 'closed immutable record tuples required'):
                    evaluate_instrument(self.policy, *args)


if __name__ == '__main__':
    unittest.main()
