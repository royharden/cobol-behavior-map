"""ARTIFICIAL DEV math declarations, never observed or accepted study data.

The evidence_mode='actual' enum is explicitly UNTRUSTED unit input permitting
positive mathematical branches. Dummy 128 integers do not describe case bytes,
a partition, observations, receipts, execution or independently collected truth.
All metadata is invented here and stays in memory; no real schedule is built.
"""
from dataclasses import replace

from evaluation.stats import OutcomeRow, TaskSlot, summarize


PREFIX = 'synthetic_math_not_observed'
FAMILIES = tuple(f'{PREFIX}_family_{i}' for i in range(6))


def synthetic_math_not_observed_frame(*, panel='unchanged', model_slot='primary'):
    """Separate declared 24-slot DEV denominator, not inferred from rows."""
    return tuple(TaskSlot(f'{PREFIX}_task_{family}_{program}',
        f'{PREFIX}_program_{family}_{program}', FAMILIES[family],
        'dev', panel, model_slot) for family in range(6) for program in range(4))


def synthetic_math_not_observed_row(slot, arm='D', *, passed=True, evidence_mode='actual', outcome=None):
    """Untrusted enum/count metadata ONLY; no native observation is constructed."""
    return OutcomeRow(slot.task_id, slot.program_id, slot.family_id, slot.split,
        slot.panel, slot.model_slot, arm, outcome or ('pass' if passed else 'fail'),
        evidence_mode, 128, 128 if passed else 0)


def synthetic_math_not_observed_mixed(frame):
    """Known arithmetic: A=0, B/D/R=1, C=1 in first three families, else 0."""
    return tuple(synthetic_math_not_observed_row(slot, arm,
        passed=(arm != 'A' and (arm != 'C' or slot.family_id in FAMILIES[:3])))
        for slot in frame for arm in ('A', 'B', 'C', 'D', 'R'))


def synthetic_math_not_observed_summary(rows, frame, **selectors):
    return summarize(rows, frame, split=selectors.get('split', 'dev'),
        panel=selectors.get('panel', 'unchanged'), model_slot=selectors.get('model_slot', 'primary'))


def synthetic_math_not_observed_pair(frame):
    """Only C/D rows: incomplete fixtures never bootstrap another contrast."""
    return tuple(synthetic_math_not_observed_row(slot, arm, passed=arm == 'D')
                 for slot in frame for arm in ('C', 'D'))


def arm(summary, name):
    return next(item for item in summary.arms if item.arm == name)


def contrast(summary, name):
    return next(item for item in summary.contrasts if item.contrast == name)
