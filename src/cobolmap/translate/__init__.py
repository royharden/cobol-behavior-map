"""Deterministic IR-to-Python text facade. Generated code is never executed here."""
from dataclasses import dataclass
from pprint import pformat

from cobolmap.shared.decimal_shim import ShimError
from .errors import TranslationRefusal


@dataclass(frozen=True)
class TranslationResult:
    code: str
    original_source_sha256: str
    diagnostics: tuple[str, ...]


def translate(program, change=None):
    """Consume DL1 ProgramIR and optional strict native structured-edit mapping.

    Source/IR bindings and supported shapes are checked before emitting text.
    Compiler parity, changed-source witness, admission and execution are pending.
    Raw edit artifact hashing remains the caller's task/provenance responsibility.
    """
    try:
        # Fixed compiler imports are lazy: importing generated runtime must not
        # require parser/contracts or make them part of the candidate SDK closure.
        from .edits import apply_change
        from .normalize import normalize
        plan = normalize(program)
        if change is not None:
            apply_change(plan, change)
        code = (
            '"""Generated private construction candidate; runtime/compiler parity unverified."""\n'
            "from cobolmap.translate.runtime import run_plan\n\n"
            "PLAN = " + pformat(plan, width=100, sort_dicts=True) + "\n\n"
            "def run_case(input_present, records):\n"
            "    return run_plan(PLAN, input_present, records)\n"
        )
        return TranslationResult(code, plan["source_sha256"], (
            "runtime_unverified", "decimal_file_initialization_and_display_hypotheses_require_compiler_probes",
            "source_construction_before_P2_disclosed", "no_changed_source_witness_or_equivalence_claim"))
    except ShimError as error:
        raise TranslationRefusal(error.code, error.message) from error
    except (KeyError, TypeError, AttributeError, RecursionError, OverflowError) as error:
        raise TranslationRefusal("ir_type", "malformed parser IR or native change mapping") from error
