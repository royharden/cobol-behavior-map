"""Closed B0 claim evaluation and bounded future admitted dev-oracle search.

Runtime-unverified construction source. No compiler/provider execution lives here.
"""
from cobolmap.contracts import (
    Claim, FieldComparison, FieldRef, FieldValue, LinearTerm, LinearValue,
    LiteralValue, OutputEquality,
)
from .evaluator import evaluate_claim
from .models import (
    CaseCandidate, ClaimCounterexample, ClaimEvaluation, ClaimResult, FieldBinding,
    FieldWitness, Minimizer, Oracle, OracleWitness,
)
from .search import MAX_ORACLE_CASES, MAX_PROPOSALS, search_claim

__all__ = [
    "Claim", "FieldComparison", "FieldRef", "FieldValue", "LinearTerm", "LinearValue",
    "LiteralValue", "OutputEquality", "CaseCandidate", "ClaimCounterexample",
    "ClaimEvaluation", "ClaimResult", "FieldBinding", "FieldWitness", "Minimizer",
    "Oracle", "OracleWitness", "MAX_ORACLE_CASES", "MAX_PROPOSALS",
    "evaluate_claim", "search_claim",
]
