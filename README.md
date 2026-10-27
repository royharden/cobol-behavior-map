# COBOL behavior map — admission preparation

This local repository contains reviewed preparation source for a bounded compiler-relative COBOL modernization study. It is not an implemented translator or a completed experiment. All construction remains runtime-unverified.

Preparation source:
- `admission/specs/` and `admission/briefs/`: bounded language, generation/manifest/hash contracts, hazards, shim API and unstaffed role briefs.
- `admission/prepare/generate.py` and `generator_continuation.py`: deterministic declarative generation and unsealed continuation source.
- `admission/prepare/generator_adapter.py`: pure generator-to-runner descriptor/index adapter source.
- `admission/prepare/receipt_validation.py`, `receipt_values.py` and `compile_run.py`: receipt/case consistency source and a structural preparation runner that refuses execution.
- `admission/gate.py`, `admission/schemas/` and `admission/custody/`: fail-closed admission-record/index contracts and source checks. A future structural result does not authenticate evidence or authorize product work.

See `admission/generator-notes.md`, `admission/oracle-preparation.md` and `admission/GATE-NOTES.md` for actual APIs, limitations and missing capabilities. No generator, adapter, gate or runner function has been executed during this construction phase; no actual corpus, expected answers, execution receipts, licensed dataset or held-out evaluation has been produced. Source syntax/JSON parsing, scoped diffs and implementation-lineage static reviews are the recorded checks.

The private OUTER shell owns `../planning/promoted/PLAN-M10-v1.md`, its status companion, `../DEFERRED-VALIDATION.md`, `../ROY-DECISIONS-REQUEST.md` and `../agentops/START.md`. P2 admission remains pending on signed licenses, named independent custody/verifier roles, authentic compiler/isolation/probe/receipt work and Roy's seal confirmation. P3+ product implementation remains blocked by the adopted plan. Dirty Mode is still active until Roy closes it; no runtime activation is authorized here.

Local Git only. No remote, push, publication, model calls, keys or spend. Proposed artifact licenses remain unapproved; no license is implied by this repository.
