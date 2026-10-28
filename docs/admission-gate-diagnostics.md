# Bounded admission gate diagnostics

`tests/admission_gate/test_gate.py` exercises the native `admission/gate.py`
strict JSON/canonical commitment/schema/timestamp helpers and early fail-closed
`evaluate` paths. All gate calls lack actual authority/evidence and must remain
PENDING or NO-GO, with a specific issue assertion. Helper controls establish
schema behavior only. Synthetic role strings do not appoint independent staff;
fixture/static receipt schema membership does not admit actual observations.

Inputs and result/read inventories are created exclusively with `xb` in a fresh
UUID directory under the own worktree `.agent-work/admission-gate-diagnostics/`.
Directories/files remain retained. An IO guard refuses reads outside that
namespace and native read-only admission schemas. Escape probes use syntactically
rejected paths with inert marker names, never symlinks or external targets.

Coverage includes unknown/duplicate keys, exact integer types, bounded JSON integer
lexemes, BOM/nonfinite/encoding refusal, raw authority hash versus canonical JSON,
unsafe references, pending versus contradictory failures and NO-GO precedence;
native reference/recipe/role/receipt/probe/partition-count schema boundaries.
No real 32/128 partitions, corpus, compiler answers, observations, signatures,
approved license or full authority document are manufactured.

Deeper semantic joins (role lineage, spec/pin inventory, paired recipe/source
bindings, partition uniqueness/disjointness, probe thresholds, repeated actual
receipts, review/custody/signatures/seals) require a fully shaped record and are
not reached by these deliberately incomplete gate inputs. Their positive and
semantic negative runtime coverage remains pending, as do actual independent P2,
containment, authenticity and product acceptance. No portable normalized gate
adoption/parity is claimed.

After fresh Medium source review and exact pin preflight, the authorized command
is the designated CPython3.12.13/Pydantic2.12.5 interpreter with
`-B -m unittest discover -s tests/admission_gate -p test_gate.py -v`, own worktree
CWD/process-local `PYTHONPATH=src`, owned process timeout at most90 seconds.
This source-only document claims no runtime result; retained outer run receipts
record actual results. No candidate/guest/compiler/authority callback, provider,
network, ledger, SQLite, install, Docker, credential, spending or push operation.
Concrete defects go to INT without product patches or weakened expectations.
