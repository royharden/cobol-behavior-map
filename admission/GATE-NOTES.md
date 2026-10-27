# P2 admission gate, version m10-p2-v1

Construction only. **Current P2: PENDING; P3–P15 blocked.** No licenses,
custodian/verifier appointment, private seal or execution receipts have been
provided. This package contains no GO record, hidden data or fabricated receipt.
Original source remains private pending Roy's R03 license decision; no license
recommendation in the plan has been adopted by these files.

Authority: promoted PLAN-M10-v1.md sections 4–5 and P1/P2 in section 10,
plan-body SHA256 552ddcb9121deb21489a903eaf77979b8068231a94a0fb714b948094c8d4dbed.
M10-DL4 owns this checker and its schemas. It does not own the generator, runner
or field/recipe vocabulary. INT owns subsequent interface reconciliation after
construction acceptance; those inputs must be frozen and pinned before use.

## Intended interface (future authorized execution only)

`evaluate(root: Path, record_path: str, authority_path: str,
authority_sha256: str) -> dict` in `gate.py` reads evidence and returns
`gate_version`, `status`, `issues`, and the structural-claim limitation.
There is no CLI or import-time execution. It neither compiles nor runs programs,
executes receipt commands, signs records, writes evidence nor fetches URLs.

Use a custodian-controlled evidence root in a later authorized environment.
Only relative forward-slash paths beneath that root are accepted; absolute,
drive, traversal and resolved symlink/junction escapes reject. File hashes bind
the actual read bytes. Do not give builders access to this root. The checker
reads committed case hashes and provenance, so builders must not use it as a
held-out rehearsal tool. Public product exports must exclude private records.

The caller must independently authenticate Roy's approved authority file and
supply its digest out of band. A digest computed from an unapproved file does
not appoint anyone. Authority names four separate sessions, full builder
author-session/lineage disclosure, appointments and frozen briefs, actual signed
license choices, deterministic three-dev selection, and Roy's manifest/date
confirmation. `author_sessions` means builder/product/preparation authors; the
custodian is separately the author of the hidden split. Include every parent,
child and fork session of each actor in `lineage_sessions`, not just its direct
parent. Registry labels and signer identity require external authentication.
Harness names use the closed canonical vocabulary Codex, Claude, Cursor, Grok,
Antigravity, Human; case variants and unknown aliases reject. Both independent
roles' complete lineage sets must avoid every disclosed builder-author session;
verifier and custodian lineages must also be disjoint. Frozen briefs equal the
approved actor-brief references exactly with no duplicate entries; artifact
briefs equal their appointed author's approved brief.

## Closed records

Bundled JSON schemas are the record contract; all fields are required and all
object keys closed. Duplicate keys, nonfinite values and booleans as integers
reject. The standard-library shape validator implements the small subset of
JSON Schema used here. No external schema engine/dependency is needed. Schema
and checker source must be pinned together in the eventual launch authority;
the version string alone is not a source-authentication mechanism.

- `authority.schema.json`: externally approved plan/appointments/licenses/seal.
- `go-record.schema.json`: pins, compiler, family/task inventory, provenance,
  seal and the twelve required section-5 signed checklist items.
- `receipt.schema.json`: actual observations or Roy approvals, signatory,
  check identity, execution counts, manifest/generator/compiler configuration
  bindings and artifact references. `fixture`/`static` cannot qualify.
- `task-oracle.schema.json`: two distinct executions of all 160 ordinary cases
  per task, source/case/tool/image pins, exact partitions and observation/log
  references. Ordinary observation bytes agree across the two runs.
- `task-trace.schema.json`: same task/source and exact oracle receipt, all 160
  cases, and traced ordinary observations matching untraced observations.

Original artifacts include programs, probes, candidates, requests, changed
originals and generated inputs. `original_artifacts` must enumerate every such
file beyond the task inventory; every one requires an `artifacts` provenance
sidecar entry. Each task source/fields/recipe/case-manifest reference also needs
an entry joined by exact path/hash, task split/family and designated split
author. Extra original-artifact references also have their digests checked
against actual bytes and their matching provenance entries. A provenance entry
binds author/callsign/harness/session/time, original
source attestation, family/split, brief/generator hashes, exact approved license
and signed license evidence. No third-party source ingestion is allowed by the
adopted plan. Tool notices/review are a separate required receipt.

## Required checks and signers

| Required item | Signer |
|---|---|
| compiler_config_notices | builder |
| originality_licenses_dev | builder |
| dev_preparation | builder |
| heldout_originals_recipes_changes | custodian |
| case_counts_partitions_quarantine | custodian |
| token_template_separation | custodian |
| independence_private_seal | custodian |
| independent_compiler_probe_rerun | verifier |
| three_selected_dev_reruns | verifier |
| recipe_reachability_custody | verifier |
| licenses_staffing | Roy |
| manifest_seal_confirmation | Roy |

Custodian must use a different harness from the builder and a separate session.
Verifier must be a separate nonauthor outside builder and custodian lineage.
The team's static reviewer is an implementation-lineage reviewer, never that
verifier or custodian. Roy appoints those roles; this package does not.

Inventory checks require six families per split, two per domain, four dev or
three held-out programs/family: 24 dev and 18 held-out originals, each with one
changed task (84 tasks total). Every task requires exactly 32 distinct loop and
128 distinct verification full-case hashes, disjoint within the task, two
reachable H1–H8 hazards, repeated actual oracle receipts and trace equality.
No reductions, authored expected outputs, missing-count defaults or candidate-
outcome-driven replacements are admitted. Receipt review must check presence,
record order, 1–64 bounds, replacement counters and quarantine reasons against
the frozen generator contract; a case hash alone cannot prove them.

Compiler contract is GnuCOBOL 3.2.0 with exact `cobc -x -free -std=default -O0
-o <bin> <source>`; trace adds `-ftraceall`, TZ UTC, LC_ALL C, cleared ambient
COB overrides. Package, image, build/version/info, libcob, default.conf, full
runtime configuration and argv have separate required pins. The verifier's
receipt needs at least six admission and 24 shim probes plus a separate receipt
for the three externally selected dev programs. Probe inventory/semantics,
recipe reachability and compiler-only expected answers need genuine independent
inspection, not just positive counts.

## Verdict and authenticity limits

Missing files/fields or explicitly pending checklist items yield PENDING.
Malformed/contradictory/failed evidence yields NO-GO, which dominates PENDING.
The report collects per-item failures once its closed top-level records parse;
a malformed top-level record cannot be expanded into trusted partial content.
No missing value defaults to a passing result.

GO means only that the submitted record passed these structural checks. It
does not authenticate authorship/signatures, prove secrecy, establish that an
execution narrative is true, establish corpus completeness or semantic
independence, or grant product/live/release authorization. Signed receipts and
observation hashes remain claims requiring the appointed verifier and Roy.
Self-authored fixtures are not independent validation, even with plausible
counts/hashes. A forged nonempty signature file cannot be cryptographically
detected by this checker. Do not represent this as full adoption/parity of the
portable evidence-gate skill's separate normalized evaluator.

Deferred after Dirty Mode closure and explicit permission: execute negative and
positive structural cases (including malformed schemas, fabricated/reused
receipts, wrong actors/pins/counts/seals), test filesystem containment, connect
real generator/runner receipt formats, exercise pinned compiler/probe and
custodian/verifier workflows. No checker function or runtime tests ran during
this construction package. P2 remains pending regardless of static review.
