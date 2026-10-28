# COBOL behavior map — private source construction

Source for a bounded compiler-relative COBOL modernization study. **Everything is
runtime-unverified.** Private original product source before P2 is authorized by
the current delegated overlay; admission, runtime/evaluation and publication are
not authorized by that source grant. Construction exposure is disclosed in
`docs/STUDY-EXPOSURE.md`. No license is adopted or implied.

The declared `cbm` entry point is `cobolmap.cli:main`. This package adds source for:

- `map SOURCE [--manifest FILE]`: strict parser/map facade, exact source-byte and
  pointer checks, static hazard warnings. No compiler semantics/equivalence claim.
- `translate SOURCE [--manifest FILE] [--change FILE]`: parser/translation facade;
  native structured-edit JSON is passed to the translator. Generated Python is
  rendered as text and never imported or run. The raw edit artifact hash remains
  separate from decoded/canonical metadata and changed-source identity.
- `report --mode replay --bundle FILE` and `demo --mode replay --bundle FILE`:
  dev-only, raw-hash-bound supplied-record replay, strict shared models, pointer
  resolution and escaped static JSON/HTML output. No bundle is included.

These are implemented source interfaces, **not commands executed during Dirty
Mode**. Parser/mapping, translation/shims and evidence/diff/claims are separate
owned source lanes; INT integrates their facades. Packaging is source-only;
dependencies, installation, imports, CLI behavior and combined runtime remain
unverified. Do not run/import/test/install this source under the current mode.

Without a replay bundle, report/demo returns `unavailable` with current model
metrics null/`not_run` and non-success status3. It creates no fixture/compiler
observation or model improvement. `--mode oracle` or `--mode live` always returns
`mode_blocked` before evidence reads: no execution backend, credentials/env reads
or network path exists in this CLI. Files or flags cannot authorize a run.

Reports expose exact source evidence mode (`not_run|static|fixture|actual`) and
separate replay processing. Supplied actual declarations are unauthenticated;
fixture records never become authentic oracle evidence. Hashes/pointers establish
byte identity only. Failures, unknown coverage, unverified custody, recorded cost
claims and absent current live metrics remain visible. HTML escapes all content;
source/candidate text stays inert. Outputs use exclusive creation and never
overwrite an existing artifact. See `docs/cli-replay.md` for schema/API/refusals.

Preparation source remains in `admission/`: subset/hazard/family/provenance/shim
contracts and unstaffed briefs; deterministic generation/continuation and pure
transport descriptors; receipt/case consistency source and a preparation runner
that refuses execution; P2 gate/index/authority schemas and custody notes. None
of those functions, the product facades or the CLI has run in this construction
phase. No actual corpus, expected answers, receipt bundle, licensed dataset,
held-out evaluation, replay demo recording or observed model result was produced.

P2 remains pending on R02 independent different-harness custody/nonauthor verifier/
seal confirmation, R03 licenses and genuine isolated compiler/probe/repeated
ordinary/trace/independent admission evidence. Source construction does not waive
that gate. The OUTER shell owns the frozen plan, delegated answers, decisions,
run state and `DEFERRED-VALIDATION.md`; only Roy closes Dirty Mode. Spend authorized
USD0; no keys/accounts, S3 vendoring, GnuCOBOL notice reliance, installs/runtime/
Docker/model calls, new repos/remotes, push/publish/deploy or independent appointments.
