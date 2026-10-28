# CLI, reports and supplied dev replay — source r1

Private original source, runtime-unverified. This document describes source
behavior only; no application import, command, test, bundle or report was run
or emitted in the current Dirty phase. P2, licenses, independent staff, actual
receipts and execution authority remain pending. Construction before admission
is disclosed in STUDY-EXPOSURE.md; this file grants no runtime activation.

## Facades and command boundary

Entry `cobolmap.cli:main(argv=None)->int`. map and translate read exact UTF8 source
bytes without universal-newline conversion, preserve source SHA256, and call
`cobolmap.parse.parse(source,filename=...,manifest=...)`. A native ProgramManifest
may be supplied for required loop/return proof metadata; parser refusal is
preserved, no guessed loop cap/default manifest is generated. Map calls
`cobolmap.mapping.build_map(program)` and resolves every returned SourcePointer
against the exact source. Static warnings remain unexecuted warnings.

Translate calls `cobolmap.translate.translate(program,change=decoded_native_mapping)`.
`TranslationRefusal` and `ParseRefusal` codes/messages/spans become JSON diagnostic
reports. Raw structured-edit SHA256 is separately retained; decoded/canonical JSON
is never its raw digest. TranslationResult original_source_sha256 must match the
source; code is a string rendered as data, never executed/imported/run_case-called.
No arbitrary patch/eval or candidate execution path is present in this CLI.

report/demo processing mode defaults replay. `--mode oracle|live` is permanently
blocked in this source package, before bundle/file reads; real authority/environment/
P2/model/keys/budget/backend must be implemented and approved later. No env/auth/key
read or network call exists. `--bundle` absence gives unavailable/not_run, never a
built-in fixture or synthetic passing run. Source examples/receipts are not authored.

Both source and replay commands accept format json|html and optional output path.
Default is stdout. An output file is created exclusively; existing file, linked/
remote/private path, absent parent or unwritable destination refuses. Errors emit
JSON on stderr, without a successful fallback artifact. No silent overwrite/truncation.
Exit0 means source output or supplied-record rendering completed, never acceptance;
2 means refusal/malformed data/interface error;3 means unavailable evidence/provider
or blocked mode. Argparse usage failures retain its standard status2.

## Replay manifest (owned envelope, schema_version integer1)

Exactly these top-level keys are required; unknown keys reject:

- bundle_id: lowercase shared identifier.
- captured_at: declared ISO8601 timestamp with timezone; not authenticated by replay.
- evidence_mode: exactly shared not_run|static|fixture|actual. Replay is processing,
  not an evidence alias. Source mode must equal the original RunResult mode.
- split: exactly dev. No held-out/independent set is loaded or authored by this CLI.
- artifacts: nonempty list of up to4096 entries.
- run_result_artifact: inventoried artifact_id of kind run_result.
- pointers: source-pointer inventory; may be empty only if no supplied model pointer
  needs resolution. The list is bounded to100000 entries.
- schema_version: integer1, never boolean.

Artifact entries are exactly artifact_id/path/sha256/kind/filename. IDs are lowercase
shared identifiers; hashes lowercase SHA256 of **actual raw bytes**. Kind is
source|candidate|run_result|observation|behavior_map|receipt|attachment. Source filename
is its relative logical source identity; every other kind requires filename null.
Paths are printable-ASCII relative forward-slash paths beneath the manifest's
artifact-only staging directory. Empty/dot/dot-dot/drive/UNC/control/backslash,
linked components/junctions, root escapes, aliases, duplicate IDs/paths and known
credential/private/held-out roots refuse. Windows trailing-dot/space components
and reserved device aliases refuse on all platforms; resolved sensitive components
are rechecked for reads and output. Never use a home, credentials directory,
private thinking lane or custody vault as a replay root. Metadata cannot prove that
bytes were never hidden; caller must stage genuine dev-only provenance.

All artifacts are streamed/hash-checked before use. Reopened structured/text
artifacts are rehashed to catch a changed file. Native ArtifactRef path/hash/optional
byte_length must match inventory. RunResult raw JSON is hashed before decode;
`RunResult.model_validate_json(raw)` preserves strict tuple/hex-byte semantics,
never strict=False or a lossy coercion through decoded Python lists. Duplicate keys,
BOM/nonfinite/malformed UTF8 JSON reject before shared-model parsing. Raw artifact
hashes, canonical model views and CaseBundle hashes remain separate.

RunResult observations is a tuple of ArtifactRef, not inline observations. Each
must reference an inventoried observation JSON artifact parsed strictly through
ExecutionObservation.model_validate_json. Source/candidate hashes bind real source/
candidate inventory bytes. Each observation's evidence.mode equals the result mode;
not_run/static cannot carry a completed payload/outcome. Actual declarations require
all EvidenceBinding actual metadata and referenced nonempty runtime receipt/admission
authority artifacts plus pins. Trace ArtifactRef also resolves. This only checks
claims/byte integrity; no signature, role authenticity, admission or actual execution
is certified. Fixture records remain scripted and unmeasured. All-not_run/absent
observations keep replay unavailable with current metrics null/not_run.

Optional behavior_map artifacts parse as shared BehaviorMap, retain static evidence
and require source/file identity. Every nested SourcePointer must be covered by a
resolved manifest pointer entry. Entries are exactly source_artifact_id/pointer;
pointer has the six exact shared source_sha256/filename/line_start/line_end/byte_start/
byte_end keys. Shared SourcePointer resolves exact raw UTF8 source, codepoint/byte
boundaries, one-based inclusive lines and half-open spans. No rewritten source or
foreign pointer is accepted. Source and candidate text is displayed only; no AST,
import, shell, subprocess, eval/exec or dynamic artifact loader executes recorded code.

Bounds refuse instead of truncating: manifest8MiB; each artifact256MiB; combined
artifact bytes1GiB; structured/text reads32MiB each; depth constraints apply in report
serialization/shared models. These are explicit replay input budgets, not study-arm/
case denominator cuts. Immutable dedicated staging is required; no concurrent file
mutation defense or complete credential provenance proof is claimed.

## Reporting

`cobolmap.reporting` exports build_document,render_json,render_html,to_data. Own report
is a JSON-ready source/replay envelope; it is not another shared RunResult model.
All shared models remain DL3-owned. Source evidence mode is preserved, processing
mode labeled separately, runtime/admission/authenticity status unverified/pending/
not_established. Recorded claims keep their native statuses and exact decimal text;
current live counts/cost/contrasts/intervals stay null/not_run. Coverage has explicit
unknown and custody unverified sections. Supplied failures/outcomes/issues, artifacts,
pointers, static maps and all raw-model data remain visible rather than being omitted.

HTML escapes headings, labels, code, JSON and all supplied strings. No scripts,
auto user URLs, remote assets, iframes or active payload interpolation; constant
CSS and restrictive CSP only. Generated/recorded text is shown in escaped pre blocks,
never executed. JSON escapes controls/ANSI via its serializer and rejects nonfinite
numbers. Source hazards, comparison labels, fixture success and possession of hashes
never become an authentic oracle pass or equivalence proof.

## Deferred checks

After explicit runtime authorization/Dirty closure: import/entrypoint/model roundtrip
and combined facade checks; CLI error statuses/exclusive output; real source CRLF/
UTF8/hash/pointer cases; malformed/refused/missing/aliased/changed bundle artifacts;
mode/pin/receipt/reference disagreements; fixture-vs-actual treatment; observation
hex bytes/missing-empty handling; escaping/script-injection/terminal controls;
large/deep input limits and immutable-staging assumptions; exact restored report
hashes from real dev receipts; compiler-free demo recording. No such check ran here.
Actual compiler/tool/isolation receipts, independent source/custody/license/seal work,
live authorization/prices/accounts/keys and publication remain separate pending gates.
