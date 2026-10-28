# Product evidence model and comparison API

Private original source constructed before P2 under the delegated overlay. Runtime,
Pydantic integration, semantic/compiler parity and independent admission remain
unverified. No examples here are measured observations. Native admission artifacts
and their gate remain separate from these product-facing model projections.

Import shared models from `cobolmap.contracts`. They use Pydantic2 frozen, strict,
extra-forbid models; nested collections are tuples. `canonical_json(model)` emits
UTF8 JSON with sorted keys, compact separators, ASCII escapes, explicit nulls and
lowercase hex bytes. Read original artifact bytes/hash first, then use
`Model.model_validate_json(raw)` for strict JSON decoding. Python-mode model_validate
expects actual tuples/bytes; do not use strict=False to hide transport mismatches.
Hex serialization/deserialization configuration and dependency behavior still need
runtime verification in the eventual pinned Pydantic2 environment.

`SourcePointer` binds source_sha256, filename, inclusive one-based lines and
half-open zero-based UTF8 byte offsets. `resolve(source, filename=None)` checks the
actual bytes, UTF8 boundaries, line agreement and optional filename. A constructed
pointer is not resolved proof. `BehaviorMap` contains tuple fields/paragraphs/edges/
effects/hazards/claims, all bound to its source/file. Hazards stay static_warning,
map status runtime_unverified and claims untested. MapField sign preserves none,
leading_separate, embedded and packed; external signed DISPLAY requires separate
sign, while internal COMP-3 metadata remains a probe hypothesis. No external packed
codec is exposed.

ArtifactRef hashes raw stored bytes. CaseBundle checks the native M10-CASE-v1
presence/ordered-length/raw-record preimage, preserving missing versus present-empty.
Records must be printable ASCII; LF/CR framing bytes are rejected inside records so
different record partitions cannot alias one materialized input stream.
file_bytes returns None for missing, empty bytes for present-empty, otherwise records
each followed by LF. ProgramManifest is a product projection with source/input/output
ArtifactRefs, declared returns and pending provenance/license/admission; it is not
the native P2 ProgramManifest schema or a replacement for its proofs. TaskBinding
keeps original source, changed oracle source and raw edit artifact distinct.

EvidenceMode is not_run|static|fixture|actual. RunResult.processing_mode separately
labels not_run|replay|oracle|live. Replay preserves declared source evidence mode;
it does not authenticate actual claims or promote fixtures. RunResult observations
are raw ArtifactRef tuples; unmeasured metrics are null and status not_run. Completed
requires explicit counts, complete schedule accounting and actual|fixture references.
No default expected output, authenticity, pass count or success exists.

ExecutionObservation binds task/program/source/case/candidate hashes, an optional
OrdinaryObservation, explicit outcome and declared returns, plus EvidenceBinding.
OrdinaryObservation preserves output presence/data, stdout, stderr and return code.
Trace artifacts and timing are metadata outside ordinary equality. EvidenceBinding
requires actual mode, runtime receipt, execution pins and admission authority before
its missing_actual checklist is empty. Empty checklist is still only structural
presence, never signature verification, independent custody or execution authority.

`cobolmap.diff.compare(expected, actual, admitted=False, fields=())` defaults pending.
An externally authenticated caller must explicitly enable comparison and supply
actual pinned observations. Oracle-side candidate identity must be absent and the
actual candidate hash must be present. Shared compiler/config/runtime/libcob/
default-conf/generator/shim identities must agree; distinct runtime image pins
are allowed for oracle versus candidate. Oracle faults yield infra_invalid; candidate
faults yield candidate_failure; matching uncontrolled crashes never match. Presence,
all bytes and declared returns compare exactly, without normalization/tolerance.
ByteDifference keeps raw mismatch bytes, their hashes, first offset and an optional
source-bound field hint. Classification tags are heuristics, never established causes.
Byte heuristics do not influence equality. General loop minimizer source is deferred;
no callback timeout or minimum is promised by this package.

B0 `Claim` is a closed conjunction of FieldComparison guards and OutputEquality.
Values are typed literals, field references or scaled linear terms with exact decimal
text. Only truncate_toward_zero and nearest_ties_away are defined. The evaluator uses
exact rational integer arithmetic, not floats, ambient Decimal state or eval. Static
evaluate_claim results satisfied/violated are mathematical relation checks over supplied
values, not empirical support/refutation or measured COBOL semantics.

Future `search_claim` requires pinned source/task, dev-only case provenance and explicit
admission plus actual oracle context before callbacks. It consumes at most1000 proposals
and50 oracle cases, boundary cases first. Decoded inputs require a caller-authenticated
authority and matching source-bound layouts. Output bindings require actual byte spans
with source-bound external DISPLAY layout (including implied scale) or exact lexical
ASCII; unobservable/missing fields are untestable. Input-only guards can filter before
oracle calls; output guards use genuine byte-witnessed outputs afterward, with false
guards still consuming the total50-call budget. No successful guard is invented.
Support needs>=10 distinct observed satisfying cases, a boundary, and no
refutation/issues. Refutation carries the actual counterexample; optional bounded
minimization can report best_found only. These are finite-case conclusions, not universal
validity, independent evidence, sealed verification changes or mutation kills. Callback
authentication, hard wall/CPU isolation and field-to-IR semantic correspondence remain
the admitted caller/backend's obligations; no execution provider is implemented here.

FeedbackPacket is closed by initial/counterexample/count_only kind. B gets no map;
C requires a map. D permits one loop witness and must call assert_loop_membership
with authenticated loop hashes before serialization. A refused/invalid/failed candidate
may instead produce diagnostic-only D feedback, with no invented candidate bytes.
`feedback_json` defaults to refusal unless admitted, checks a full32-case loop context,
membership/pointer resolution and payload bytes, never truncates or sends. It
requires an exact frozenset of32 distinct loop hashes; equal ordinary observations
cannot form a populated counterexample witness. A byte bound
is not token accounting. R has only failure counts and
its own prior candidate/diagnostic context, never witness or verification fields.
Source and candidate text are hash-bound data; foreign repair-arm candidates refuse.
Typed keys are primary leakage control, but cannot authenticate diagnostic origins or
detect hidden content embedded in allowed strings. Caller source/context separation,
payload-bound checks, canary rejection and genuine custody are still required before
any send. No provider/network/send function is implemented here.

RunPlan keeps model IDs/authority/GO/budget/pins explicit and defaults absent. Its
missing_authority checklist is not an authorization checker. All arms and k=1 remain
in the declaration; the finite-call/token bounds are declarations, not budget proof or
dispatch. No local ledger/provider implementation or live call occurs in this package.

Deferred activation: resolve P2/roles/licenses, establish authentic pinned source and
receipt artifacts, verify Pydantic JSON/immutability and imports, execute focused
positive/negative comparator/DSL/feedback cases, join parser/mapper/codec/CLI facades,
verify exact sign/scale/overflow/compiler probes and containment/callback time bounds.
No application imports, functions, tests, generated data, compiler/model calls, build,
dependency install, containers or live resources were run during construction.
