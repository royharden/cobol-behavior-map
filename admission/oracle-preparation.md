# Oracle preparation contract v1

Status: preparation source only, runtime unverified. P2 GO, licenses, custody and
independent verification remain pending. No compiler results exist in this package.
The runner is Python 3.12 standard-library source, not a compiler launcher.

## Envelope boundary

`prepare/compile_run.py REQUEST --sha256 EXTERNAL_HASH --artifact-root ROOT` validates
raw envelope bytes against a separately supplied lowercase SHA256, then checks
artifact pins and the declared schedule. It prints `prepared_only` with
`oracle_observations: null`; this is neither a seal signature nor admission GO.
`--execute` always refuses, before reading the envelope. There is no backend switch,
subprocess, import of product code, shell, compiler or candidate execution path.
Future execution requires separately authorized implementation and validated OS
isolation; passing an image name, a receipt or an extra JSON field cannot enable it.
Do not run even this validator in the current Dirty Mode construction phase.

An authorized operator supplies an artifact-only staging directory, containing no
credentials or unrelated files. Relative POSIX artifact names cannot escape it;
linked components/junctions are rejected. Envelope is at most 1 MiB; each artifact
is at most 256 MiB (a legal 160-case inline hex transport can exceed 160 MiB).
At most 1024 artifacts and 4096 scheduled task variants. These are preparation
bounds, not study scope cuts: split envelopes at complete program/panel pairs if
necessary. One pair can hold two distinct sets of 160 cases plus tools/sources.
Staging must
be immutable while hashing; path checks are not a defense against concurrent host
filesystem mutation. Never point ROOT at a home, custody vault or arbitrary upload.

Top-level fields are closed: `manifest_version: 1`, `kind: oracle_preparation`,
`artifacts`, `pins`, `compiler`, `runs`, `case_hash_contract_sha256`. `artifacts` maps
relative paths to SHA256 of exact bytes. `pins` maps each of the following names to
one artifact path: `compiler_source`, `compiler_package`, `base_image`, `libcob`,
`default_conf`, `compiler_config`, `runtime_config`, `tool_info`, `generator`,
`fields`, `recipes`, `subset_spec`, `runner`, `generation_receipts`, `program_manifests`.
`generator` means the actual standalone generate.py implementation artifact, not
GENERATOR.md; its implementation hash intentionally differs from the case-format
spec hash in `case_hash_contract_sha256`. The runner pin must match the validator's
own source. Tool artifacts are future receipts, not invented images/configurations;
pinning a receipt does not verify that its assertions are true. `base_image` receipt
must contain the actual immutable OCI digest, not a tag. `tool_info` must preserve
full version/build/info and tool-help output. Package/source and libcob receipts bind
actual binary/source checksums. Config receipts bind complete config bytes and their
hashes; default.conf is separately pinned. License approval is external and pending.

Each `runs` entry has exactly `task_id`, `program_id`, `panel` (`unchanged` or `change`), `source`
and `cases` (artifact paths), `case_bundle_sha256`, `ordinary_repeats: 2`,
`trace_repeats: 2`. Each program has both panels, with distinct task IDs and no
duplicate program/panel. IDs use `[a-z][a-z0-9_-]{0,63}`.
`case_bundle_sha256` is the stored cases artifact hash, not one individual case hash.
The validator checks exact 32/128 case counts, case framing hashes, duplicate and
cross-partition hashes and physical file materialization. It does **not** establish
originality, family/split separation, legal subset, field layout correctness, seal
authority, reachability, oracle validity or custody. Those remain required before GO.
It does not accept expected-answer fields.

## Seam and freeze

INT adopted DL1's GENERATOR.md SHA256
`b0ac6b2d52977025366b75c4ef02435fc70156500eaa2afd5d5eed07476f7f8c` and FAMILY.md
`08c2e2caa5be00c7851e5b3ad37b4f2ce9c6f0be434d2de3ad22b3b9463f7da5` for construction
through SEAM-DL1-ruling-r2-relay.md; these supersede the earlier relay's stale pins.
The validator requires the former as `case_hash_contract_sha256`. Fields retain
name/pic/usage/sign/offset/width/scale; recipes specify missing|empty|records and
ordered field mappings. No generator recipe schema is redefined here.

Cases artifact transport is a JSON object with exactly `loop` and `verification`
lists of 32/128 entries. Each entry has exactly `input_present` (strict bool),
`records_hex` (ordered lowercase hex strings of exact record bytes), `case_sha256`,
`input_file` (pinned artifact path for present input; null for missing). Hex is a
transport adapter for in-memory bytes, never the case-hash preimage. DL2/INT own
joining generator results to this adapter; no joined execution is claimed. Records
are bounded to 64 printable-ASCII records of 1..8192 bytes. Missing requires no
records; present with no records means empty. Raw file bytes are records each
followed by LF, including the last; present empty is zero bytes. Each present file
must match both materialized bytes and its stored artifact hash.

Case hashing is SHA256 of `M10-CASE-v1` ASCII + NUL + presence byte 0/1 + U32BE count
+ ordered (U32BE length + raw record bytes). The validator checks this framing,
per-task partition disjointness and duplicates. Artifact SHA256 hashes stored bytes;
canonical document hashes use sorted keys, comma/colon separators, ASCII escapes,
UTF-8, integers only and no trailing newline, as GENERATOR.md defines. These are
distinct commitments; the envelope never substitutes canonical JSON for case bytes.
The original/changed schedule pair uses FAMILY.md unchanged/change panels and
separate source-bound task IDs. Post-probe instrument freeze and independent admission
remain pending. DL3 owns future runner reconciliation when the seam changes.

## Generation receipts and continuation boundary

`generation_receipts` pins an artifact holding the generator's original receipt
bytes; `program_manifests` pins source-bound ProgramManifest bytes from FAMILY.md.
Hash validation does not validate their declarations or make them execution evidence.
The current validator has **no receipt-semantic checker or continuation engine**;
it never consumes a next counter, replaces a case or emits an admitted partition.
Those capabilities are deferred, not coerced into the structural preparation result.

Later backend admission must validate each receipt's exact fields:
manifest_version, recipe_sha256, fields_sha256, partition, case_hashes,
boundary_case_hashes, next_counter, fill_proposals_consumed, excluded_hashes_sha256.
Bind recipe/field hashes to the same task/source; compare ordered case_hashes to
the case transport. Keep every boundary ID when explicit equal cases merge. Check
the canonical sorted unique exclusion-list commitment against the final loop set.
The generation receipt records candidates only, never oracle-valid admission.
Persist accepted/seen/quarantined hashes, boundary-label associations, the original
seed, next_counter and cumulative proposals in a separate later runner ledger.
Refuse counter overflow (U64), exhausted cumulative 100000 fill proposals, missing
history or changed seed; never restart counters to escape the cap. Resume only
before seal under the original stream, with no candidate-performance influence.
No recipe row expansion, alternate X draw, sentinel EOF or inferred boundary values.
ProgramManifest legality, allowed handled return codes, finite-loop proofs, source
hashes and reachable hazards require later semantic admission; metadata is not proof.

## Deferred compiler and containment contract

GnuCOBOL 3.2.0 ordinary argv, as a vector (never shell text):

```text
["cobc", "-x", "-free", "-std=default", "-O0", "-o", "<bin>", "<source>"]
```

Trace argv inserts `-ftraceall` immediately after `-O0`, using the same unmodified
source in a separate build/output directory. No debug/exception flags,
`-fno-trunc`, `-farithmetic-osvs`, IBM dialect or ambient compiler flags. The future
backend substitutes fixed container-internal paths, never caller-supplied commands.
The exact `compiler` object is version `3.2.0`, `ordinary_argv`, `trace_argv`, and
`environment: {"TZ":"UTC","LC_ALL":"C","COB_overrides":{}}`. Start from a
sanitized allowlist, clear all ambient COB_* overrides, and record actual runtime
configuration/defaults, PATH/tool resolution and allowed settings in pinned receipts.
Any required setting change demands a new reviewed contract, not an unrecorded flag.
Verify actual installed tool help/guide and pins in the later authorized environment.

Standalone preparation uses the same containment policy as the later product:
separate oracle and candidate containers; nonroot UID 10001; network none; read-only
root; all capabilities dropped; no-new-privileges; 256 MiB RAM, 1 CPU, 64 pids;
16 MiB scratch tmpfs; 5 s CPU/10 s wall; 1 MiB output per execution. No Docker socket,
home or credential mount. Candidates never receive oracle binaries, expected outputs,
hidden verification data or host paths. Compile and run only in a later validated
backend; build containment must also bound compiler effects. No Docker scaffolding
or invocation is provided now. Host candidate execution is forbidden in every mode.

## Deferred observation and quarantine receipts

For **each case of each original and changed task**, run ordinary twice and trace
twice from fresh state. Preserve output-file presence and exact bytes, stdout bytes,
ordinary stderr bytes and declared return code, including handled nonzero outcomes.
Never trim, normalize CRLF/signs, tolerate epsilon or derive expected answers from
Python/shim/parser/models. Compare repeated ordinary observations exactly. Compare
both trace builds' ordinary observations to both ordinary runs. Trace diagnostics
use a demonstrably separate channel, hashed as metadata; if separation cannot be
proved, reject coverage rather than strip arbitrary stderr. Trace must identify
source spans; absent statement identity means paragraph-only, statement unknown.

Future observation hashes must bind a versioned, unambiguous length-framed byte
encoding of output names/presence/bytes, stdout/stderr and signed return code. Preserve
raw byte hashes per component plus the aggregate observation hash and framing-spec
hash. DL1/INT must ratify observation framing before any receipt is frozen. No
observation hashing implementation or fabricated observation is supplied here.
Receipt links task/variant/case digest, source hash, generator/spec/tool/config/image
pins, build kind, repetition, argv, isolation policy/receipt, raw component hashes,
aggregate digest, timestamp and exact executing role/session. Trace metadata and
timing/containment receipts never enter ordinary equality targets.

Quarantine uncontrolled oracle crash, timeout and nondeterminism with counts/reasons
and retained receipts. Trace/ordinary divergence blocks instrument/coverage admission;
retain the case and receipts, never replace it to obtain parity. Wrong pins or
backend/setup failure also block admission, not candidate failures or passes.
Keep defined handled FILE STATUS/error outcomes. Deterministically replace quarantined
seeded cases by the recipe's next declared counter **before seal only**, until exactly 32
loop and 128 valid verification cases exist per task. Impossible counts fail admission.
An oracle-invalid mandatory explicit boundary fails admission; never replace away
its semantic obligation. Continuation consumes the original SHA256-counter-v1 stream,
preserving seen/quarantined hashes and cumulative 100000-proposal cap; no reseeding.
Finalize loop replacements before verification generation against the final loop
exclusion set. If unsealed loop changes, invalidate/log and regenerate verification
from its original seed against that final set. No post-seal quiet replacement.
Never replace based on candidate outcomes. Record guide/intent disagreements in
future disputes records with minimal reproducer and hashes; deterministic compiler
behavior stays the oracle, not silently normalized. No sealed-set repair by builder.

Deferred activation: approve R02/R03, appoint custodian/verifier, freeze DL1/DL2
interfaces, validate isolation with hostile fixtures, establish genuine compiler pins,
run admission/shim probes, reproduce ordinary/trace runs and verify seal/case counts.
Only actual execution receipts can close these gates. The present package closes none.
