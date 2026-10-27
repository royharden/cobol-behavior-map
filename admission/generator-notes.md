# Standalone preparation generator

Dirty construction only; runtime unverified. R02/R03/P2 GO pending. Original private
source; no license adopted. Consumes authoritative DL1 GENERATOR.md and FAMILY.md
through SEAM-v1-authoritative.md; no product, compiler, expected answers or corpus.

Use load_document(raw_utf8_bytes) for strict duplicate/BOM/float/nonfinite-refusing
JSON, then prepare(fields, loop_recipe, verification_recipe) for a paired task.
Mapping API requires strict-decoded JSON. generate(fields,recipe,excluded_hashes)
is the low-level partition API: verification requires exactly 32 distinct committed
loop hashes; the caller owns their authenticity. prepare obtains them itself after
checking task identity and partition pairing. Cases stay in memory as ordered bytes;
no automatic execution or file writes. All outputs are unexecuted_not_admitted.

Exact manifest_version=1 PIC/usage/sign/offset/width/scale layout is validated.
Numeric encoding uses integer/string arithmetic, preserving explicit signed -0,
refusing unsigned negative zero and excess fractional precision without rounding.
Case hashes use M10-CASE-v1 binary framing. Records omit LF; later materialization
adds LF per record. Missing and empty differ. Partition commitment is SHA256 of
canonical JSON ordered full-case hash strings. Recipe/field hashes are canonical
document hashes in native generator recipes/receipts, distinct from stored artifact
sidecars and raw ProgramManifest/task pins. Source hash is an input
binding, not a compiler execution receipt.

Boundary consumption is exactly top-level complete case, ordered complete boundary
cases, then seeded fill: no value expansion, inferred boundary or Cartesian product.
Duplicate explicit same-partition cases are recorded/skipped; any explicit case
colliding with opposite partition fails partition_collision. Unique explicit cases
above target fail. Tags describe author intent, never achieved semantic coverage.
Seed is SHA256 of canonical JSON identity tuple; draw uses seed || U64BE(counter)
|| U32BE(row) || U32BE(field) || U32BE(block). Reserved row/field 0xffffffff choose
record count. X concatenates draw blocks and maps modulo95+32. Numeric draws map
modulo finite field domain. No clock, model, OS randomness or version-dependent PRNG.
At most100000 fill proposals; every proposal advances the counter, every duplicate
is logged, exhaustion refuses rather than shrinking the fixed 32/128 counts.

Generation refusals carry code, root JSON pointer, stage and canonical field/recipe
hash context. Strict JSON parse refusals precede valid-document hashing. No partial
partition is written or admitted. Expected compiler outputs are never computed.
Oracle-only quarantine/replacement integration is deferred: future caller must
retain prior accepted hashes, reasoned quarantine records/counters and exclusions,
and never replace based on candidate outcomes. Generation uniqueness is not admission.

Deferred execution: deterministic repeat generation; malformed JSON/layout/recipe,
signed-zero/precision/bounds, hash/order/count/disjointness and exhaustion checks;
compiler repeated/trace observations; actual boundary/hazard reachability; custodian,
verifier and seal. Post-probe source/format freeze is not construction acceptance.
Static review/effort history is in OUTER run requests, not product runtime evidence.

Ruling r2 (GENERATOR b0ac6b2d52977025366b75c4ef02435fc70156500eaa2afd5d5eed07476f7f8c)
adds exact generation receipt and continuation. Result has cases, receipt,
ordered_sha256, duplicates, seen_hashes and unexecuted_not_admitted status. The
receipt alone has exactly the specified nine keys; boundary_case_hashes retains
every boundary ID even when cases deduplicate. Additional result metadata is not
part of that receipt schema.

Import as local namespace module admission.prepare.generate. Source-only helper
admission.prepare.generator_continuation.resume(fields,recipe,previous_result,
accepted_hashes,quarantine_hashes,excluded_hashes) preserves prior accepted order,
mandatory base/boundary cases and seen hashes, starts at receipt.next_counter,
and enforces cumulative100000 proposal budget/U64 bounds. Every omitted prior
case must be explicitly quarantined; mandatory explicit-case quarantine refuses.
Continuation checks receipt identity/commitments and prior case byte hashes;
the external caller authenticates that these are its genuine unsealed artifacts
and that quarantine decisions came only from candidate-independent oracle faults.
No oracle decision or seal enforcement is manufactured in this helper.

Finalize loop admission/replacements before producing verification. If loop changes,
invalidate the unsealed verification proposal and call generate with the original
verification recipe/seed and final loop hashes; never reuse continuation against a
changed exclusion commitment. Runner owns durable reasons/quarantine/skip ledger,
execution isolation and sealed-version reseal rules. These source APIs have not run.
Pairing diagnostics bind an ordered recipe-pair hash; per-partition diagnostics bind
the individual recipe. Decoder errors occur before valid canonical documents exist.
Earlier note saying quarantine integration is deferred refers to oracle/runner
integration; pure source continuation is now provided by ruling r2.

## Generator-to-runner adapter (r2, reconciled consumer indexes)

Pure namespace API `admission.prepare.generator_adapter.adapt_task(binding, generated,
artifacts, *, expected_generator_sha256=...)` never calls the generator, writes paths
or runs a validator/compiler. Require an externally authenticated generator source
SHA256; absence returns pending, mismatch with actual supplied generator bytes refuses.
Never infer this external value from a generation receipt. Caller authenticates real
generation results and immutable source artifacts; no generator/adapter was run here.

Artifacts map exactly source, fields, loop_recipe, verification_recipe, program_manifest,
generator, case_spec, family_spec to {path,raw_bytes}; change panels additionally require
the raw structured-edit artifact under change. Missing artifacts return pending.
Fields/recipe/manifest raw bytes are preserved exactly. Nine-key generator receipt
objects are serialized individually as canonical JSON descriptors: these are proposed
serialization of supplied real in-memory generator receipts, not invented run evidence.
No synthetic document or actual emitted index is supplied by this source package.
Binding has task_id/program_id/family_id/split/panel/original_sha256/oracle_source_sha256/
change_sha256. Source raw SHA joins fields and ProgramManifest; both recipes join exact
task/program/family/partition/canonical fields. Original/change source roles are checked.
Both partitions share corpus_version, and original recipes require strict integer
collision_counter0 in generator, adapter and continuation validation. Boolean/nonzero
recipe origins refuse. Continuation uses the unchanged original recipe and separately
advanced receipt/state next_counter, never a rebased recipe (INT ruling r3).

The output run entry keeps the accepted eight-key shape and intended repeat counts2/2,
not observed runs. Cases JSON is exactly loop/verification with32/128 transports
{input_present,records_hex,case_sha256,input_file}. Binary full-case hashes and ordered
bytes are preserved. Present descriptors append LF to each record; present-empty is
zero bytes; missing stays null/no descriptor. No file is materialized. Descriptors have
path/raw_bytes/raw_sha256/canonical_sha256/spec_lf_sha256. JSON canonical and raw hashes
are separately named; current LF edition pins a8a28c8b... and4895efdb... do not replace
raw CRLF hashes (accepted master4975609).

Consumer metadata follows SEAM-receipt-producer-index-r2.md exactly:
- generation_receipts: {manifest_version:1,tasks:{task_id:{loop:{recipe,fields,receipt},
  verification:{recipe,fields,receipt}}}}, with every leaf a descriptor artifact path.
- program_manifests: {manifest_version:1,tasks:{task_id:manifest_artifact_path}}.
Raw original field/recipe/ProgramManifest descriptors and partition-receipt descriptors
back all references. This supersedes the early inline source-bound receipt wrapper in
requests/SEAM-DL2-adapter-r2.md; no consumer uses that withdrawn wrapper.

`combine_tasks(packets)` is pure, accepts genuine immutable successful adapt_task
packets and returns pending for pending inputs. It aggregates only complete original/
change pairs, rejects duplicate tasks/panels, mismatched same-program family/split/original
hash or generator pins, and rejects artifact path conflicts. Equal shared descriptors
may deduplicate. It builds exact batch indexes and fields/recipes provenance catalogs,
a runner artifact-hash map and partial pins. Catalog paths are reserved and must not
collide with supplied paths; batches over1024 artifacts refuse (split complete pairs).

Caller supplies missing actual compiler/package/image/libcob/config/tool-info/runner
and DL3 receipt_validator/receipt_values source pins plus the actual raw frozen
subset_spec grammar artifact, authenticates complete source
closure, supplies real compiler declaration and freezes immutable staging. The returned
expected_generator_sha256 is the unchanged external argument for DL3 validator/CLI
handoff; generator_raw_sha256 separately describes actual provided source bytes.
subset_spec is distinct from case_spec/GENERATOR.md; its raw artifact pin must never
be inferred from or replaced by the case contract hash. It remains explicitly missing
in missing_actual_pins until the caller supplies it when assembling the envelope.
There is no runnable envelope or execution evidence until those actual artifacts exist.
DL3 owns semantic receipt checking, boundary/counter obligations and authenticated
source-context validation; filesystem containment belongs to runner. Actual generation,
transport/index join execution, malformed input/pin/path/panel/hash checks, compiler,
quarantine/custody/seal/licenses/P2 all remain deferred. Metadata is never a signed DL4
actual/approval receipt or oracle-valid observation. Next work requires a concrete
consumer mismatch; no source replay/fill-draw or continuation execution is claimed.

## Contextual field and recipe commitments (INT ruling r3)

ProgramManifest input_fields_sha256/output_fields_sha256 identify exact stored field
document raw bytes; adapter compares input_fields_sha256 only to its input field
descriptor raw_sha256. Output-layout validation remains the independent caller's
obligation because this transport API receives only the input layout. Native FAMILY
task fields_sha256/recipe_sha256 likewise identify actual raw field/paired-recipe
artifact bytes; DL1 owns the paired-recipe artifact shape, not this adapter.

Native GENERATOR recipe.fields_sha256 and generation receipt fields_sha256/recipe_sha256
retain canonical JSON document commitments. Seed tuples are canonical. These identical
key spellings are contextual: never accept raw or canonical interchangeably. Artifact
hash maps, source/tool pins and sidecars always identify raw bytes; explicitly named
canonical_sha256 and spec_lf_sha256 descriptor metadata never replace raw_sha256.

Continuation preserves original recipe0 identity/hash/seed, authenticates previous
receipt/state, and checks next_counter against cumulative consumed proposals (U64,
no wrap, at most100000). A positive state next_counter is legal and is never passed
as a new original recipe origin. No continuation/generation execution validated here.

## Paired task recipe index (INT ruling r4, within DL2 r3)

Successful adapt_task also returns task_recipe_index and its task_recipe_index_path
descriptor. The index has exactly manifest_version1/task_id/program_id/family_id/split/
panel/corpus_version/fields_sha256/recipes. recipes is exactly loop/verification, each
{path,sha256}, identifying the actual distinct raw recipe artifact paths/digests.
Index fields_sha256 uses the actual raw field descriptor hash. Native recipe
fields_sha256 and generation receipt commitments still use canonical JSON hashes.

task_binding_patch supplies fields_sha256 (raw fields), recipe_sha256 (raw serialized
task index), generator_sha256 (provided actual generator source) and change_sha256
(raw structured-edit artifact, null for unchanged). Caller joins this patch and
task_recipe_index_path to the authenticated enclosing task/source/artifact references;
the patch is not a full task, provenance attestation, authority or admission record.
combine_tasks returns these per-task paths/patches without changing the consumer's
generation_receipts/program_manifests indexes or field/recipe provenance catalogs.
Descriptor serialization is only source behavior proposed for future genuine inputs;
no index bytes or generator result were emitted during this construction work.

For a change panel the raw structured-edit descriptor must match binding.change_sha256;
its task_id/original_sha256/changed_sha256 join task/original/oracle source identities.
Source raw bytes bind oracle_source_sha256 separately and must differ from original
for a change panel. A changed source hash must
never substitute for the raw edit-artifact digest. Full edit legality, target spans
and behavioral witness remain later semantic/compiler checks. Unchanged keeps
change_sha256 null and original/oracle hashes equal. No native recipe keys were added.

Spec edition identity is returned as spec_edition_pins (current accepted GENERATOR
a8a28c8b656ee61d929f9048c222acf683fe09465c1aa9c240d0177da074bc9d / FAMILY
4895efdbb65ed26ecf24cece2fcc36a768a9e812a450c8e4f964355b2a78010b). Ruling r5 selects
that exact GENERATOR LF edition for active case_hash_contract_sha256 too; old code
pins are not alternatives. Binary case framing remains unchanged. Current spec
descriptors independently preserve raw bytes/hashes: new LF edition pins must not
replace raw staged artifact hashes. Consumer75ccd24 comparison is historical; DL3's
new r3 updates its active expected edition and removes its extra boundary-label cap.
The producer has no raw label-count cap;100000 limits cumulative fill proposals only.
Source comparison is static and the updated producer/consumer join remains unexecuted.
