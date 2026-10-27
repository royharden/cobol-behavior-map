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
document hashes, distinct from stored artifact sidecars. Source hash is an input
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

## Generator-to-runner adapter (r2)

Pure namespace API `admission.prepare.generator_adapter.adapt_task(binding, generated,
artifacts)` never calls the generator, writes paths or runs a validator/compiler.
Its provisional API/consumer seam is recorded in OUTER requests/SEAM-DL2-adapter-r2.md.
Artifacts must be immutable exact bytes in memory, keyed source, fields, loop_recipe,
verification_recipe, program_manifest, generator, case_spec, family_spec; each value
is exactly {path,raw_bytes}. Missing source artifacts return pending; malformed or
contradictory bindings refuse. No actual artifact bytes are authored in this package.

Binding is exactly task_id/program_id/family_id/split/panel/original_sha256/
oracle_source_sha256/change_sha256. Both recipes must name the same task/program/family,
partition and canonical field document; fields and ProgramManifest bind exact oracle
source raw bytes. Unchanged source equals original with null change; change source
equals change hash. Caller authenticates original/change provenance and joins the
structured change/task inventory; adapter does not prove program legality or effects.

Output run entry has the accepted runner eight-key shape, intended repeat counts2/2
as a proposed schedule, not observed runs. Cases artifact has exactly loop/verification
32/128 bundle transports: presence, ordered records_hex, unchanged binary case hash,
input_file (null for missing). Every present file descriptor contains ordered records
with LF after each; present-empty is zero bytes. No path is materialized. Descriptors
carry path, raw_bytes, exact raw_sha256, separately named canonical_sha256 for JSON,
and spec_lf_sha256 only for spec documents. LF pins are b0ac6b2d.../08c2e2ca...;
raw CRLF artifact hashes are retained separately. Case bundle artifact hash is the
stored JSON bytes hash, not an individual full-case hash.

Generation-receipts record has task_id/program_id/panel/source_sha256/fields_sha256,
recipe_sha256={loop,verification}, partitions={loop,verification} with the original
nine-key receipts. It is serialized as a descriptor and returned for DL3 semantic
validation. Adapter checks task/source/field/recipe joins, ordered case hashes and
exclusion commitments; DL3 owns full counter/boundary/custody receipt semantics.
No receipt becomes an oracle observation or valid-oracle case count.

Caller aggregates complete original/change panel pairs, artifact descriptors, recipe/
field/program-manifest indexes and generation-receipt records using the final DL3
consumer seam. Caller supplies actual pinned compiler/package/image/libcob/config/
tool-info/runner artifacts and real compiler declaration; missing_actual_pins reports
these as pending. Adapter returns no runnable envelope or fabricated pins/authority.
Generator implementation artifact hash is explicitly generator_raw_sha256; this is
not the case-spec LF hash. Caller authenticates the complete helper/source closure
when freezing tools; an arbitrary caller-supplied generator descriptor alone does
not prove it produced the supplied results. Staging must remain immutable and actual
filesystem containment belongs to the runner. Exact transport API execution, runner
join, negative source/recipe/panel/path/byte binding cases, and all compiler/runtime/
custody/GO validation remain deferred. No adapter or generator was executed here.
