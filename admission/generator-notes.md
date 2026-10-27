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
