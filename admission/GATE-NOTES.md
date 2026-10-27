# P2 admission gate, version m10-p2-v2

Construction only. **P2 remains PENDING; P3–P15 blocked.** No license,
custodian/verifier appointment, private seal or actual execution receipt has
been provided. This package supplies no GO record, corpus, hidden data or
expected answers. Source stays private pending Roy's R03 license decision.

Authority: promoted PLAN-M10-v1 sections 4–5 and section 10 P1/P2; plan-body
SHA256 552ddcb9121deb21489a903eaf77979b8068231a94a0fb714b948094c8d4dbed.
DL4 owns the gate/schema/custody paths only. r2 reconciles the DL1 contracts at
05a1d0c846b9a40a9bf4b2a0efd67e3865c715f6 after fast-forwarding the assigned lane
from local master c01644fc7058c1c2806c9b8820f4642dfafb9e44. The additional accepted
master files were DL3 preparation files; this reconciliation did not inspect or
modify their source. No product implementation or new custody role is granted.

## Interface and authority

`evaluate(root: Path, record_path: str, authority_path: str,
authority_sha256: str) -> dict` reads local evidence and returns gate_version,
status, issues and the structural-claim limitation. No CLI, product import,
import-time IO, command execution, signing, evidence write or network access.
Use only later in an authorized custodian environment: the evidence root holds
private commitments/receipts that builders must not use for held-out rehearsal.

Only relative forward-slash paths resolved beneath that root are accepted.
Artifact hashes always bind actual read bytes. LF Git blob hashes and CRLF
checkout hashes are distinct: never normalize a file before comparing its raw
artifact SHA256. Canonical JSON hashes and CaseBundle hashes are other, separately
named commitments. They never substitute for raw artifact hashes.

Caller must independently authenticate Roy's approved authority and supply its
digest out of band. Authority binds gate version v2, the adopted plan, four
separate sessions/identities, appointments, approved briefs, licenses and their
license_approval_ids, deterministic three-dev selection and exact seal/date.
All disclosed builder/product/preparation authors belong in author_sessions.
Authority authors profiles bind their exact identity, session, canonical harness,
approved brief and complete lineage; the author_sessions inventory must match
those profiles. This allows genuine dev/shared preparation contributors without
relabeling their work as the primary builder's. The builder profile must match
its appointment. Profiles are contributor declarations, not custody appointments.
Include complete parent/child/fork sets in lineage_sessions. Custodian separately
authors hidden data; both independent roles' lineages must avoid all disclosed
builder authors and the designated builder lineage. Verifier and custodian
lineages must be disjoint. No builder or review child can self-appoint.

Harness vocabulary is closed: Codex, Claude, Cursor, Grok, Antigravity, Human.
Frozen briefs exactly equal the approved actor/author brief set without duplicates.
Registry labels, complete lineage disclosure and signatures require external
authentication; a hash cannot establish those facts.

## Canonical joins introduced in r2

FAMILY.md, GENERATOR.md and PROVENANCE.md are authoritative for native names.
The gate record is an evidence envelope, not a replacement native format.

| Accepted source field | Gate join |
|---|---|
| family_id, split, domain, template/program/hazard metadata | families[].metadata uses exact native family keys; domain is decimal_fees, sequential_status or year_window |
| author_provenance_sha256 | families[].author_provenance actual-byte reference; template_commitment remains a distinct gate evidence reference |
| task_id, program_id, family_id, split, panel | tasks[].binding uses native task identity; panel is unchanged or change |
| original_sha256 / oracle_source_sha256 | original_source / oracle_source actual-byte references; the paired panels share the same original reference |
| fields_sha256 | input_fields raw artifact hash; output_fields is a separate source-bound document |
| recipe_sha256 | recipe raw artifact hash, treated as a task-level commitment; see remaining producer gap below |
| generator_sha256 | frozen generator pin, never a generated-input or canonical-document hash |
| change_sha256 | null for unchanged; otherwise the structured edit artifact hash; its changed_sha256 binds oracle_source_sha256 |
| ProgramManifest source/input/output/provenance hashes | exact oracle source, input/output field documents and the source artifact's provenance-sidecar bytes |
| allowed_return_codes | sorted unique integer list 0..255 including0; no fault becomes a declared code |
| loops/proof/hazards | closed native objects; unique ordered loop targets, nonzero step, declared 1..64 cap, source-resolving spans and >=2 hazard IDs; semantic proof/reachability still requires verifier evidence |

Gate schemas validate integer manifest_version=1 on native records. The gate
protocol version is separately m10-p2-v2. Unknown keys, duplicate JSON keys,
UTF-8 BOM, noninteger JSON numbers and booleans as integers reject. Source and
schema bytes must be pinned together for a later launch; version labels alone
do not authenticate them. The local shape validator implements only the JSON
Schema subset actually used: closed objects, exact/nullable types, arrays,
min/max items and integers, strings/patterns, enums and constants.

## Native provenance sidecars

artifacts[] is now a gate envelope of file, provenance and license_class.
The provenance file uses PROVENANCE.md names exactly: artifact_path/hash/kind,
author_callsign/harness/session_id, UTC created_at, textual originality_attestation,
nullable family_id, dev/heldout/shared split, brief/generator/source/parent hashes,
license_id/approval_id/status and evidence_paths. Gate evidence_paths use hashed
file references; native prose does not define a weaker alternate path format.

Hidden author identity joins the appointed custodian; dev/shared authors join
Roy-approved builder contributor profiles. Task-associated sidecars join
exact artifact bytes, family and split. Brief hash equals the approved author
brief. Generated input requires the frozen generator hash; a nongenerated
artifact may carry null. Shared instruments have null family_id; only an
independent shared specification may omit source_sha256. The textual originality
attestation needs genuine review for contribution/model family and prohibited
ingestion; a nonempty sentence is not proof. Changed-source sidecars identify
changed_source and their original source as parent; original source sidecars
require a null parent. ProgramManifest provenance
commits to the oracle source sidecar, avoiding a self-hash requirement.

Pending license status requires null license/approval IDs and stays PENDING;
denied is NO-GO. Approved license IDs/decision IDs must equal Roy's externally
approved authority and have actual evidence references. No MIT/CC0 choice was
adopted here. original_artifacts enumerates every extra program/probe/candidate/
request/field/recipe/input/instrument/specification; each actual digest must join
its checked sidecar. Task source/fields/recipe/manifest/case/edit artifacts also
require provenance. The custodian/verifier must check corpus completeness.

## Case counts and actual receipts

Six families/split, two/domain, four dev or three held-out originals/family:
24 dev +18 held-out originals, each with its own change task =84 tasks. Every
task requires exactly32 distinct valid loop and128 distinct valid verification
full-case hashes, disjoint within that task. Case hashes mean GENERATOR.md's
M10-CASE-v1 binary preimage: presence, count and ordered length-prefixed records.
They are not raw input.dat hashes or JSON hashes. Missing and present-empty
are distinct; task labels cannot make duplicate bytes disjoint.

The generator's generation-only receipt reports unique **candidates**, recipe/
fields/partition hashes, boundary mapping, counters and exclusion commitments.
Its case_hashes/target count cannot establish valid oracle cases, repeated
execution, trace equality or independent reproduction. A generation receipt
fails the closed task-oracle/task-trace schemas and cannot satisfy an actual
checklist receipt. No conversion to an executed receipt is supplied.

Gate-owned task-oracle/task-trace schemas remain a later admission evidence
contract: two distinct ordinary executions of all160 valid cases and a traced
ordinary observation equal to those bytes, bound to task/source/case/tool/image
hashes and actual logs. No runner is claimed to emit them yet. The required
signed checklist remains compiler/notices, originality/licenses/dev prep;
hidden authorship/counts/template separation/independence/seal; independent
compiler/probe/three-dev reruns and recipe/reachability/custody; Roy licenses/
staffing and manifest confirmation. Distinct actual receipts are mandatory;
fixture/static modes or absent/skipped executions never pass.

## Remaining producer seams and deferred validation

FAMILY's singular task recipe_sha256 does not specify how a two-partition native
recipe inventory is packaged. This gate verifies the declared task commitment,
but does not claim it is one GENERATOR recipe for both partitions. INT/DL1 must
confirm the task-level commitment/partition-recipe representation before actual
admission integration; producer absence is pending. Likewise field documents
are shape/source/hash checked here; the frozen generator and independent actual
validation must establish PIC/layout/encoding, boundaries, presence/order,
1..64 records, deterministic counters, quarantine/replacement semantics and
full-case hash computation. Metadata does not establish those properties.
The gate interprets task change_sha256 as the structured edit artifact hash,
whose changed_sha256 member binds the changed oracle source. INT/DL1 should
confirm that distinction before connecting actual task producers; no adapter
silently exchanges a change-document hash and a changed-source hash.

Loop spans/caps and hazard metadata do not prove every path bounded/reachable,
complete loop enumeration or return-code reasoning. The appointed verifier's
recipe/reachability/custody evidence must establish those semantics and changed
behavior witnesses; source shape inspection does not. No parser or expected-
answer logic was added to the gate. No builder sees held-out inputs/answers.

After explicit execution authorization and Dirty Mode closure: reconcile real
generator/runner receipts without inventing execution, exercise positive/negative
schema/binding cases, test path containment, reproduce actual compiler/probes and
three-dev receipts, and complete licenses/staffing/seal/custody. Retain failed
receipts and the plan's retry/reseal/burn rules. None of that ran here.

## Verdict boundary

Missing files/fields or pending items yield PENDING; malformed, contradictory,
denied or failed evidence yields NO-GO, which dominates PENDING. Errors remain
aggregated once closed top-level records parse; none defaults to a pass.
GO is structural eligibility only. It cannot prove truthful authorship, secrecy,
complete lineage/corpus, semantic independence, genuine signatures or actual
execution narratives, and grants no product/live/release authority. Fixtures
are never independent validation. The portable evidence-gate normalized
checker has not been adopted or claimed equivalent by this package.
