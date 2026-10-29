# P2 admission gate, protocol m10-p2-v3

Construction only; runtime unverified. **P2 remains PENDING; P3+ blocked.** No
license, independent staff, seal, corpus, expected answer or execution receipt
is supplied here. Original source stays private pending R03. Adopted plan-body
SHA256: 552ddcb9121deb21489a903eaf77979b8068231a94a0fb714b948094c8d4dbed.

DL4 r3 implements RULING-task-recipe-index-r4.md in its owned paths, preserving
accepted r2 d315613. The lane started clean from accepted master4975609, then
fast-forwarded current accepted specs36d4f09 and producerbe2a409 while retaining
its owned source delta. Pre-r3 transport work was preserved as a patch and six
exact snapshots in ignored .agent-work/receipts/DL4-r3-intake; no reset/deletion.
Only the explicitly granted producer source and historical runner c01644f were
inspected; no generator/adapter/runner was imported or executed.

Current accepted spec LF edition IDs are GENERATOR
706962cfa01ebe22892e8862260db1b8e4535d38d0e665af1c8b85bc5d4100fd and FAMILY
f780695503c0f5764ba6f05737ff6d8c2466f767c847466efc4a1a6496afe483. These identify
editions. Actual staged artifact hashes remain hashes of actual read bytes;
no LF/CRLF or canonical digest substitutes for them.

## API and authority

`evaluate(root: Path, record_path: str, authority_path: str,
authority_sha256: str) -> dict` reads evidence and returns gate_version/status/
issues/recipe_bindings/claim. It writes nothing, signs nothing and runs no
commands. No CLI, product dependency, import-time IO or network. Use only later
in an authorized custodian environment, never as a builder held-out rehearsal.

File references use printable ASCII relative forward-slash paths under the
existing evidence root. Empty/dot/dot-dot components, drive/UNC/absolute paths,
backslashes, controls, linked components/junctions and resolved escapes reject.
Paired native recipe paths resolve distinctly and raw digests differ. Staging
must be immutable; hash/path checks do not protect concurrent host mutation.

Roy's authority digest is authenticated out of band and hashes the exact parsed
bytes. Authority binds protocol v3, the adopted plan, exact roles/sessions and
appointments, approved briefs/contributors, license decision IDs, independent
three-dev selection, seal/date and the approved observation-framing edition.
Builder-author inventory and profiles match; primary builder profile matches its
appointment. Both independent identities and complete disclosed lineages avoid
all builder authors/lineages, and verifier/custodian lineages are disjoint.
Custodian uses a different canonical harness. Profiles declare contributors,
not custody appointments. No implementation child may claim independent status.

Registry labels and hashes cannot authenticate those declarations. Caller must
verify Roy's decision, actual signatories, complete truthful lineage and genuine
observations. Frozen briefs equal the approved actor/author brief set exactly.

## Paired index and contextual commitments

Task binding uses unchanged/change panels, source/field/generator hashes and the
raw structured-edit hash (null only for unchanged). Each task.recipe_sha256
identifies actual stored paired-index bytes, referenced by task.recipe. Its
closed schema has manifest_version integer1, task/program/family identity,
split/panel, corpus_version, raw fields_sha256 and exactly loop/verification
recipe references. No new split/panel/source keys enter native recipes.

Gate checks index identity against the task; index.fields_sha256 equals task's
raw input-fields digest. It verifies those actual bytes first, strictly decodes
the source-bound field document, and independently computes canonical JSON SHA256.
Both raw native recipe references are read/hash-checked, strictly decoded and
matched to index/task/corpus identity, map-key partition, canonical field digest,
original strict-integer collision_counter0, original seed tuple and32/128 target.
Closed recipe/boundary/fill keys, complete field-name rows, scenario/count shapes
and unique boundary IDs are checked. No counter is rebased for continuation.

Canonical JSON means UTF-8, sorted keys, comma/colon separators, ensure_ascii=true,
no BOM/trailing newline, integer numbers only and strings unchanged. Strict JSON
rejects duplicate keys, floats/nonfinite values and integer lexemes over20 digits,
matching the accepted producer decoder. Native IDs and corpus ID use its lowercase
ID rule. Typed additional properties occur only in native record-value maps;
all other schema objects remain closed, and row keys must equal declared fields.

`recipe_bindings` reports computed raw index/raw fields/canonical fields and each
raw/canonical recipe commitment. This is metadata, **not** a generation receipt,
case count, observation, approval or independent evidence. Raw/canonical digests
may coincide for canonically stored bytes; both checks keep their named contexts.
The gate never accepts either digest as a fallback for the other.

Generation receipt fields_sha256/recipe_sha256 are canonical document commitments.
Envelope/sidecar/ProgramManifest/task/index hashes bind raw artifacts. DL3 owns
generation-receipt semantics; this gate neither calls that checker nor converts
its result to actual oracle/trace evidence. The paired index and both raw native
recipes each require recipe-kind provenance inventory entries joined to exact
bytes, family/split/source and approved contributor/custodian identity.

## Native source, fields, edit and provenance joins

Family metadata uses decimal_fees/sequential_status/year_window, six families per
split and two/domain. Four dev or three held-out originals/family give24+18
originals and both panels (84 tasks). Both panels share the original source,
have distinct task IDs/indexes and different oracle sources. Structured edit
raw bytes bind change_sha256; edit.original_sha256 binds original bytes and
edit.changed_sha256 binds oracle_source_sha256. No source/hash interchange.

ProgramManifest binds exact oracle source, input/output field raw documents and
raw oracle-source sidecar. Return codes are sorted unique0..255 including0;
source-resolving hazard/proof spans, unique ordered loop targets, nonzero step
and declared1..64 cap are checked. Metadata does not establish complete loop
proofs, valid node edits, reachable hazards or changed-behavior witnesses.

Native provenance retains author/session/harness, textual originality attestation,
UTC time, nullable source/generator/family/parent contexts and explicit license
status/decision. Dev/shared contributors join approved profiles; hidden work
joins the appointed custodian. Original source parent is null; changed source
parent equals original hash. Generated inputs need the actual frozen generator
pin. Approved licenses must match Roy's authority/evidence; pending licenses
have null IDs and stay pending; denied is NO-GO. No license choice is adopted.

## Transport and actual observation boundary

See custody/RUNNER-TRANSPORT.md for the exact producer/runner mapping. Accepted
producerbe2a409 emits only pure descriptors/task-binding patches; missing actual
tool/source pins remain explicit. Historical runnerc01644f emits prepared_only
with null observations and refuses --execute. Neither status can satisfy the
closed actual receipt schemas. No source or emitted join is claimed here.

The gate keeps exactly32 distinct loop and128 distinct verification full-case
commitments, disjoint per task. They mean M10-CASE-v1 binary framing, never raw
input.dat or JSON artifact hashes. Generation target_count/case_hashes establish
candidates only. Missing/present-empty and record ordering remain distinct.
Provenance-declared input artifacts may be zero bytes (present-empty input),
with their actual SHA256 checked. Approvals, signatures, briefs, receipt documents
and other evidence retain the nonempty-file requirement; an empty input exception
cannot be used as an empty approval or execution receipt.

Actual evidence still requires all160 valid cases twice ordinarily and twice
traced, separate trace repetition logs, and both trace ordinary observations
matching both ordinary runs. Trace diagnostics remain separate metadata. The
approved observation-framing digest binds oracle and trace receipt editions;
framing ratification/implementation/actual backend remain pending. Compiler
source/package are separate pins; complete compiler_config and default_conf are
separate actual raw commitments in task and generic signed receipts. The renamed
base_image_pin_sha256 denotes the raw base-image receipt artifact, not the OCI
digest inside it. Actual immutable OCI identity/tool truth still need independent
inspection. No framing bytes or observation is fabricated.

Required signed checklist retains builder compiler/notices/originality/dev prep;
custodian hidden authorship/counts/template/independence/seal; independent verifier
pins/probes/three-dev/recipe/reachability/custody; Roy licenses/staffing/seal. Neither
an index nor a prepared transport closes any of those items. Missing actual
producers or receipts remain pending, not automatically filled.

## Deferred work and verdict

After explicit execution authorization/Dirty Mode closure: exercise positive and
negative raw/canonical/index/identity/path/provenance cases; actual producer→gate
join; generator/receipt/continuation checks; field/PIC/layout/encoding and full-case
hashes; semantic loop/return/hazard/edit proofs and compiler witnesses; actual
framing/isolation/probe/oracle/trace/independent reruns; genuine staff/licenses/seal.
No tests, gate calls, imports of app modules or emitted data ran in this package.

Missing files/fields/pending items yield PENDING. Malformed, failed or contradictory
evidence yields NO-GO, which dominates PENDING. Computed recipe metadata cannot
remove errors or authorize execution. GO is structural eligibility only: hashes
cannot prove authorship/secrecy/completeness/signatures/actual narratives, nor
grant product/live/release authority. Fixtures never provide independent validation.
No adoption/parity of the portable evidence-gate normalized evaluator is claimed.
