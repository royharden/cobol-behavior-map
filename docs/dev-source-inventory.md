# Builder-authored dev source inventory

Private source-only construction, runtime unverified. No admitted corpus or independent test data.
There are 24 original COBOL files and 24 one-edit changed files in six dev families, four original variants per family.
No parser, translator, native generator, CLI or compiler was imported or invoked to author/check them.

| Family | Domain | Template | Intended hazards |
|---|---|---|---|
| dev_decimal_tier | decimal_fees | fee_threshold_branch | H1, H5 |
| dev_decimal_chain | decimal_fees | three_operator_division | H7, H8 |
| dev_status_fallback | sequential_status | linear_eof_fallback | H3, H6 |
| dev_status_two_read | sequential_status | two_read_gate | H3, H6 |
| dev_year_century | year_window | century_direct | H4, H5 |
| dev_year_pivot_score | year_window | pivot_division | H2, H7 |

The native family declarations and source-inventory.json identify every source/edit/field/manifest path and raw SHA256.
Variant constants and requests do not increase independent family count. Different family control templates remain explicit.
Each original has a distinct original task ID and one changed task ID. Changed source bytes differ by one supported
numeric literal, alpha literal, comparator or ROUNDED edit; this does not establish a behavior-changing witness.
Two hazard themes and source-linked targets per program express static design/reachability intent, not observed reachability.

All programs use fixed input.dat/output.dat bindings, FILE STATUS fields, exact DISPLAY layouts and at most two acyclic
paragraphs; two-read behavior is unrolled. No PERFORM UNTIL appears, so loops=[] records absence rather than a fabricated bound.
Today/year values are inputs. There are no clocks, external/client/Gauntlet/NIST inputs, hidden templates or other-app source copies.

ProgramManifest declarations end in .pending.json because hazard reachability_recipe_ids are empty: current grant authorizes
no actual input records/partition recipes/case generation. These declarations are intentionally NOT complete/schema-eligible
(minItems1 cannot be met truthfully) and must not be passed off as admitted manifests. The later authorized data author must
supply actual references, independent checks and compiler-derived source/change witnesses; invalid/nonchanging/unreachable
sources must be rejected. Native task paired-recipe indexes/recipe hashes are absent, not fabricated. Compiler semantics,
fallback initial values, error handling/statuses, internal packed layout, numeric rounding and actual edit effects remain pending.

Provenance uses actual builder session/callsigns, source/field/edit raw hashes and UTC creation times. No human or independent
role is claimed; source license_status=pending, license_id/license_approval_id=null. ProgramManifest provenance_sha256 binds
its source provenance bytes. Fields pins are raw stored bytes, distinct from future canonical generator commitments.
The generic static writer expanded authored source templates and wrote bytes/hashes/spans only; it was not an application run.
corpus/dev/.gitattributes disables text conversion for cbl/json/md to preserve these exact raw pins on checkout.
No root attributes or other lane source were edited. docs/translation.md policies are hypotheses, not expected oracle outputs.

Source bytes, JSON syntax/keys, counts, raw hashes, exact edit/target spans and declared static limits can be inspected offline.
Actual COBOL syntax/compiler acceptance, parser/translator/CLI joins, case counts, reachable hazards, behavioral witnesses,
license approval, provenance authentication, independent custody/verifier/seal and P2 all remain unverified/pending.

All sources guard READ/WRITE/CLOSE with successful-open flags, avoid a second READ after EOF, and emit FILE STATUS outcomes before cleanup and after CLOSE attempts. H3 targets a WRITE result that is emitted without conditional handling. Current parser flow and runtime failed-OPEN modeling need owner reconciliation; no executed join is claimed.
