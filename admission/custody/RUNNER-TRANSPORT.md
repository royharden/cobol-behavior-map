# Gate transport mapping — construction only

Current paired-index contract: accepted DL1 specs36d4f09, INT r4 ruling; producer
sourcebe2a409. Historical runner transport examined at exact acceptedc01644f.
This is a source comparison, not a receipt adapter, emitted packet or executed join.
DL3 owns generation-receipt validation and current consumer source; no other lane
is changed by DL4. No genuine compiler/backend/observation exists in this package.

## Pure producer descriptor to gate

Accepted generator_adapter.py `adapt_task` returns transport_only_execution_pending
(or pending), raw byte descriptors, task_recipe_index/path, task_binding_patch,
run metadata and missing_actual_pins. `combine_tasks` preserves full panel pairs
and aggregates transport catalogs. Neither calls generation/runner nor writes files.

- task_recipe_index_path selects the descriptor for task.recipe. Descriptor
  raw_sha256 binds actual serialized index bytes and task.recipe_sha256.
- task_binding_patch fields_sha256 binds actual raw input fields; generator_sha256
  binds supplied actual standalone generator source, authenticated externally.
- Index recipes.loop/verification refs bind raw native recipe descriptors. Native
  recipe fields_sha256 and generation receipt fields/recipe digests are canonical.
  Gate verifies raw before strict decode/derivation, never accepts either namespace.
- Descriptor canonical_sha256 and spec_lf_sha256 are separately named metadata;
  raw_bytes/raw_sha256 remain unchanged. No canonicalization of artifact pins.
- change_sha256 binds structured-edit raw bytes; its changed_sha256 binds changed
  source. Original/change task IDs, source-bound fields and indexes stay separate.
- Actual output field layout, provenance, signed authority and tool evidence are
  caller obligations beyond the pure adapter. They are not defaulted by the gate.

## Historical runner request to gate evidence

The c01644f preparation envelope is manifest_version1/kind oracle_preparation,
artifacts path→raw SHA256, pins, compiler, runs and case_hash_contract_sha256.
Its eight-key run is task_id/program_id/panel/source/cases/case_bundle_sha256/
ordinary_repeats2/trace_repeats2. The intended direct joins are:

| Native transport | Gate |
|---|---|
| run task_id/program_id/panel | task binding exact identity |
| run.source / artifacts[source] | oracle_source path / raw SHA256 |
| run.cases / case_bundle_sha256 | case_manifest path / raw SHA256 of stored cases artifact |
| case list case_sha256 | task loop_hashes/verification_hashes; binary full-case hashes |
| compiler_source, compiler_package pins | separate same-named gate raw pins |
| compiler_config, default_conf | separate same-named raw pins; both actual receipt bindings |
| base_image | gate image raw receipt pin; base_image_pin_sha256, not the contained OCI digest |
| libcob, runtime_config, generator | corresponding raw gate pins |
| tool_info | compiler_build_version_info raw pin |
| subset_spec | subset raw pin; never inferred from GENERATOR spec edition |
| runner | compile_runner raw source pin; actual staged bytes, not an LF-normalized substitute |
| fields/recipes/program_manifests catalog paths | explicit per-task source/field/index/manifest inventory joins; no implicit catalog expansion |
| generation_receipts catalog | DL3 generation-only checker input; never signed actual/approval or oracle/trace evidence |

Case transport has exactly loop/verification lists with32/128 entries:
input_present, records_hex, case_sha256, input_file. Hex is a serialization of
ordered record bytes, not the full-case hash preimage. Present file materialization
is each record plus LF; empty is zero bytes; missing is absent/null. Current gate
index eligibility does not replace DL3 case/receipt validation or infer oracle
validity from a candidate set or native request's successful preparation status.

Historical c01644f hardcodes old LF b0ac... as the case-format edition. That is
historical only, not a current accepted alternative. Current producer SPEC_PINS
and case_hash_contract_sha256 identify GENERATOR LF
706962cfa01ebe22892e8862260db1b8e4535d38d0e665af1c8b85bc5d4100fd, FAMILY LF
f780695503c0f5764ba6f05737ff6d8c2466f767c847466efc4a1a6496afe483. INT assigns
current DL3 r3 edition/receipt closure; no claim that historicalc016 transport is
already joined to those sources. Raw staged artifact hashes are checked separately.

## Missing actual execution transport

Historical runner emits prepared_only/execution unavailable/request_sha256/
oracle_observations null; --execute refuses before reading a request. No compiler,
sandbox, signature, seal or execution backend is present. These results and the
pure adapter's transport_only_execution_pending fail the gate's actual receipt
shape/mode requirements. Caller cannot replace absent receipts with counters,
flags, hashes of metadata or the success exit of a preparation validator.

Gate v3 now requires two trace repetitions across all160 valid cases, rather than
one summary; each has an independent log reference, ordinary observation reference
and separate trace-metadata reference. Both must equal the two ordinary runs.
Oracle/trace receipts bind an externally approved observation-framing edition.
No framing implementation, trace channel, repetition or output is manufactured.
DL1/INT ratification and real executing-role receipts remain pending.

OCI identity, complete measured compiler settings, tool/binary/config contents,
source closure, recipe semantics and genuine independent reproduction still need
actual appointed validation. Missing actual source/producer/observations is pending.
This mapping grants no execution, custody role, license adoption or product GO.
