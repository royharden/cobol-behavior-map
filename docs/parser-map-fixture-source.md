# Builder parser/map regression source

Original disclosed builder regression sources and future native unittest assertions. Author-declared static expectations are neither compiler/oracle observations nor independent proof. At authoring, no tests or app functions have run. All source licenses stay pending/null; no admitted/scored/held-out corpus or actual CaseBundles/input records/expected compiler outputs/model data are authored.

There are43 original COBOL snippets:20 refusal sources targeting18 current emitted parser refusal codes,6 IR/PIC/pointer/control/map-limit sources, and17 H1-H8 positive/near-negative/guard-invalidation sources. Three future test modules live under tests/parser_map/. Each source/proposal/test and inventory is raw-hash bound with actual parent0003 or child0080 author/session provenance. Child authoring utility is preserved only OUTER in task-owned authoring scratch, outside product source.

| Refusal code | Source cases |
|---|---|
| bad_layout_or_sign | external_signed_embedded |
| bad_picture | bad_picture_prefix |
| compute_limit | compute_four_operators |
| control_flow | main_missing_stop |
| duplicate_name | duplicate_folded_name |
| external_path | external_input_binding, logical_filename_escape |
| field_limit | numeric_digit_limit |
| file_contract | read_before_open, close_after_failed_open |
| literal_range | value_overwidth |
| out_of_subset | forbidden_call |
| return_contract | return_without_manifest |
| source_encoding | encoding_nonascii |
| source_limit | line_limit_201 |
| syntax_error | header_syntax |
| type_mismatch | alpha_to_numeric |
| unbounded_perform | until_without_proof |
| unknown_token | unknown_symbol |
| unresolved_name | missing_receiver |

The partial_parse enum is a concrete coverage/precondition gap: SUBSET lists it, but current lexer/parser/validation have no emitting path. Parsing consumes remaining tokens as paragraph syntax or raises another code. The future explicit partial-parse test is skipped with that reason, not replaced by a made-up fixture/code expectation. MappingRefusal.pointer_unresolved and MappingLimitRefusal.map_limit are distinct map API boundaries; pointer corruption and source-admitted call-DAG expansion tests use their real prerequisites.

Refusal expectations assert exact code, raw source hash/filename and byte/line pointer consistency, with a source failure-focus intersection where meaningful. Encoding and line-limit fixtures are intentionally invalid/non-ASCII or201lines; they are not supposed to be admitted programs. The invalid logical filename case expects the documented safe fallback diagnostic filename and zero-width initial pointer. This is explicit static diagnostic expectation, not observed behavior.

IR/map fixtures protect escaped quote/comment token fidelity, raw LF/CRLF source pointers, separate-sign width/offset versus packed working-storage layout, successful-open alpha flag cleanup and call-site-specific PERFORM returns. The acyclic eight-paragraph/four-way DAG is intended to exceed4096 map edges after parser admission while staying below static parser analysis budgets; actual budget behavior remains unexecuted and any earlier failure must be reported, never relabeled as a map pass. Internal COMP-3 width assertion describes current proposed IR layout only, not measured compiler storage parity.

Each hazard assertion binds hazard ID to one exact target statement/span/hash; unrelated warnings cannot satisfy a target check. H3 currently warns every OPEN/READ/CLOSE/WRITE even with status guards: no guarded suppression pair is claimed. Its near-negative has no file operation. H4 tests a two-digit YEAR-YY name with a dominating literal50 pivot comparison. H7 includes nonzero guarding and subsequent write invalidation. Static warning detection is neither actual reachability nor a proven bug. Source minimum-two-hazard admission rules do not apply to these isolated regression instruments.

Every proposal records what_bug_this_catches: a plausible incorrect acceptance, refusal, span/layout/control result or warning classification. The tests assert functional public parse/build_map/resolve_pointer outputs, not a local reimplementation of their algorithms. Test files must preserve fixture bytes with read_bytes().decode(...), never text newline normalization. All app imports/calls occur only in the deferred test source; none were invoked while authoring.

ROUND2-DL2-DL3-DIAGNOSTICS.md grants a later narrow exception: after fresh static review of the exact test edition, parent may run only these own tests using already-installed Python3.11.3/Pydantic with -B, process-local PYTHONPATH=owned src, explicit file selection and bounded timeout. No pytest/plugin discovery, installs, Docker, network/provider/accounting/SQLite/backend, generated candidate, guest entry, hostile fixture or compiler execution. Python3.11 is below project>=3.12; any later results are unsupported-runtime diagnostics, never supported-runtime validation or study/admission evidence. Exact tested commit/command/version/results must be retained separately OUTER; this inventory creates no executed result.

Source permissions remain unchanged. A concrete product mismatch must be reported to INT; no parser/map/scored grammar fix is authorized. Current code paths/read hashes and all artifact/test pins live in source-inventory.json. Metadata/authorship hashes are integrity labels, not license approval or independent authentication.

Deferred: actual reviewed-edition diagnostics, supported Python>=3.12 execution and dependency validation, all native parser/map/IR/source-pointer/layout/control/hazard/manifest/resource behavior, compiler parity/reachability, full product/CLI/translator joins, licenses/authenticity/independent roles, runtime/entry/screen/backend/hostile containment, P2 and study acceptance. No unexecuted test or skipped gap is a pass.
