# Hostile candidate source fixtures

Builder DEV instrument source only. All 13 fixtures are NOT RUN; no fixture module was imported, compiled or executed. No observed output, expected-answer bytes, CaseBundle, CandidateRequest, backend callback, authority object or genuine conformance receipt was authored. Licenses stay pending/null. Sources are hostile data for later separately authorized containment validation, never independent or held-out study data.

| Fixture | Intended category | Raw source SHA256 |
|---|---|---|
| outside_scratch_read | out-of-scratch read | `f133d50c3b24b15310a48d9922205da08d7def272b901a13c5b4355825ea8ab7` |
| oracle_private_read | oracle-private read attempt | `8f57a4a88530b16425eea5dddf3c4b2d742161808977c5e77953f00be249744a` |
| network_socket | socket/network attempt | `28680419c7bc41b4315c0a10c9d38ef1b4808413fda786bd41a5ef01aa098155` |
| subprocess_attempt | subprocess execution attempt | `d7103e8ec7f261b848d2d82c73528f895edc5d5bd8e50f0445e6ba1585861e00` |
| process_limit | bounded process spawning beyond policy | `a14434faa2a34acf61614d3c180b214b9c1f0ccb62509ae40d782689ebbd0b0e` |
| memory_limit | allocation beyond memory policy | `35cafd6d2397ef08a416d90a4a79a0bfa415e5defa5c5ec83b3b2ad5b09b4682` |
| scratch_limit | scratch file growth beyond policy | `700c13b9c84a00eddbed60e4faa75509a87b7182f0d3c02f6e52996b2bf7cce3` |
| stdout_limit | stdout beyond captured output policy | `7ec53d082e5c6f08b97514fc7ea15cb7881b3b7ef9408a33e10e378407e6ff82` |
| aggregate_output_limit | combined stdout/stderr beyond aggregate policy | `2c4539f18f8c70808fd1a93bb9635c1164d67970553862622fec4cbd5a27ebd6` |
| endless_loop | endless CPU loop | `bf6a413493d847cd9c0d837be6d08dbf9e65a1a73b54fb7b1c8589b18013db29` |
| forbidden_import | non-SDK import attempt | `29236d88166b4aeed239f6afa59c4b504afa9fb718f9d437e76ee934bc87e679` |
| host_volume_read | fake mounted host-volume access | `2c8052cb7cdcf52176868684596d0940dfa7771a8794854b1de2bd9e5632effb` |
| readonly_root_write | write outside scratch/read-only-root attempt | `e8c29bed0d4a3f7477f7215efcaeddc07acf85f89cdb54e061d1810c9442e2e7` |

Each source has only a module docstring and one undecorated run_case(input_present, records) definition. Hostile imports, file/socket/process attempts, allocations, output writes and loops occur only in that never-autoinvoked body. No automatic main, decorators, default argument evaluation, class creation, module import or top-level call is present. An entry that reaches its end raises a diagnostic fault rather than inventing ordinary output. This is source structure, not a safety claim about invoking it.

The source/proposal inventory and all raw sidecars are in corpus/fixtures/hostile/. Source identity/proposal hashes use actual raw bytes; scoped attributes preserve them. All provenance identifies actual builder0003/0912/session01a17ef6-6282-7162-9d28-0d5deb0d6496 and original source authoring. No compiler/OS/backend/custody/license authority is inferred from hashes.

Staging reconciliation: integrated CandidateRequest accepts candidate Blob <=65536 bytes and exactly eight approved helper blobs; the planner stages /stage/candidate.py and the helper closure under /stage/sdk, with fixed isolated Python argv ending /stage/sdk/entry.py and m10-run-case-v1 ABI. Translator emits run_case(input_present, records). These sources match that signature, but a future authenticated approved entry adapter must invoke the entry inside actual isolation to exercise bodies. No adapter, request, input stream or backend is created here; fixtures do not supply a normal observation mapping.

The policy is a source declaration: UID10001, no network, read-only root, all capabilities dropped, no new privileges, 256MiB memory, one CPU, 64pids, 16MiB /work scratch, 5sCPU/10swall and 1MiB aggregate captured output. Attempts are intentionally above selected bounds. Output/CPU/memory/process/scratch quantities in proposals describe attempted source activity, never measured consumption or observed cap events. The process fixture has a finite 80-child attempt and no child recursion; descendant lifetime/cleanup must be independently authenticated before any containment pass.

Only fake marker paths are used. A later designated authority must arrange suitable synthetic canaries and a test child executable within an authenticated guest instrument, prove the intended operation was reached where appropriate, and verify that forbidden objects remain inaccessible and host/control-plane state is unaffected. Missing markers, nonexistent executables, failed routing, missing modules, process startup errors or generic crashes alone do not establish confinement. No credential, home, device, real oracle source or actual host-mount targets are supplied.

Pure DL1 screening may refuse a source before entry. That is a distinct screening result and never proof of OS policy enforcement. Exact screening API integration remains pending DL1 published supplement; no guessed screening call is made. Default runner backend/authority/conformance are absent and pending; these source files cannot authorize dispatch. Future fixture execution requires separate preparation authorization and authenticated backend controls, not a fabricated completed hostile-fixture receipt.

Classification is hypothetical: candidate-caused forbidden/import/timeout/resource/output failures remain candidate failures; setup/transport faults become infra_invalid only after external authentication. Observed channels, flags, outcomes, receipts, host effects, exact cap behavior and cleanup are all pending. A policy declaration or matching crash is not actual conformance.

Deferred: independent design/syntax review and authenticated actual entry/SDK source selection; screening versus enforcement distinction; actual backend/image/policy/tool pins; controlled canary/child instrument setup; resource accounting and capped channel capture; actual execution of every fixture; process cleanup and host unaffected checks; fault attribution, retained actual receipts and consistency; licenses, runtime/R07/P2/independent authority and study gates. No fixture invocation is authorized by this inventory.
