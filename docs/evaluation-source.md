# Evaluation construction source

`evaluation/` is private source outside the distributable wheel. Nothing imports it
from the CLI, sends provider requests, opens the ledger, authors study artifacts or
activates a study. Dirty construction is runtime-unverified. P2, licenses, approved
model IDs/prices, real admission, independent appointments, conformance and paid
authority remain absent. Current authorized spend is USD0. Pending dev source
manifests from DL2 are not admitted corpus or measured reachability evidence.

## Schedule and selection

`schedule.build_schedule(native RunPlan)` requires the entire unique 84-task frame:
six dev families with four programs and both panels (48), six heldout families with
three programs and both panels (36). Paired panels must bind the identical original
source hash; a shared program ID alone is insufficient. Programs cannot cross families/splits. The two
logical slots are `primary` and `replication`; model IDs stay `None` until actually
declared. Declarations are never model approval. There is one sample per task/model.

`Schedule.tasks` describes each free deterministic A slot, repeated for each model
comparison without a paid call. `calls` describes B/C attempt0 and D/R repairs1..3;
domain-separated, length-framed SHA256 identities bind run/task/model-slot/arm/attempt.
Adapter smoke occupies a separate identity domain; all1346 IDs must be unique. Maximums
are 768 dev, 576 heldout and two separate smoke slots, 1346 total. All task source,
oracle/edit and recipe refs are native `TaskBinding`, not a second corpus model.
Hidden slots are opaque metadata only; builders must not materialize/read hidden
programs, cases or outcomes. A declared frame is not authority to access it.

The identifier algorithm is now `m10-call-id-v2`: its version, domain, run, task,
model slot, arm, fixed sample1 and attempt are length-framed before SHA256; native
call IDs are `c_` plus the first62 lowercase hex characters,64 total. Ordinary,
shared-C and smoke references use the same algorithm and combined uniqueness check.
Actual SHA256 commitment fields remain full hashes. This is an explicit identifier
edition change; previously sealed inventories must never be silently rewritten.
This construction team has emitted no actual inventory.

`fork_shared_c(CandidateAttempt)` shares the identical frozen C object, including
its bytes/hash/call/status when invalid or refused. D and R have separate immutable
`SampleState`. `record_loop` records only the trusted 32-case loop failure count;
unknown measurement stops unavailable. `append_repair` checks exact model/task/C
identity, sequential attempt and unique call IDs, retaining every attempt. The
first loop pass, repeated candidate hash or third allowed repair stops selection;
absent a loop pass the selected candidate is the last allowed one. Refused or
invalid candidates cannot pass the loop. `disclose_verification` requires closed
selection and permanently forbids repair; verification never chooses a candidate.
No callback, provider invocation, cross-task memory, feedback truncation or implicit
fixture exists. A future caller must authenticate loop observations and persist all
attempts, including sent-unknown calls, independently of these pure transitions.

DL1's proposed `ReductionResult.origin_case_sha256` is separate from the final
`case.case_sha256`. Only the original root belongs to the sealed original32; no
derivative is inserted into that set or counted as a new original. `ReductionStep`
retains parent/derivative hashes and actual witness pairs as local control evidence.
The current minimizer explicitly has `outbound_feedback_compatible=False`.
Evaluation contains no feedback serialization or generic model-dump path and does
not consume that result as an original member. Derivative feedback remains missing
until DL3's explicitly adopted interface authenticates exact origin/task/program/
source/candidate/pins, retained lineage and final witness using external authority.
Full lineage/intermediate witnesses must stay local; D may receive only the one
permitted final witness, R counts only, with no verification/trace/other-task leak.
Hash lineage or flags alone cannot authenticate execution or authorize transport.

## Preregistration and accounting boundary

`prereg.Preregistration` contains a native `RunPlan`, closed named `Commitment`
references and optional `ModelPrice` slots. The complete key set covers task/source/
corpus/compiler/runtime/shim/prompt/model/price/payload/generator/execution/seed/cap/
authorization/GO/exposure/admission/token-count/canary/custody/conformance artifacts.
References commit raw bytes, not their truth or approval. No default pins, prices,
signatures, GO, custodian, approved IDs or fabricated zero liabilities are supplied.
Caller must authenticate the contents and bind each actual source, payload, price,
seed, cap and immutable task schedule before any later independently authorized use.

`validate_prereg` rejects duplicate/unknown commitments and schedule/seed/cap/model
drift. Missing values yield explicit issues. Full all-fee bounds use canonical DL1
`CostBounds`; the additional bound must include declared other fees and its pinned
method must bound cache/reasoning/category overlap and every non-token fee. Input
and output maxima are 6000/2500. Actual whole-wire token counting and category-method
verification are external; no tokenizer approximation is accepted as authority.

Exact rational money avoids ambient Decimal rounding. Each model has 673 maximum
calls. The recommended envelope checks are one summed per-model smoke call <=USD1,
384 summed per-model calls <=USD20 dev, 288 <=USD17 heldout, full schedule <=USD40.
USD40 is a study ceiling, not permission; remaining USD2 is reserve, not extra calls.
Full schedule plus known, reserved unknown and other app liabilities must fit the
declared current authorized headroom, which defaults to zero. Missing liabilities
remain unavailable. The report may describe an inert native `PricePlan` only when
all inputs are present. It always reports `backend_unverified`, missing external
authority/conformance/admission/custodian and `dispatch_allowed=False`.

Accepted DL1 ledger source9e40591 is the only accounting backend. Its constructor
and mutations are never called here. Native `reserve`, `mark_sent`, `settle`,
`mark_unknown`, `link_shared_c`, `record_expense`, `report` and `export` stay with DL1.
The ceiling, a reservation, a hash, environment flag or signature-shaped metadata
cannot grant dispatch. DL3's published provider seam uses B/C0, D/R1..3 and the same
C call ID; its `AccountingBridge` also has no transport and cannot use the unverified
backend. No provider SDK, key/env reading, live adapter or substitute backend exists
in evaluation source. No joined ledger/provider execution has occurred.

## Custody metadata consistency

`custody.validate_chain(events, *, commitment_sha256, expected_tasks)` reads only
future supplied immutable metadata. `CustodyEvent` hashes compact sorted ASCII JSON
of all dataclass fields except `event_sha256`; the first predecessor is `None` and
sequence starts at1. Every event binds the same prereg commitment. No seal/event
instance, signature or appointment is emitted. `expected_tasks` are precommitted
verification-unit IDs (each task/model/arm), not a deduplicated corpus task list.
The caller's authenticated commitment must bind that entire exact unit frame.

Transitions are unsealed -> sealed -> scheduled -> running -> completed, with
terminal burned permitted after sealing, including exposure before completion.
Reordering, duplicates, missing predecessors, commit drift, unknown/replayed units
and post-completion replacements refuse. Reserved call IDs are unique; only
never-sent reservations are resumable. Unresolved sent/unknown IDs globally block
new sends/reservations and completion. Settlement reconciles the same call ID,
never another request. No backend calls or model regeneration occur.
The resumable report uses the same running/open-unit/global-hold predicates as the
send transition; sealed, disclosed, completed, burned or globally blocked units
never appear structurally eligible. This is still bookkeeping, not send authority.

Verification fixes the candidate hash permanently. Genuine observed candidate-
independent infra faults can retain another verification record for the identical
candidate; the first valid record completes that unit. A boolean declaration is
not independent proof: all custody authenticity remains `unverified`. The entire
chain must be retained. Local hashes cannot authenticate a custodian or prevent an
operator rewriting a whole chain. Real hidden operation remains Roy-appointed only.

## Descriptive summaries and costs

`stats.expected_slots(native tasks)` adapts the complete schedule into frozen
`TaskSlot` metadata for both models. `OutcomeRow` adds arm/outcome/evidence mode and
optional verification counts. `summarize(rows, expected, *, split, panel,
model_slot)` uses the separately frozen expected frame, never the observed rows as
the denominator. Every A/B/C/D/R row remains scheduled. Missing, unknown,
infra-invalid, non-actual or unmeasured rows block complete headlines. A measured
pass requires all128 verification cases passing. Actual candidate refusal,
malformation, crash or ordinary fault is a failed sample, not an omitted one.
An `actual` label remains supplied and unauthenticated; it is never admission.

D-C, D-R, C-B, D-B and D-A are reported separately for dev/heldout, each panel and
each model. Six family means receive equal weight, with 10000 resamples of six
whole families using seed20261027; intervals use exact linear interpolation of
2.5%/97.5% percentiles. The six values, discordant counts, measured and scheduled
pair counts accompany each contrast. Effective n=6, descriptive and fragile; no
significance, power, generalization or provider sampling-variance claim is made.
One sample cannot estimate provider randomness. No summaries have been executed.

`AttemptCost` describes every actual supplied attempt, selected or not.
`summarize_costs` deduplicates exact call IDs, rejects conflicting duplicate
identities/charges and attributes the same C charge to both D/R while counting it
once in the application projection. Inclusive arm costs must not be summed.
Unavailable charge or unresolved liability yields null total. Completeness requires
the authoritative all-attempt ID inventory, including failed/refused/unknown and
other app expenses in the real ledger; unused maximum schedule slots are not bills.
The projection does not replace DL1's authoritative ledger or authenticate billing.

## Supplied dev replay enumeration

`replay_manifest.enumerate_manifest(path)` requires an actually supplied inventory
and raw artifacts. Kind, logical source filename, capture time, source mode and
run-result identity cannot truthfully be inferred from filenames. The accepted CLI
`load_replay` checks the actual files, strict native `RunResult`/observations/maps,
source spans, inventory refs and raw SHA256/size budgets. No directory sweep or new
candidate, observation, receipt, capture time or result is generated. No supplied
recorded code executes. Not-run input stays unavailable; fixture remains fixture.

The returned `ManifestEnumeration` holds manifest bytes for an explicitly authorized
future caller to save in dedicated dev staging, actual inventory metadata, original
manifest raw hash and separate canonical manifest hash. Raw result/source/receipt
bytes are unchanged. Processing is replay; source evidence mode is preserved;
authenticity/admission remain unverified. The closed v1 CLI schema is unchanged.
The CLI's private/credential/heldout/root/link/Windows alias guards and limits apply.

## Deferred verification

Only source inspection, AST parsing and Git whitespace/hash checks are permitted
now. Target imports, functions, statistics, tests, generators, custody/ledger calls,
artifact creation, providers and CLI were not executed. Later authorized isolated
conformance must exercise schedules/state and disclosure, exact money/fee bounds,
custody restart/reorder/unknown/infra handling, missing-denominator/bootstrap/cost
projections, replay byte/path/race behavior and joined provider/accounting contracts.
Source review and construction acceptance do not establish product/runtime results.
