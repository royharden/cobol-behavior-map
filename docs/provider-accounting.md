# Neutral provider and accounting source

Private original source, Dirty construction only. USD0; no live model IDs/prices,
accounts/keys, authority receipts or actual result scripts are supplied. No HTTP,
SDK, environment/auth reader, sender or database backend is implemented by this
package. No provider/adapter/mock/ledger/import/test was executed during construction.
Provider wire shapes are unverified source hypotheses; official compatibility and
actual model/token/billing semantics must be checked under a later separate grant.

Import neutral types from `cobolmap.providers`. ProviderRequest binds call/task/arm/
attempt/sample and original typed context, with model/run-plan/price/token receipt
slots absent by default. D/R use their own immutable call ID plus a separate shared
C ID; no implicit retry or regenerated sent ID exists. Message holds typed ContextPart
tuples; content is delimited JSON data. Context kinds exclude verification, changed
oracle source, other-task, trace and arbitrary tool content. Typed tags cannot prove
origin: authenticated task-specific content hash allowlists are still mandatory.

`validate_payload(request,policy,require_actual_context=True)` checks all task/part
bindings, exact original source, arm access, repair/counterexample/count roles, shim
access, context allowlist, loop membership and decoded/serialized canary fingerprints.
It refuses oversize data without truncation. Empty/missing authenticated policy/token/
canary context yields pending. Fingerprints are a secondary interlock, not a complete
leak detector. No data declaration authenticates itself. Total exact model tokens,
including wire framing/schema/context and billable reasoning bounds, require an
external authenticated token receipt; a byte bound or an integer count is not proof.

`prepare_payload(request,format,policy=...)` builds OpenAI-compatible chat or Anthropic
message-shaped JSON as an inert PreparedPayload. Missing model/policy pends; unknown
roles/unsupported shapes refuse. No tools/stream/multi-choice are supported here;
the source declares a single text generation port. Payload bytes/hash and request
hash remain explicit, compatibility unverified and transport_authorized always false.
`parse_response(request,raw_json,format=...,sent=...,provenance='provider_declared')`
parses caller-supplied bytes; it does not fetch them or authenticate sent state.
Duplicate/nonfinite/malformed JSON, incomplete text and model mismatch cannot yield
success. Possibly-sent malformed outcomes remain unknown, not free failures.

Usage preserves nullable input/output/cache-read/cache-write/reasoning/other token
categories and reasoning-in-output overlap. Absent categories never become zero;
overlap and price semantics are never guessed. Parsing does not calculate cost.
ProviderResult statuses are not_sent/refused/failed/unknown/success; provenance is
not_run/fixture/provider_declared, never automatic actual study evidence. Raw response
digest remains separate from request/candidate/compiler evidence. A provider-declared
success is only supplied text, never a compiler observation, verified translation,
model efficacy result or P2 acceptance.

`ScriptedMock(entries,position=0).respond(request)` returns a result and next immutable
state, consuming only explicitly provided ScriptEntry call/hash/format/response data.
Missing, mismatched or malformed script refuses without canned success or advancing.
Valid scripted provider refusals/errors can consume their own entry. Fixture parsing
is explicitly selected with sent=False and may leave model pins absent if the raw
response also has no model. It never invents a model ID; fixture results cannot settle
a paid ledger or become actual evidence. No fixture/script/result instance was emitted.

`cobolmap.accounting.AccountingBridge` wraps the DL1 `shared.callledger` facade;
it never constructs Ledger, owns SQLite, vendors code or maintains a second store.
Native PricePlan/CostBounds remain DL1-owned frozen accounting inputs. prepare and
mark_sent first complete neutral/wire payload checks, recompute final wire bytes,
check explicit category/total token+fee bounds and matching sealed plan/model IDs,
then inspect ledger state. Native backend_unverified/dispatch_allowed=False blocks
progress. Only a future explicitly adopted backend_verified report may pass that
accounting precondition, and a true report flag is still not spending authority.

ApprovalArtifacts contains raw approval/GO/conformance/price/token/call-binding/
settlement/never-sent refs, all absent by default. A separately injected trusted
AuthorityBoundary implementation must authenticate their actual signatures/provenance,
independent gates, full maximum schedule liability, price/model pins, exact final
wire token receipt, context policy and immutable call-ID -> request-hash binding
across restart/concurrency. No verifier implementation is supplied. Its methods must
authenticate or raise and return None; boolean/data returns refuse. Merely supplying
artifacts, a ceiling, flags or a verifier-shaped object cannot establish genuine
authorization; that code dependency and environment need independent authentication.
The current native report always blocks even if such a dependency is supplied.

Bridge prepare uses native atomic reserve, then shared-C linking; mark_sent repeats
the preflight and reserve checks before a bookkeeping marker. There is no transport
call afterward. Shared C must be same model/task/sample, actually sent, settled and
known-cost; C is charged once and D/R get inclusive attribution rather than a second
C charge. Reserved/sent/unknown/terminal identities are never silently regenerated;
only exact never-sent reservation replay is structurally eligible. External immutable
call-binding verification, not a new bridge database, binds payload hashes to IDs.

Settlement stays recordable after lost dispatch authority: fixtures/unrun responses
refuse paid settlement; mismatched call/model/request or ambiguous sent state retains
unknown liability/global halt through native events. Missing billed cost/category or
authentication stays unknown, never cost0. Authenticated explicit never-sent zero-charge
proof is a separate path; lack of usage alone cannot activate it. Sent exceptions use
mark_unknown. Native overrun/conflict/late-unknown costs and liabilities remain intact.
Ledger errors propagate; no catch creates a new ID, retries a model or fabricates a
settled result. Caller must durably preserve actual raw provider/proof artifacts;
BridgeResult is a record of bridge processing, never a provider receipt or authority.

Deferred: actual shared facade/import availability, pinned provider compatibility,
real payload/token/canary/context checks, deterministic mock sequences, unknown versus
not-sent parsing, bounds/billing/cache/reasoning overlap, authentic verifier integration,
reservation/sent/exception/settlement/shared-C/restart/concurrency/overrun conformance,
durable raw artifacts, all runtime/security/resource behavior and independent P2.
No real approval, model result, valid compiler case, expected output or successful
backend conformance is authored here. Existing R02/R03-R07 remain open as delegated.
