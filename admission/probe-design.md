# Deferred oracle and shim probe design

This is a design inventory, not probe source, held-out data, expected-answer data or
an execution report. Every item is NOT RUN. No numeric/status expectation below is
an established compiler result. An appointed independent verifier later authors
tiny sanity probes and labels their independently reasoned expectations as probes;
the builder never authors hidden programs, recipes or expected bytes.

Use the pinned oracle contract in oracle-preparation.md. A probe receipt binds exact
source/input/output hashes, ordinary/trace build kind, two repeat observations,
tool/config/image pins and executing session. Inspect emitted observables only;
internal state is not observable unless source explicitly emits it. Separate genuine
handled errors from crashes and instrument faults. Failure blocks affected semantics;
retain discrepancies instead of changing hypotheses to hide a failed instrument.

## Admission probes (at least six, all required)

| ID | Instrument question | Required observation/check, still deferred |
|---|---|---|
| A01 | Signed decimal MOVE and arithmetic | Compare explicit emissions for positive/negative fractions, truncation and zero sign; preserve bytes. |
| A02 | ROUNDED ties and non-ties | Both signs, halfway and adjacent values; verify guide hypothesis against compiler, then shim. |
| A03 | Overflow and SIZE ERROR | With/without handler, explicit destination-before/after emissions; distinguish defined handling from uncontrolled fault. |
| A04 | Sequential-file scenarios | Present, missing, empty and EOF; emit status. Research hypotheses 35 for missing and 10 for EOF require actual pinned verification. |
| A05 | Integer year window | Both sides of declared pivot and pivot itself, with emitted result; no platform date dependency. |
| A06 | Trace instrument parity | Same source/input with ordinary and -ftraceall builds, repeated twice; exact ordinary equality and separately captured diagnostics/source identity. |

## Focused shim probes (at least 24, all required)

Each row describes a distinct narrowly isolated case family. The future verifier
chooses concrete legal values within the frozen grammar; no table cell is an oracle
answer. Compare the future shim to recorded compiled-original results. Independently
reasoned sanity expectations diagnose instrument errors without becoming study answers.

| ID | Focus | Selection/measurement constraint |
|---|---|---|
| S01 | Positive tie, ROUNDED | Exact halfway discarded digit; emit destination. |
| S02 | Negative tie, ROUNDED | Mirror sign without normalizing output. |
| S03 | Positive non-tie below halfway | Adjacent representable below tie. |
| S04 | Positive non-tie above halfway | Adjacent representable above tie. |
| S05 | Negative non-tie below magnitude halfway | Preserve sign and destination scale. |
| S06 | Negative non-tie above magnitude halfway | Compare exact bytes to S05 independently. |
| S07 | Tiny discarded positive fraction | Fraction smaller than destination least unit. |
| S08 | Tiny discarded negative fraction | Include signed destination emission. |
| S09 | Positive truncation without ROUNDED | Nonzero discarded fraction. |
| S10 | Negative truncation without ROUNDED | Distinguish toward-zero hypothesis from floor. |
| S11 | Negative zero through MOVE | Explicit signed display and source/destination declarations. |
| S12 | Negative zero through arithmetic | Same representational question, arithmetic path. |
| S13 | Leading separate sign | Measure emitted width/sign position; no sign stripping. |
| S14 | Trailing separate sign | Measure exact bytes independently of S13. |
| S15 | Internal COMP-3 size | Explicit compiler-observable size for odd/even legal digit widths. |
| S16 | Internal COMP-3 truncation | Move internal packed field to emitted numeric destination; no external packed codec. |
| S17 | Overflow without handler | Largest admitted boundary and next arithmetic result; classify fault if uncontrolled. |
| S18 | Overflow with SIZE ERROR | Explicit handler path emission. |
| S19 | Destination preservation on SIZE ERROR | Emit sentinel before/after; do not infer preservation. |
| S20 | Divide-by-zero handling | Declared handler and unhandled variant; no matching-crash pass. |
| S21 | Multi-operator COMPUTE intermediate | At most three operators, mixed scales; record final result and source order. |
| S22 | Missing sequential input | Explicit emitted status, input_present=false. |
| S23 | Empty input versus EOF | Present zero-byte input, first read and subsequent EOF; record order. |
| S24 | Year-window lower side | Pivot minus one and pivot, no date clock. |
| S25 | Year-window upper side | Pivot plus one and declared century mapping. |
| S26 | Signed to unsigned MOVE | Negative source and unsigned destination, emitted result. |
| S27 | Alphanumeric padding/truncation | Shorter/longer moves, exact widths and spaces. |
| S28 | Ordered records and presence | Same records reordered, empty versus missing; case hashes must distinguish these. |

Additional prerequisites: schema/recipe reachability, original/changed pairing,
loop/verification disjointness and exact 32/128 counts; original/changed repeated
ordinary and trace parity per sealed case; independent reproduction of admission
probes and three deterministically selected dev programs. These are not replaced
by the six admission probes or 28 shim designs. Candidate containment requires at
least ten hostile fixtures later (filesystem/oracle reads, network, subprocess/fork,
output flood, loops, imports and mounts); this document creates none of those fixtures.

Freeze source, recipes, counter policy and pins before probing. Disputes retain
minimal reproducer, guide citation and observation hashes. Semantic disagreement
does not remove scored cases; nondeterminism/configuration faults invalidate the
instrument. No corpus, compiler run, shim result, GO, license adoption or seal is
claimed by this inventory.

Receipt seam validation is also NOT RUN. Deferred focused negative/positive checks
must cover raw versus canonical pin mismatch, bool counters, reordered case hashes,
duplicate boundary labels retained on one case, false boundary mapping, wrong field
width/sign, incorrect final-loop exclusion commitment, counter overflow/reset and
cumulative proposal exhaustion. Exercise the real producer adapter when supplied;
do not substitute synthetic receipts for observed generation or admission evidence.
