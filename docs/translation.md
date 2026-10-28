# Decimal translation construction

Private original source under the delegated source-before-P2 overlay. Everything
here is runtime-unverified; no compiler probe, generated program, shim function or
test has run. There are no authored oracle observations or independent data.

`from cobolmap.translate import translate, TranslationResult, TranslationRefusal`.
`translate(program, change=None)` consumes DL1's `ProgramIR`, including retained
original source, exact source SHA/filename/spans, field storage/record metadata,
explicit `FileBinding` and parser-attached PERFORM proof bounds. It returns a frozen
result with `code`, `original_source_sha256` and a tuple of diagnostic strings.
Failures expose `code/message/span`; no code is returned after refusal.

Generated Python is text with a fixed `cobolmap.translate.runtime.run_plan` import,
an inert literal plan and `run_case(input_present, records)`. The facade never
executes/imports generated text. The future isolated candidate entry consumes raw
ordered record bytes and returns modeled `output_present/output_bytes/stdout/stderr/
return_code`, plus construction-hypothesis metadata. These values are not an
ExecutionObservation, authentic receipt, admitted corpus or equivalence claim.
No filesystem path, clock, environment, network, subprocess, eval or dynamic import
is exposed. Only explicit input/output record bindings select storage; FD role is
never guessed from a path or field offset. Logical source filenames are metadata.

The closed plan supports MOVE, ADD, SUBTRACT, MULTIPLY, DIVIDE GIVING, bounded
three-operator COMPUTE, comparisons/AND/OR/IF, named PERFORM/UNTIL, OPEN/READ AT END/
WRITE/CLOSE, DISPLAY and MAIN STOP RUN. RETURN-CODE is an integer0..255 literal MOVE;
membership in declared outcomes is the parser's manifest-validation obligation.
No fallthrough/recursive calls or unknown node/argument shapes are accepted.
The parser's structural/semantic validation is the input facade contract; the
translator additionally checks original bytes/spans/layout/types/references.

Shared shim APIs are `DecimalValue(coefficient,scale,negative_zero)`, `decimal_value`,
`FieldSpec.from_mapping`, `AssignmentResult`, `move/arithmetic/compute/compare`,
`truncate_toward_zero/nearest_ties_away`; codec exports `parse_display/format_display/
decode_record/encode_record`. Internal `embedded/packed` source sign metadata is
preserved in plans; no embedded-sign or packed external byte codec is invented.
The shim canonicalizes its internal numeric representation only. Numeric constants
retain exact decimal text including `+`; floats/exponents/executable strings refuse.

Explicit construction hypotheses, all requiring pinned GnuCOBOL probes:

- Exact rational arithmetic intermediates; destination truncation toward zero or
  nearest ties away for ROUNDED. Unhandled overflow/division-zero is a typed candidate
  fault; a handler receives size_error with its previous destination preserved.
- Signed zero is retained; signed-to-unsigned numeric MOVE takes magnitude. Alpha
  MOVE truncates/pads right; comparisons space-pad matching alpha operands.
- Implicit initial values are zero/spaces. Numeric DISPLAY renders picture digits
  with an implied decimal point and a separate sign, including a proxy for internal
  packed/embedded fields; this is not measured internal DISPLAY parity.
- File statuses00/35/10 model successful/missing/EOF cases. Failed-open READ47 and
  CLOSE42 are additional unverified hypotheses. Missing and present-empty differ;
  output presence starts at OPEN OUTPUT, records/stdout keep exact LF and spaces.

Native `change` is exactly the FAMILY structured-edit mapping, with its existing
keys and target. CLI passes the decoded mapping directly; no alternate model or raw
text patch is required. `target.node_kind` is the exact DL1 IR kind (`literal`,
`compare` or the arithmetic verb). Original hash/file/line/byte span/before/type
must resolve exactly once. Operations numeric/alpha literal replacement, numeric IF
comparator replacement and ROUNDED toggle preserve one-node routing; unknown/noop/
ambiguous/out-of-context edits refuse. Raw edit artifact hashing stays with the
caller; decoded mapping/canonical JSON is not its raw artifact identity. The changed
source hash is a commitment only; translator never fetches oracle-only changed text.

Numeric edit representability uses the nearest arithmetic receiver or the referenced
peer field(s) in a comparison: exact scale, digit range and sign must fit without
rounding. Literal-only comparisons without a declared field context refuse rather
than inventing a numeric type. This restriction applies to edit eligibility, not
ordinary source arithmetic intermediates. A future extension needs explicit context
metadata; it must not silently admit an out-of-range or fractional replacement.
Expression ownership stops at the nearest statement, including handler/AT END bodies;
an inner MOVE or literal-only IF cannot borrow an outer arithmetic receiver. Numeric
MOVE literal edits are outside FAMILY's arithmetic/comparison edit vocabulary.

Edits revalidate types/graphs and derive candidate loop bounds with the declared
constant monotone integer proof form, all-path step checks, dominating known values,
PIC fit and the64-iteration subset limit. This is static candidate reasoning, never
compiler execution or a changed-original admission proof. An edited unreached loop
whose test/induction changes lacks dominating context and refuses `change_requires_proof`;
it needs a separately supported proof interface, not a guessed cap. Unmodified
unreached loops retain the parser-attached original proof metadata. Runtime statement,
stdout and output-file caps are secondary guards, never proof or OS isolation.

Future activation must exercise shim/codec signed-zero/tie/non-tie/truncation/overflow/
handler and internal-width probes, field/source correspondence, all statement/file/
year-window journeys, edit targeting/noop/loop-bound cases and malformed IR refusals.
Generated text syntax/execution, full parser/contract/CLI joins and candidate isolation
are untested. Equal-access API docs and actual implementation/import closure must be
frozen identically for all arms; generic runtime assistance must be disclosed. No model
traffic, corpus admission, custody appointment, license, cost or release is authorized.
