# Equal-access decimal shim API v1

Specification only; no implementation or compiler-equivalence claim. Every arm A/B/C/D/R receives byte-identical versioned API documentation and permitted runtime access. Custodian may receive this spec but not shim implementation. No translated paragraph or changed original is provided through this API.

Numbers use exact decimal text/integers and explicit Python decimal contexts; float input and arbitrary eval are forbidden. FieldSpec contains name/pic/usage/sign/offset/width/scale with the GENERATOR external layout rules; internal fields additionally allow COMP-3 and have no external codec. API operations return tagged values/faults and never silently clamp or erase negative zero.

| Operation | Contract |
|---|---|
| `parse_display(raw: bytes, field: FieldSpec) -> DecimalValue` | exact width, ASCII separate sign and implied scale; preserve signed zero; refuse malformed bytes |
| `format_display(value: DecimalValue, field: FieldSpec) -> bytes` | encode representable destination value at exact width; no rounding/overflow hidden in encoding |
| `move(value, source_spec, destination_spec) -> AssignmentResult` | numeric destination quantization/sign behavior and alpha padding/truncation according to later measured pins |
| `arithmetic(op, operands, destination, rounded, size_error_handler, previous_destination) -> AssignmentResult` | op `add|subtract|multiply|divide|compute`; destination-scale/overflow/zero behavior measured by probes; handler preserves or updates destination only as pinned |
| `compute(expression, bindings, destination, rounded, size_error_handler, previous_destination)` | closed typed expression tree, <=3 binary ops, parentheses represented by tree; no arbitrary Python |
| `compare(left, comparator, right) -> bool` | typed numeric/ASCII comparison with no implicit mixed-type coercion; comparator matches SUBSET |
| `truncate_toward_zero(x,s) -> DecimalValue` | sign(x)*floor(abs(x)*10^s)/10^s |
| `nearest_ties_away(x,s) -> DecimalValue` | sign(x)*floor(abs(x)*10^s+1/2)/10^s; never decimal ROUND_UP |

DecimalValue retains decimal coefficient/scale and sign of zero. AssignmentResult is `{value, stored_bytes_or_null, size_error: bool, fault_or_null}`; a fault is not a successful assignment. A controlled handler outcome and an unhandled fault remain distinguishable. Integer arithmetic/context precision, intermediate quantization, packed internal sizes, negative-zero transfer and destination preservation remain unresolved until all 24+ focused probes pass. Do not choose Python default context as compiler semantics. Prototype code may not advertise parity before the gate. Shared API version/hash and implementation hash bind attempts and observations later.

Runtime file facade follows CaseBundle input_present/ordered records with explicit OPEN/READ/EOF/WRITE/CLOSE states, declared status field and RETURN-CODE outcomes. It must preserve output presence/bytes, stdout/stderr and return code; no whitespace/CRLF/sign normalization. A missing file is not an empty file. No ambient clock, filesystem paths, network, subprocess, imports or candidate access to oracle/hidden data is exposed. Exact missing/EOF codes are compiler hypotheses until probed.

## Claims and typed errors

B0 is a closed conjunction of field comparisons (`= != < <= > >=`) and output equality to a constant, another field or scaled linear expression. Only the two rounding functions above; explicit decimal semantics, no executable strings. Numeric coefficients/constants are exact decimal strings. Resolve every field/span; unobservable fields or impossible guards are untestable. Search <=50 guard-satisfying dev cases, boundaries first, supported_on_N only N>=10 including a boundary and no refutation; refutation yields a minimized dev witness. Finite tested support is not universal validity and cannot amend sealed verification.

API errors: `shim_type`, `shim_layout`, `shim_unrepresentable`, `shim_precision_unpinned`, `division_zero`, `size_error`, `unsupported_expression`, `file_contract`, `pointer_unresolved`. Refusal means no observation, not equality. Candidate-caused faults map to candidate failures, candidate-independent setup to infra_invalid; never disguise either as expected output. Deferred: every operation's pinned compiler probes, equal-access payload checking, context/intermediate/packed-size reconciliation, source/field correspondence and isolation validation.
