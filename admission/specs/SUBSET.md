# M10 bounded language v1

Contract version 1. Implements the admission boundary in adopted PLAN-M10-v1 sections 4–5/7. This is a preparation specification, not compiler validation or P2 GO. Compiler behavior remains hypothetical until pinned probes run. Closed world: anything not listed below is refused, including recognized COBOL outside this grammar. No prefix/partial parse succeeds.

## Lexical and source rules

ASCII bytes only, free format, LF or CRLF source lines; at most 200 physical lines including comments/blanks. Keywords and identifiers are case insensitive; preserve original byte spans. Identifiers match `[A-Za-z][A-Za-z0-9-]*`, are at most 30 bytes, cannot end in hyphen, cannot be reserved words, and resolve uniquely after uppercase folding. Decimal literals have optional leading sign, decimal digits and optional fractional digits; no exponent, commas or figurative constants. Single/double quoted ASCII literals double their delimiter to escape it; no continuation, embedded newline or control bytes. `*>` starts a comment only outside a literal. Reject tabs/control bytes except source line endings. Token spans use zero-based half-open byte offsets and one-based line/column; unresolved references never become supported pointers.

## Closed productions

The following EBNF uses braces for repetition and brackets for optional text; quoted words/punctuation are literal terminals. `id`, `number` and `string` are lexical tokens. All declarations precede executable statements. Optional clauses appear only in the order shown. Division/section headers and paragraph ends use periods; statements use explicit terminators where shown. No implicit scope-closing period inside a block.

```text
program = "IDENTIFICATION DIVISION." "PROGRAM-ID." id "."
          "ENVIRONMENT DIVISION." "INPUT-OUTPUT SECTION." "FILE-CONTROL."
          select-in select-out "DATA DIVISION." "FILE SECTION."
          fd-in fd-out "WORKING-STORAGE SECTION." {decl}
          "PROCEDURE DIVISION." main {paragraph} ;
select-in = "SELECT" id "ASSIGN TO" '"input.dat"'
            "ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS" id "." ;
select-out = "SELECT" id "ASSIGN TO" '"output.dat"'
             "ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS" id "." ;
fd-in = "FD" id "." record ; fd-out = "FD" id "." record ;
record = "01" id "." { "05" elementary } ;
decl = "01" elementary | "01" id "." { "05" elementary } ;
elementary = id "PIC" picture [usage] [sign] ["VALUE" literal] "." ;
picture = "X(" positive-int ")" | ["S"] "9(" positive-int ")"
          ["V9(" positive-int ")"] ;
usage = "DISPLAY" | "COMP-3" | "USAGE IS DISPLAY" | "USAGE IS COMP-3" ;
sign = "SIGN LEADING SEPARATE" ;
literal = number | string ;
main = "MAIN." {stmt} "STOP RUN." ;
paragraph = id "." {stmt} "." ;
stmt = move | arithmetic | conditional | perform | open | read | write
       | close | display ;
move = "MOVE" atom "TO" id ;
arithmetic = ("ADD" atom "TO" id | "SUBTRACT" atom "FROM" id
           | "MULTIPLY" atom "BY" id | "DIVIDE" atom "BY" atom "GIVING" id
           | "COMPUTE" id "=" expr) ["ROUNDED"]
           ["ON SIZE ERROR" {stmt}] arithmetic-end ;
arithmetic-end = "END-ADD" | "END-SUBTRACT" | "END-MULTIPLY"
               | "END-DIVIDE" | "END-COMPUTE" ;
expr = term {("+" | "-") term} ; term = factor {("*" | "/") factor} ;
factor = atom | "(" expr ")" ; atom = id | number | string ;
conditional = "IF" condition {stmt} ["ELSE" {stmt}] "END-IF" ;
condition = comparison {("AND" | "OR") comparison} ;
comparison = atom ("=" | "<>" | "<" | "<=" | ">" | ">=") atom ;
perform = "PERFORM" id ["UNTIL" condition] ;
open = "OPEN" ("INPUT" id | "OUTPUT" id) ;
read = "READ" id "AT END" {stmt} "END-READ" ;
write = "WRITE" id ; close = "CLOSE" id ;
display = "DISPLAY" (id | string) {(id | string)} ;
```

Canonical spelling is deliberately narrow; optional COBOL noise words are unsupported unless shown. A later compiler probe may demonstrate this grammar's canonical spelling needs correction; change the contract version with receipts, never silently widen. Arithmetic terminator must match its verb. Arithmetic atoms must be numeric; string atoms are legal only for compatible MOVE/comparisons. Comparisons require matching numeric or alphanumeric operands; no coercion. AND binds tighter than OR, with left associativity; condition grouping, NOT and abbreviated conditions are unsupported. COMPUTE has at most three binary operators across the entire expression; no unary operators except a signed numeric literal. DIVIDE `a BY b GIVING c` means a/b. Multiple operands/receivers, GIVING on other verbs, CORRESPONDING and multiple WRITE targets are refused. Only default ROUNDED is supported; no MODE clause. No nested ON SIZE ERROR arithmetic block recursion (conditional bodies otherwise may nest, subject to source limits).

## Declarations, layout and control

Exactly one input and one output SELECT/FD pair, each with an explicit, distinct two-character PIC X(2) status field in working storage. One fixed-width record per FD; nonempty elementary children. No variable-length/depending clauses. Group names are references only for READ/WRITE record identity; group MOVE/arithmetic is unsupported. Count all elementary data/status fields toward 32; group names do not count. Numeric total digits n+m <=8; 0<=scale m<=4; n>=1. Alphanumeric n is 1..256. External FD fields use DISPLAY only; signed external numbers require SIGN LEADING SEPARATE and occupy digits+1 bytes, unsigned digits bytes, X fields n bytes. External numbers have an implied decimal point, never a physical dot. Internal numeric fields permit DISPLAY or COMP-3; packed storage is not an external codec. Working-storage VALUE must fit exactly, numeric by value, X by ASCII length, with no implicit literal truncation. No implicit REDEFINES of status/RETURN-CODE.

At most eight paragraphs including MAIN; MAIN alone terminates with STOP RUN. Other paragraphs can only be reached by named PERFORM, never by sequential fallthrough: MAIN's STOP RUN precedes their declarations. No paragraph ranges/THRU, recursion or cyclic call graph; no STOP RUN in performed paragraphs. PERFORM UNTIL is test-before and requires a declared finite integer iteration bound in the manifest (1..64), an identified monotone induction field, and a statically checkable update/exit on every path. A runtime cap alone is not proof of boundedness. Missing proof refuses the source. No inline PERFORM or nested paragraph definitions. READ is input-only, WRITE uses the output record, and OPEN/CLOSE must have balanced, valid file-state transitions on every reachable path; no EXTEND/I-O. FILE STATUS checks use ordinary IF. READ AT END handles EOF; NOT AT END is outside v1. DISPLAY emits literals/fields with default newline only; no UPON/NO ADVANCING. `MOVE integer TO RETURN-CODE` is the sole special-register access; manifest declares finite allowed integer return codes 0..255. File-status/error outcomes must be emitted to be observable.

One input case has 0..64 records (zero only for explicit missing/empty scenarios); each nonempty case uses the same declared input record width. Path spelling is fixed as above; reject absolute paths, alternate files, path expressions and source-supplied environment settings. Today/pivot values are explicit integer inputs/constants, never clocks.

## Refusal codes and precedence

Return all safely discoverable diagnostic spans but choose primary code by this ordered stage list, then smallest byte offset, then code lexical order. A refusal is never a successful map with a skipped node.

| Stage | Stable code | Trigger |
|---|---|---|
| bytes | `source_encoding` | non-ASCII/control byte or invalid source line ending |
| bounds | `source_limit` | >200 lines, >32 elementary fields, >8 paragraphs |
| tokens | `unknown_token` | unlexable token, malformed literal/identifier |
| forbidden production | `out_of_subset` | recognized but unlisted COBOL construct |
| syntax | `syntax_error` | incomplete/misordered production, unmatched terminator, trailing tokens |
| declarations | `duplicate_name`, `unresolved_name` | folded duplicate or unknown reference |
| pictures | `bad_picture`, `field_limit` | edited/invalid PIC or digit/scale/width bound |
| representation | `bad_layout_or_sign` | external COMP-3, wrong/missing separate sign, invalid offset/width/status |
| types | `type_mismatch`, `literal_range` | incompatible operand or unrepresentable VALUE |
| arithmetic | `compute_limit` | >3 operators, unsupported arithmetic form |
| flow | `control_flow`, `unbounded_perform` | fallthrough, recursion, unsupported STOP or unproven loop |
| files | `file_contract`, `external_path` | invalid SELECT/FD/state or path contract |
| returns | `return_contract` | undeclared/out-of-range RETURN-CODE assignment |
| completion | `partial_parse` | any unconsumed source after an apparent successful parse |

Always refuse GO TO, CALL, COPY, OCCURS, REDEFINES, level 88, EVALUATE, PERFORM VARYING, DIVIDE REMAINDER, NOT ON SIZE ERROR, edited pictures, COMP/COMP-5/BINARY, ACCEPT, CURRENT-DATE, FUNCTION/intrinsics, clocks, embedded SQL, CICS, DB2/JCL, indexed/relative files and unknown extensions. Inside comments/literals those spellings are data, not executable tokens. Parser implementation and compiler acceptance checks are deferred.

## Pinned compiler and observation contract (unexecuted)

GnuCOBOL 3.2.0: argv `cobc -x -free -std=default -O0 -o <bin> <source>`. Trace build adds `-ftraceall` to unchanged original. No IBM dialect, debug/exception toggles, `-fno-trunc` or `-farithmetic-osvs`. Later authorized builder verifies actual help/guide, records exact package/source checksum, base-image digest, build/version/info, libcob and compiler configuration/default.conf SHA256, argv and runtime config. TZ=UTC, LC_ALL=C, clear ambient COB_* overrides and explicitly record allowed settings. These are required future pins, not an installed-tool receipt.

Expected observations come only from repeated original/changed COBOL execution: exact output-file presence/bytes, stdout/stderr bytes and declared return code, with source/task/case/compiler/config/image hashes. No trimming, epsilon, CRLF/sign normalization or hidden tolerances. Trace is a separate channel and must preserve ordinary observations. Matching uncontrolled crashes never pass. Candidate-independent timeout/crash/nondeterminism quarantines before seal; deterministic handled status/error outcomes stay. Candidate source is never executed on host. See the adopted plan section6 for future containment; no Docker/CI/environment scaffolding or execution is authorized by this contract.
