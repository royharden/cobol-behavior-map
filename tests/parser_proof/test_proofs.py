"""Original builder parser-data regressions. No COBOL/candidate execution.

Proof dictionaries are unsigned parser input, NOT admitted ProgramManifest,
compiler truth, actual observations, receipts or independent evaluation data.
"""
import copy
import hashlib
import re
import unittest

from cobolmap.parse import ParseRefusal, parse

FILENAME = "builder-proof.cbl"
HEADER = '''IDENTIFICATION DIVISION.
PROGRAM-ID. PROOFCASE.
ENVIRONMENT DIVISION.
INPUT-OUTPUT SECTION.
FILE-CONTROL.
SELECT INFILE ASSIGN TO "input.dat" ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS IN-STATUS.
SELECT OUTFILE ASSIGN TO "output.dat" ORGANIZATION IS LINE SEQUENTIAL FILE STATUS IS OUT-STATUS.
DATA DIVISION.
FILE SECTION.
FD INFILE.
01 IN-REC.
05 IN-N PIC 9(2).
05 IN-TEXT PIC X(1).
FD OUTFILE.
01 OUT-REC.
05 OUT-N PIC 9(2).
WORKING-STORAGE SECTION.
01 IN-STATUS PIC X(2) VALUE "00".
01 OUT-STATUS PIC X(2) VALUE "00".
01 IN-OPENED PIC X(1) VALUE "N".
01 OUT-OPENED PIC X(1) VALUE "N".
01 WIDE-FLAG PIC X(2) VALUE "NN".
01 MARK PIC X(1) VALUE "N".
01 I PIC 9(2) VALUE 0.
01 J PIC 9(2) VALUE 0.
PROCEDURE DIVISION.
MAIN.
'''


def source(main, paragraphs=(), *, header=HEADER):
    text = header + main + "\nSTOP RUN.\n"
    for name, body in paragraphs:
        text += name + ".\n" + body + "\n.\n"
    return text


def digest(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def span(text, marker, occurrence=0):
    positions = [match.start() for match in re.finditer(re.escape(marker), text)]
    if len(positions) <= occurrence:
        raise AssertionError("builder span marker missing: " + marker)
    start = positions[occurrence]
    return dict(file=FILENAME, line=text[:start].count("\n") + 1,
                byte_start=start, byte_end=start + len(marker))


def proof(text, *, initial="0", step="1", limit="4", relation=">=", cap=4,
          field="I", initializer=None, updates=("ADD 1 TO I END-ADD",), paragraph="LOOP-BODY"):
    condition = field + " " + relation + " " + limit
    call = "PERFORM " + paragraph + " UNTIL " + condition
    update_spans = []
    for marker in set(updates):
        update_spans.extend(span(text, marker, index) for index, _ in enumerate(re.finditer(re.escape(marker), text)))
    update_spans.sort(key=lambda item: item["byte_start"])
    return dict(source_sha256=digest(text), loops=[dict(
        target=span(text, call), paragraph=paragraph, induction_field=field,
        initial=initial, step=step, relation=relation, limit=limit, max_iterations=cap,
        proof=dict(initialization_span=span(text, initializer or "MOVE " + initial + " TO " + field),
                   update_spans=update_spans, exit_span=span(text, condition)))])


def loop_case(*, initial="0", limit="4", cap=4, relation=">=", step="1", body=None, before="", main=None):
    update = "ADD " + step + " TO I END-ADD"
    body = update if body is None else body
    main = ("MOVE " + initial + " TO I\n" + before + "\nPERFORM LOOP-BODY UNTIL I " + relation + " " + limit
            if main is None else main)
    text = source(main, (("LOOP-BODY", body),))
    return text, proof(text, initial=initial, step=step, limit=limit, relation=relation,
                       cap=cap, updates=(update,))


OPEN_INPUT = '''OPEN INPUT INFILE
IF IN-STATUS = "00" MOVE "Y" TO IN-OPENED END-IF
'''
CLOSE_INPUT = 'IF IN-OPENED = "Y" CLOSE INFILE END-IF'
READ = 'READ INFILE AT END MOVE "E" TO MARK END-READ'


class ParserProofVectors(unittest.TestCase):
    def accepted(self, text, manifest=None):
        result = parse(text, filename=FILENAME, manifest=manifest)
        self.assertEqual(result.source, text)
        self.assertEqual(result.source_sha256, digest(text))
        return result

    def refused(self, text, manifest=None, code="unbounded_perform"):
        with self.assertRaises(ParseRefusal) as caught:
            parse(text, filename=FILENAME, manifest=manifest)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.span.source_sha256, digest(text))
        self.assertEqual(caught.exception.span.filename, FILENAME)
        return caught.exception

    def test_test_before_zero_iterations_does_not_visit_unsafe_body(self):
        body = "CLOSE INFILE\nADD 1 TO I END-ADD"
        zero, declaration = loop_case(initial="4", limit="4", cap=1, body=body)
        result = self.accepted(zero, declaration)
        self.assertEqual(result.paragraphs[0].statements[1].args["max_iterations"], 1)
        entered, declaration = loop_case(initial="3", limit="4", cap=1, body=body)
        self.refused(entered, declaration, "file_contract")

    def test_64_actual_iterations_fit_but_63_cap_refuses(self):
        text, declaration = loop_case(limit="64", cap=64)
        self.accepted(text, declaration)
        too_small = copy.deepcopy(declaration)
        too_small["loops"][0]["max_iterations"] = 63
        self.refused(text, too_small)

    def test_declared_cap_zero_bool_and_65_refuse_without_expansion(self):
        text, declaration = loop_case()
        for cap in (0, True, 65):
            changed = copy.deepcopy(declaration)
            changed["loops"][0]["max_iterations"] = cap
            self.refused(text, changed)

    def test_descending_integer_loop_and_wrong_direction_proof(self):
        text, declaration = loop_case(initial="4", limit="0", cap=4, relation="<=", step="-1")
        self.accepted(text, declaration)
        wrong = copy.deepcopy(declaration)
        wrong["loops"][0]["step"] = "1"
        self.refused(text, wrong)

    def test_zero_step_and_declared_update_mismatch_refuse(self):
        text, declaration = loop_case()
        for step in ("0", "2"):
            changed = copy.deepcopy(declaration)
            changed["loops"][0]["step"] = step
            self.refused(text, changed)

    def test_proof_list_missing_duplicate_wrong_source_and_closed_entry(self):
        text, declaration = loop_case()
        self.accepted(text, declaration)
        mutations = [None, dict(source_sha256=digest(text), loops=[]),
                     dict(declaration, source_sha256=digest(text + "\n")),
                     dict(declaration, loops=declaration["loops"] * 2)]
        changed = copy.deepcopy(declaration)
        changed["loops"][0]["unknown_proof_field"] = "not a proof"
        mutations.append(changed)
        for changed in mutations:
            self.refused(text, changed)

    def test_induction_field_binding_is_to_actual_exit_reference(self):
        text, declaration = loop_case()
        changed = copy.deepcopy(declaration)
        changed["loops"][0]["induction_field"] = "J"
        self.refused(text, changed)
        changed["loops"][0]["induction_field"] = "MISSING-FIELD"
        self.refused(text, changed, "unresolved_name")

    def test_each_native_target_initial_update_exit_span_must_resolve(self):
        text, declaration = loop_case()
        for label in ("target", "initialization_span", "update_spans", "exit_span"):
            changed = copy.deepcopy(declaration)
            entry = changed["loops"][0]
            pointer = entry["target"] if label == "target" else entry["proof"][label]
            if label == "update_spans":
                pointer = pointer[0]
            pointer["byte_end"] += 1
            self.refused(text, changed)

    def test_missing_update_and_wrong_exit_relation_are_not_annotations(self):
        text, declaration = loop_case()
        changed = copy.deepcopy(declaration)
        changed["loops"][0]["proof"]["update_spans"] = []
        self.refused(text, changed)
        changed = copy.deepcopy(declaration)
        changed["loops"][0]["relation"] = ">"
        self.refused(text, changed)

    def test_initialization_must_dominate_call_not_just_exist_in_source(self):
        main = "IF IN-N > 0 MOVE 0 TO I END-IF\nPERFORM LOOP-BODY UNTIL I >= 4"
        text, declaration = loop_case(main=main)
        self.refused(text, declaration)
        text, declaration = loop_case(before="MOVE 1 TO I")
        self.refused(text, declaration)

    def test_value_initializer_is_not_a_dominating_move(self):
        text = source("PERFORM LOOP-BODY UNTIL I >= 4", (("LOOP-BODY", "ADD 1 TO I END-ADD"),))
        # Independent raw span intentionally points at VALUE declaration, not a MOVE.
        declaration = proof(text, initializer="I PIC 9(2) VALUE 0")
        self.refused(text, declaration)

    def test_called_initializer_returns_known_value_unreached_one_does_not(self):
        paragraphs = (("INIT-I", "MOVE 0 TO I"), ("LOOP-BODY", "ADD 1 TO I END-ADD"))
        text = source("PERFORM INIT-I\nPERFORM LOOP-BODY UNTIL I >= 4", paragraphs)
        self.accepted(text, proof(text))
        uncalled = source("PERFORM LOOP-BODY UNTIL I >= 4", paragraphs)
        self.refused(uncalled, proof(uncalled))

    def test_every_body_path_requires_same_nonzero_step(self):
        body = "IF IN-N > 0 ADD 1 TO I END-ADD ELSE ADD 1 TO I END-ADD END-IF"
        text, declaration = loop_case(limit="1", cap=1, body=body)
        self.accepted(text, declaration)
        body = "IF IN-N > 0 ADD 1 TO I END-ADD END-IF"
        text, declaration = loop_case(limit="1", cap=1, body=body)
        self.refused(text, declaration)

    def test_numeric_progression_overflow_refuses_near_fitting_pair(self):
        text, declaration = loop_case(initial="98", limit="99", cap=1)
        self.accepted(text, declaration)
        text, declaration = loop_case(initial="99", limit="100", cap=1)
        self.refused(text, declaration)

    def test_literal_spelling_and_raw_crlf_proof_bindings_are_exact(self):
        text, declaration = loop_case(initial="000")
        self.accepted(text, declaration)
        changed = copy.deepcopy(declaration)
        changed["loops"][0]["initial"] = "0"
        self.refused(text, changed)
        crlf = text.replace("\n", "\r\n")
        self.refused(crlf, declaration)
        rebound = proof(crlf, initial="000")
        self.accepted(crlf, rebound)

    def test_unreached_loop_still_needs_source_bound_syntactic_proof(self):
        text = source("", (("UNUSED", "MOVE 0 TO I\nPERFORM LOOP-BODY UNTIL I >= 4"),
                           ("LOOP-BODY", "ADD 1 TO I END-ADD")))
        self.refused(text)
        self.accepted(text, proof(text))  # Syntactic proof only; body remains unreachable.

    def test_open_flag_overwrite_and_unknown_copy_invalidate_cleanup(self):
        for overwrite in ('MOVE "N" TO IN-OPENED', 'MOVE IN-TEXT TO IN-OPENED'):
            text = source(OPEN_INPUT + overwrite + "\n" + CLOSE_INPUT)
            self.refused(text, code="file_contract")

    def test_overwriting_status_cannot_manufacture_successful_open(self):
        text = source('OPEN INPUT INFILE\nMOVE "00" TO IN-STATUS\nIF IN-STATUS = "00" CLOSE INFILE END-IF')
        self.refused(text, code="file_contract")

    def test_read_eof_second_read_guard_and_forged_status_pair(self):
        text = source(OPEN_INPUT + 'IF IN-OPENED = "Y"\n' + READ
            + '\nIF IN-STATUS = "00"\n' + READ + '\nEND-IF\nEND-IF\n' + CLOSE_INPUT)
        self.accepted(text)
        for between in ("", 'MOVE "00" TO IN-STATUS\nIF IN-STATUS = "00"'):
            second = READ if not between else between + "\n" + READ + "\nEND-IF"
            text = source(OPEN_INPUT + 'IF IN-OPENED = "Y"\n' + READ + "\n" + second + '\nEND-IF\n' + CLOSE_INPUT)
            self.refused(text, code="file_contract")

    def test_reopen_clears_prior_read_exhaustion_without_failed_open_cleanup(self):
        text = source('OPEN INPUT INFILE\nIF IN-STATUS = "00"\n' + READ
            + '\nCLOSE INFILE\nOPEN INPUT INFILE\nIF IN-STATUS = "00"\n' + READ
            + '\nCLOSE INFILE\nEND-IF\nEND-IF')
        self.accepted(text)

    def test_write_status_invalidation_needs_independent_open_flag_cleanup(self):
        bad = source('OPEN OUTPUT OUTFILE\nIF OUT-STATUS = "00"\nWRITE OUT-REC\n'
                     'IF OUT-STATUS = "00" CLOSE OUTFILE END-IF\nEND-IF')
        self.refused(bad, code="file_contract")
        good = source('OPEN OUTPUT OUTFILE\nIF OUT-STATUS = "00" MOVE "Y" TO OUT-OPENED END-IF\n'
                      'IF OUT-OPENED = "Y" WRITE OUT-REC END-IF\nIF OUT-OPENED = "Y" CLOSE OUTFILE END-IF')
        self.accepted(good)

    def test_file_bindings_and_and_or_flags_do_not_cross_authorize_io(self):
        prefix = OPEN_INPUT + 'OPEN OUTPUT OUTFILE\nIF OUT-STATUS = "00" MOVE "Y" TO OUT-OPENED END-IF\n'
        suffix = "\n" + CLOSE_INPUT + '\nIF OUT-OPENED = "Y" CLOSE OUTFILE END-IF'
        good = source(prefix + 'IF IN-OPENED = "Y" AND OUT-OPENED = "Y" WRITE OUT-REC END-IF' + suffix)
        self.accepted(good)
        bad = source(prefix + 'IF IN-OPENED = "Y" OR OUT-OPENED = "Y" WRITE OUT-REC END-IF' + suffix)
        self.refused(bad, code="file_contract")

    def test_alpha_exclusion_copy_preserves_width_but_truncation_drops_it(self):
        template = ('OPEN INPUT INFILE\nIF IN-STATUS <> "00"\nIF IN-STATUS <> "Y"\n'
                    'MOVE IN-STATUS TO {target}\nIF {target} = "Y" CLOSE INFILE END-IF\n'
                    'END-IF\nEND-IF\nIF IN-STATUS = "00" CLOSE INFILE END-IF')
        self.accepted(source(template.format(target="WIDE-FLAG")))
        self.refused(source(template.format(target="MARK")), code="file_contract")

    def test_two_performed_open_cleanup_cycles_need_flag_reset_on_each_call(self):
        close = ("CLEANUP", CLOSE_INPUT)
        main = "PERFORM ACQUIRE\nPERFORM CLEANUP\nPERFORM ACQUIRE\nPERFORM CLEANUP"
        good = source(main, (("ACQUIRE", 'MOVE "N" TO IN-OPENED\n' + OPEN_INPUT), close))
        self.accepted(good)
        bad = source(main, (("ACQUIRE", OPEN_INPUT), close))
        self.refused(bad, code="file_contract")

    def test_unreachable_indirect_recursion_is_still_refused(self):
        text = source('IF IN-OPENED = "Y" PERFORM ALPHA-P END-IF',
                      (("ALPHA-P", "PERFORM BETA-P"), ("BETA-P", "PERFORM ALPHA-P")))
        self.refused(text, code="control_flow")
        safe = source("PERFORM ALPHA-P", (("ALPHA-P", "PERFORM BETA-P"), ("BETA-P", 'DISPLAY "builder"')))
        self.accepted(safe)

    def test_performed_return_code_requires_closed_declared_integer_set(self):
        text = source("PERFORM SET-RETURN", (("SET-RETURN", "MOVE 7 TO RETURN-CODE"),))
        declaration = dict(source_sha256=digest(text), loops=[], allowed_return_codes=(0, 7))
        self.accepted(text, declaration)
        for codes in ((7, 0), (0, True, 7), (0, 3)):
            self.refused(text, dict(declaration, allowed_return_codes=codes), "return_contract")

    def test_small_256_path_boundary_refuses_next_expansion(self):
        branch = 'IF IN-N > 0 MOVE "A" TO MARK ELSE MOVE "B" TO MARK END-IF\n'
        self.accepted(source(branch * 8))
        error = self.refused(source(branch * 9), code="file_contract")
        self.assertIn("path limit256", error.message)

    def test_full_cumulative_100k_visit_exhaustion_remains_unexercised(self):
        self.skipTest("Native parse has no public smaller proof-budget parameter; full100000-visit/DAG stress excluded by r10. Guard reviewed as source, not runtime-covered.")


if __name__ == "__main__":
    unittest.main()
