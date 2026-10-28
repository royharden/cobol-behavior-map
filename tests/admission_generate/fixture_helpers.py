"""Original synthetic DEV units. Fixed native standalone source; never prepare()."""
import hashlib
import importlib.util
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(r"C:\Worktrees\PortfolioBuilder\cobol-behavior-map\DL2-generator\admission\prepare\generate.py")
SOURCE_SHA256 = "4438bb3a481ca5e88d0cba7451e9de4c4a6d613686c67759043a40aff14278a8"

def load_generator():
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise AssertionError("native standalone source pin changed")
    spec = importlib.util.spec_from_file_location("dl2_fixed_native_generator", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

g = load_generator()

def field_document():
    return {"manifest_version": 1, "program_id": "unit-program", "source_sha256": "1" * 64,
            "record_width": 8, "fields": [
                {"name": "N", "pic": "9(2)V9(1)", "usage": "DISPLAY", "sign": "none", "offset": 0, "width": 3, "scale": 1},
                {"name": "S", "pic": "S9(1)V9(1)", "usage": "DISPLAY", "sign": "leading_separate", "offset": 3, "width": 3, "scale": 1},
                {"name": "X", "pic": "X(2)", "usage": "DISPLAY", "sign": "none", "offset": 6, "width": 2, "scale": 0}]}

def loop_recipe(document):
    identity = ["unit-v1", "builder-unit", "unit-program", "unit-task", "loop"]
    return {"manifest_version": 1, "corpus_version": identity[0], "family_id": identity[1],
            "program_id": identity[2], "task_id": identity[3], "partition": identity[4],
            "fields_sha256": g.digest(document), "scenario": "records",
            "records": [{"N": "1.2", "S": "-0.0", "X": "A"}], "boundaries": [],
            "fill": {"algorithm": "sha256-counter-v1", "seed_material": identity,
                     "target_count": 32, "max_records": 1}, "collision_counter": 0}

def refuse_without_fill(test, document, recipe, code, excluded=None):
    # Safety guard: no replacement generator or fabricated output. Any attempt
    # to fill a full partition fails the test before the first draw.
    with patch.object(g, "seeded_case", side_effect=AssertionError("full partition fill forbidden")) as guard:
        with test.assertRaises(g.AdmissionError) as caught:
            g.generate(document, recipe, excluded)
        test.assertEqual(caught.exception.code, code)
        test.assertEqual(caught.exception.stage, "generation")
        test.assertEqual(caught.exception.fields_sha256, g.digest(document))
        test.assertEqual(caught.exception.recipe_sha256, g.digest(recipe))
        guard.assert_not_called()
    return caught.exception
