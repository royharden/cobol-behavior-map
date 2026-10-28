"""Only fixed native preparation modules and untrusted builder metadata."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import patch

ROOT=Path(r"C:\Worktrees\PortfolioBuilder\cobol-behavior-map\DL2-generator")
PINS={"generate":"4438bb3a481ca5e88d0cba7451e9de4c4a6d613686c67759043a40aff14278a8",
      "generator_adapter":"f92e72db4a4e2471bd326f96ae641685539adbd0ef6387ba7f605ba3206eb4ac",
      "generator_continuation":"f796cb274d3f5410794ea8f9696c9ea1ecdc27cdbc6ddc9a55c6cb389883ee11"}

def load_native():
    name="dl2_fixed_prepare"
    package=types.ModuleType(name);package.__path__=[str(ROOT/"admission/prepare")]
    sys.modules[name]=package
    loaded={}
    for stem,digest in PINS.items():
        path=ROOT/"admission/prepare"/(stem+".py")
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise AssertionError("native source pin changed")
        spec=importlib.util.spec_from_file_location(name+"."+stem,path)
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
        spec.loader.exec_module(module);loaded[stem]=module
    return loaded

native=load_native();g=native["generate"];a=native["generator_adapter"];c=native["generator_continuation"]

def binding(panel="unchanged"):
    raw=b"original unit metadata, not COBOL\n"
    original=hashlib.sha256(raw).hexdigest()
    return {"task_id":"unit-task","program_id":"unit-program","family_id":"builder-unit",
            "split":"dev","panel":panel,"original_sha256":original,
            "oracle_source_sha256":original,"change_sha256":None}

def incomplete_artifacts():
    # Shape markers are deliberately not recipes, cases, manifests or receipts.
    # Never inspect/fill an actual verification partition.
    result={role:{"path":"unit/"+role,"raw_bytes":b"{}"} for role in sorted(a.REQUIRED)}
    result["source"]["raw_bytes"]=b"original unit metadata, not COBOL\n"
    result["generator"]["raw_bytes"]=(ROOT/"admission/prepare/generate.py").read_bytes()
    result["case_spec"]["raw_bytes"]=(ROOT/"admission/specs/GENERATOR.md").read_bytes()
    result["family_spec"]["raw_bytes"]=(ROOT/"admission/specs/FAMILY.md").read_bytes()
    return result

def adapter_refuses(test,code,b,artifacts,expected=PINS["generate"]):
    with test.assertRaises(g.AdmissionError) as caught:
        a.adapt_task(b,{},artifacts,expected_generator_sha256=expected)
    test.assertEqual((caught.exception.code,caught.exception.stage),(code,"transport_adapter"))
    return caught.exception

def continuation_refuses(test,code,recipe,previous,accepted=None,quarantine=None,excluded=()):
    # Deliberately malformed predecessor metadata only. No closed receipt/history
    # is synthesized and no fabricated case or full partition can be returned.
    fields={"manifest_version":1,"program_id":"unit-program","source_sha256":"1"*64,
            "record_width":1,"fields":[{"name":"X","pic":"X(1)","usage":"DISPLAY",
            "sign":"none","offset":0,"width":1,"scale":0}]}
    with patch.object(c,"seeded_case",side_effect=AssertionError("continuation fill forbidden")) as guard:
        with test.assertRaises(g.AdmissionError) as caught:
            c.resume(fields,recipe,previous,[] if accepted is None else accepted,
                     [] if quarantine is None else quarantine,excluded)
        test.assertEqual((caught.exception.code,caught.exception.stage),(code,"continuation"))
        test.assertEqual(caught.exception.fields_sha256,g.digest(fields))
        test.assertEqual(caught.exception.recipe_sha256,g.digest(recipe))
        guard.assert_not_called()
    return caught.exception
