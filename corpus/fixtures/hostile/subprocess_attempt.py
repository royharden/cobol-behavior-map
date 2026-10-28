"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    import subprocess
    subprocess.run(["/m10-fixture-markers/bin/fixture-child"], check=True)
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
