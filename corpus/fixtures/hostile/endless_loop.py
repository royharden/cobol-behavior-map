"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    while True:
        pass
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
