"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    import sys
    chunk = "F" * 65536
    for index in range(48):
        sys.stdout.write(chunk)
        sys.stdout.flush()
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
