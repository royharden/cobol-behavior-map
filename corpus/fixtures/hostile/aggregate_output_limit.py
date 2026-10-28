"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    import sys
    chunk = "F" * 65536
    for index in range(12):
        sys.stdout.write(chunk)
        sys.stdout.flush()
        sys.stderr.write(chunk)
        sys.stderr.flush()
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
