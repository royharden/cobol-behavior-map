"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    chunk = b"F" * 65536
    with open("/work/m10-fixture-scratch.bin", "wb") as marker:
        for index in range(320):
            marker.write(chunk)
            marker.flush()
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
