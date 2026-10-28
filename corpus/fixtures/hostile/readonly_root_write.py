"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    with open("/m10-fixture-markers/root-write.txt", "wb") as marker:
        marker.write(b"F")
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
