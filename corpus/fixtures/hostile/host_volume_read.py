"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    with open("/m10-fixture-markers/host-volume/marker.txt", "rb") as marker:
        marker.read(1)
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
