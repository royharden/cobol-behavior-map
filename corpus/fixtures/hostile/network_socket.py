"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(("192.0.2.1", 9))
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
