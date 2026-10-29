"""Inert builder containment fixture; never import or invoke during construction."""

def run_case(input_present, records):
    import os
    import time
    children = []
    for index in range(80):
        child = os.fork()
        if child == 0:
            time.sleep(30)
            os._exit(0)
        children.append(child)
    for child in children:
        os.waitpid(child, 0)
    raise RuntimeError("hostile fixture entry reached completion; no ordinary result supplied")
