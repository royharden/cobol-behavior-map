"""Closed containment declarations; no executor or OS enforcement is supplied."""
from typing import Literal
from cobolmap.contracts import ArtifactRef, FrozenModel, Identifier, Sha256


class SandboxPolicy(FrozenModel):
    profile: Literal["m10-isolation-v1"] = "m10-isolation-v1"
    uid: Literal[10001] = 10001
    network: Literal["none"] = "none"
    root_read_only: Literal[True] = True
    cap_drop: Literal["ALL"] = "ALL"
    no_new_privileges: Literal[True] = True
    memory_bytes: Literal[268435456] = 268435456
    cpus: Literal[1] = 1
    pids: Literal[64] = 64
    scratch_bytes: Literal[16777216] = 16777216
    scratch_path: Literal["/work"] = "/work"
    cpu_microseconds: Literal[5000000] = 5000000
    wall_microseconds: Literal[10000000] = 10000000
    output_bytes: Literal[1048576] = 1048576
    host_mounts: tuple[()] = ()
    inherit_environment: Literal[False] = False


class BackendConformance(FrozenModel):
    backend_id: Identifier
    profile: Literal["m10-isolation-v1"]
    role: Literal["oracle", "candidate"]
    image_sha256: Sha256
    policy_sha256: Sha256
    measurement: ArtifactRef
    hostile_fixture_receipt: ArtifactRef | None = None
    # Receipts must be authenticated by the externally designated authority.
    # Fields, hash consistency or protocol membership do not authorize execution.
