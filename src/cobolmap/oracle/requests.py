"""Pure structured argv/staging planning. No filesystem or execution operations."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from cobolmap.contracts import (
    ArtifactRef, CaseBundle, FrozenModel, Sha256, TaskBinding, canonical_json, sha256,
)
from .isolation import SandboxPolicy
from .pins import Blob, CandidateToolchain, OracleToolchain, SDK_PATHS, exact, helper_digest

Codes = Annotated[tuple[Annotated[int, Field(ge=0, le=255)], ...], Field(min_length=1, max_length=256)]


class OracleRequest(FrozenModel):
    task: TaskBinding
    source: Blob
    case: CaseBundle
    toolchain: OracleToolchain
    purpose: Literal["preparation", "study"]
    authorization: ArtifactRef
    allowed_return_codes: Codes = (0,)
    trace: bool = False

    @model_validator(mode="after")
    def bind(self) -> Self:
        if self.source.ref != self.task.oracle_source:
            raise ValueError("exact task oracle source required")
        if len(self.source.data) > 65536 or not self.source.data or not self.source.data.isascii():
            raise ValueError("bounded ASCII compiler source required")
        if self.trace and (self.task.panel != "unchanged" or self.toolchain.trace_framing is None):
            raise ValueError("trace requires unchanged original and approved framing reference")
        if tuple(sorted(set(self.allowed_return_codes))) != self.allowed_return_codes or self.allowed_return_codes[0] != 0:
            raise ValueError("sorted unique return codes including0 required")
        if self.purpose == "preparation" and self.task.split != "dev":
            raise ValueError("preparation restricted to dev/probe task scope")
        return self


class CandidateRequest(FrozenModel):
    task: TaskBinding
    candidate: Blob
    helpers: Annotated[tuple[Blob, ...], Field(min_length=8, max_length=8)]
    case: CaseBundle
    toolchain: CandidateToolchain
    purpose: Literal["preparation", "study"]
    authorization: ArtifactRef
    allowed_return_codes: Codes = (0,)

    @model_validator(mode="after")
    def bind(self) -> Self:
        paths = [blob.ref.path for blob in self.helpers]
        if len(set(paths)) != len(paths) or set(paths) != SDK_PATHS:
            raise ValueError("exact approved SDK/entry staging closure required")
        if (helper_digest(self.helpers) != self.toolchain.helper_manifest_sha256
                or next(b.ref for b in self.helpers if b.ref.path == "entry.py") != self.toolchain.launcher
                or next(b.ref.sha256 for b in self.helpers if b.ref.path == "cobolmap/shared/decimal_shim.py") != self.toolchain.pins.shim_sha256):
            raise ValueError("launcher/shim/helper manifest mismatch")
        if len(self.candidate.data) > 65536 or not self.candidate.data:
            raise ValueError("bounded candidate bytes required")
        if tuple(sorted(set(self.allowed_return_codes))) != self.allowed_return_codes or self.allowed_return_codes[0] != 0:
            raise ValueError("sorted unique return codes including0 required")
        if self.purpose == "preparation" and self.task.split != "dev":
            raise ValueError("preparation restricted to dev/probe task scope")
        return self


class StageFile(FrozenModel):
    guest_path: str
    data: bytes
    sha256: Sha256
    read_only: Literal[True] = True


class Command(FrozenModel):
    phase: Literal["compile", "run"]
    argv: tuple[str, ...]
    cwd: Literal["/work"] = "/work"


class ExecutionPlan(FrozenModel):
    request: OracleRequest | CandidateRequest
    role: Literal["oracle", "candidate"]
    policy: SandboxPolicy
    staging: tuple[StageFile, ...]
    commands: tuple[Command, ...]
    environment: tuple[tuple[str, str], ...]
    stdin: bytes
    output_path: Literal["/work/output.dat"] = "/work/output.dat"
    input_present: bool
    abi: Literal["line-sequential-v1", "m10-run-case-v1"]

    @property
    def plan_sha256(self) -> str:
        return sha256(canonical_json(self))


def prepare_request(request: OracleRequest | CandidateRequest) -> ExecutionPlan:
    if type(request) not in (OracleRequest, CandidateRequest):
        raise TypeError("exact oracle/candidate request required")
    # Revalidation returns a detached canonical value, closing constructed bypasses.
    request = exact(request, type(request))
    stages = []
    def stage(path: str, data: bytes) -> None:
        stages.append(StageFile(guest_path=path, data=data, sha256=sha256(data)))
    if type(request) is OracleRequest:
        stage("/stage/program.cbl", request.source.data)
        if request.case.input_present:
            stage("/work/input.dat", request.case.file_bytes())
        argv = ("/opt/gnucobol/bin/cobc", "-x", "-free", "-std=default", "-O0")
        if request.trace:
            argv += ("-ftraceall",)
        commands = (Command(phase="compile", argv=argv + ("-o", "/work/oracle", "/stage/program.cbl")),
                    Command(phase="run", argv=("/work/oracle",)))
        role, stdin, abi = "oracle", b"", "line-sequential-v1"
    else:
        stage("/stage/candidate.py", request.candidate.data)
        for blob in sorted(request.helpers, key=lambda item: item.ref.path):
            stage("/stage/sdk/" + blob.ref.path, blob.data)
        commands = (Command(phase="run", argv=("/opt/python/bin/python3", "-I", "-B", "/stage/sdk/entry.py")),)
        role, stdin, abi = "candidate", canonical_json(request.case), "m10-run-case-v1"
    return ExecutionPlan(request=request, role=role, policy=SandboxPolicy(),
                         staging=tuple(stages), commands=commands,
                         environment=request.toolchain.environment, stdin=stdin,
                         input_present=request.case.input_present, abi=abi)
