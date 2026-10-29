"""Caller-supplied actual tool artifacts; structural pins never authenticate them."""
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator
from cobolmap.contracts import ArtifactRef, ExecutionPins, FrozenModel, Sha256, canonical_json, sha256

ENVIRONMENT = (("LC_ALL", "C"), ("TZ", "UTC"))
SDK_PATHS = frozenset({
    "entry.py", "cobolmap/__init__.py", "cobolmap/shared/__init__.py",
    "cobolmap/shared/decimal_shim.py", "cobolmap/shared/codec.py", "cobolmap/translate/__init__.py",
    "cobolmap/translate/runtime.py", "cobolmap/translate/errors.py",
})


def exact(model, expected):
    """Reject subclasses and revalidate nested constructed-model bypasses."""
    if type(model) is not expected:
        raise TypeError(f"exact {expected.__name__} required")
    return expected.model_validate(model.model_dump())


class Blob(FrozenModel):
    ref: ArtifactRef
    data: Annotated[bytes, Field(max_length=1048576)]

    @model_validator(mode="after")
    def bind(self) -> Self:
        self.ref.check_bytes(self.data)
        return self


class OracleToolchain(FrozenModel):
    pins: ExecutionPins
    package: ArtifactRef
    compiler_source: ArtifactRef
    build_info: ArtifactRef
    version_info: ArtifactRef
    compiler_info: ArtifactRef
    compiler: ArtifactRef
    compiler_config: ArtifactRef
    runtime_config: ArtifactRef
    libcob: ArtifactRef
    default_conf: ArtifactRef
    environment: tuple[tuple[str, str], ...] = ENVIRONMENT
    trace_framing: ArtifactRef | None = None

    @model_validator(mode="after")
    def bind(self) -> Self:
        if self.pins.compiler_version != "3.2.0" or self.environment != ENVIRONMENT:
            raise ValueError("GnuCOBOL3.2.0 and exact cleared environment required")
        for name in ("compiler", "compiler_config", "runtime_config", "libcob", "default_conf"):
            if getattr(self, name).sha256 != getattr(self.pins, name + "_sha256"):
                raise ValueError("tool artifact/pin mismatch")
        return self


class CandidateToolchain(FrozenModel):
    pins: ExecutionPins
    runtime_version: Annotated[str, Field(min_length=1, max_length=128)]
    runtime: ArtifactRef
    runtime_package: ArtifactRef
    runtime_info: ArtifactRef
    launcher: ArtifactRef
    helper_manifest_sha256: Sha256
    abi: Literal["m10-run-case-v1"] = "m10-run-case-v1"
    environment: tuple[tuple[str, str], ...] = ENVIRONMENT

    @model_validator(mode="after")
    def bind(self) -> Self:
        if self.environment != ENVIRONMENT:
            raise ValueError("exact cleared candidate environment required")
        return self


def helper_digest(helpers: tuple[Blob, ...]) -> str:
    """Closed deterministic manifest, not an SDK authenticity receipt."""
    # Every Blob.ref.path is the logical SDK-relative staging name here.
    ordered = tuple(sorted(helpers, key=lambda blob: blob.ref.path))
    return sha256(b"M10-SDK-v1\0" + b"\0".join(
        canonical_json(blob.ref) for blob in ordered))
