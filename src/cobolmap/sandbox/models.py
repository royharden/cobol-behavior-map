"""Screening declarations retain commitments, never execution permission."""
from typing import Annotated, Literal, Self
from pydantic import Field, model_validator
from cobolmap.contracts import ArtifactRef, FrozenModel, Identifier, Sha256
from cobolmap.oracle.pins import Blob, CandidateToolchain


class ScreenContext(FrozenModel):
    task_id: Identifier
    program_id: Identifier
    original_source: Blob
    source_filename: Annotated[str, Field(min_length=1, max_length=256)]
    candidate_sha256: Sha256
    toolchain: CandidateToolchain
    helpers: Annotated[tuple[Blob, ...], Field(max_length=8)] = ()
    entry_approval: ArtifactRef | None = None


class ScreenReason(FrozenModel):
    code: Literal[
        "candidate_type", "candidate_limit", "candidate_encoding", "context_missing",
        "context_invalid", "source_invalid", "candidate_pin", "helper_pin", "entry_missing",
        "token_limit", "unsupported_token", "syntax", "ast_limit", "entry_shape",
        "literal_shape", "literal_limit", "plan_shape", "source_pointer",
    ]
    detail: str
    line: int | None = None
    column: int | None = None


class ScreenResult(FrozenModel):
    status: Literal["pending", "refused", "screened"]
    profile: Literal["translator-plan-v1"] = "translator-plan-v1"
    candidate: ArtifactRef | None = None
    context: ScreenContext | None = None
    computed_helper_manifest_sha256: Sha256 | None = None
    reasons: tuple[ScreenReason, ...] = ()
    tokens: int | None = None
    ast_nodes: int | None = None
    ast_depth: int | None = None
    execution_authorized: Literal[False] = False
    containment_verified: Literal[False] = False
    study_admitted: Literal[False] = False

    @model_validator(mode="after")
    def no_authority(self) -> Self:
        if any(value is not False for value in (
                self.execution_authorized, self.containment_verified, self.study_admitted)):
            raise ValueError("screening confers no authority or containment")
        if self.status == "screened" and (self.reasons or self.context is None or self.candidate is None):
            raise ValueError("screened result requires complete commitments and no refusals")
        return self
