from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ArchiveSummary(BaseModel):
    entry_count: int = Field(ge=0)
    compressed_bytes: int = Field(ge=0)
    uncompressed_bytes: int = Field(ge=0)
    dex_files: int = Field(ge=0)
    native_libraries: int = Field(ge=0)


class IngestionResult(BaseModel):
    analysis_id: str
    status: Literal["accepted"] = "accepted"
    filename: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    received_at: datetime
    archive: ArchiveSummary


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    detail: ErrorDetail
