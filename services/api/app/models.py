from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class ArchiveSummary(BaseModel):
    entry_count: int = Field(ge=0)
    compressed_bytes: int = Field(ge=0)
    uncompressed_bytes: int = Field(ge=0)
    dex_files: int = Field(ge=0)
    native_libraries: int = Field(ge=0)


class SdkInfo(BaseModel):
    minimum: int | None = None
    target: int | None = None
    maximum: int | None = None


class ApplicationConfig(BaseModel):
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None


class ComponentInfo(BaseModel):
    name: str
    exported: bool | None = None


class ComponentSummary(BaseModel):
    activities: list[ComponentInfo] = Field(default_factory=list)
    services: list[ComponentInfo] = Field(default_factory=list)
    receivers: list[ComponentInfo] = Field(default_factory=list)
    providers: list[ComponentInfo] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(
            len(items) for items in (self.activities, self.services, self.receivers, self.providers)
        )


class SigningCertificate(BaseModel):
    sha256: str
    sha1: str
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class SigningInfo(BaseModel):
    signed_v1: bool = False
    signed_v2: bool = False
    signed_v3: bool = False
    certificates: list[SigningCertificate] = Field(default_factory=list)


class AppMetadata(BaseModel):
    package_name: str
    app_name: str
    version_name: str | None = None
    version_code: str | None = None
    main_activity: str | None = None
    sdk: SdkInfo
    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    permissions: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    components: ComponentSummary
    libraries: list[str] = Field(default_factory=list)
    signing: SigningInfo


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    remediation: str
    score: int = Field(ge=0, le=40)


class RiskSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    rating: Literal["low", "moderate", "high", "critical"]
    finding_count: int = Field(ge=0)
    severity_counts: dict[Severity, int]


class IngestionResult(BaseModel):
    analysis_id: str
    status: Literal["accepted"] = "accepted"
    filename: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    received_at: datetime
    archive: ArchiveSummary


class AnalysisReport(IngestionResult):
    status: Literal["complete"] = "complete"
    metadata: AppMetadata
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskSummary


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    detail: ErrorDetail
