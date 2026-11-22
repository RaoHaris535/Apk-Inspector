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


class SecretIndicator(BaseModel):
    kind: str
    evidence: str
    source: str


class TechniqueIndicator(BaseModel):
    technique: str
    evidence: list[str] = Field(default_factory=list)


class NativeLibraryInfo(BaseModel):
    path: str
    architecture: str
    size_bytes: int = Field(ge=0)


class CodeIndicators(BaseModel):
    urls: list[str] = Field(default_factory=list)
    cleartext_urls: list[str] = Field(default_factory=list)
    secrets: list[SecretIndicator] = Field(default_factory=list)
    techniques: list[TechniqueIndicator] = Field(default_factory=list)
    native_libraries: list[NativeLibraryInfo] = Field(default_factory=list)
    scanned_files: int = Field(ge=0, default=0)


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
    code: CodeIndicators = Field(default_factory=CodeIndicators)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskSummary


class ComparisonDiff(BaseModel):
    identical_file: bool
    package_name_matches: bool
    signing_certificate_matches: bool
    added_permissions: list[str] = Field(default_factory=list)
    removed_permissions: list[str] = Field(default_factory=list)
    added_components: list[str] = Field(default_factory=list)
    removed_components: list[str] = Field(default_factory=list)
    added_urls: list[str] = Field(default_factory=list)
    removed_urls: list[str] = Field(default_factory=list)
    added_native_libraries: list[str] = Field(default_factory=list)
    removed_native_libraries: list[str] = Field(default_factory=list)
    risk_score_delta: int


class ComparisonReport(BaseModel):
    comparison_id: str
    status: Literal["complete"] = "complete"
    submitted: AnalysisReport
    reference: AnalysisReport
    differences: ComparisonDiff
    possible_repackaging: bool


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    detail: ErrorDetail
