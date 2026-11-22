from datetime import UTC, datetime

from app.analyzer.comparison import compare_reports
from app.models import (
    AnalysisReport,
    AppMetadata,
    ArchiveSummary,
    CodeIndicators,
    ComponentInfo,
    ComponentSummary,
    NativeLibraryInfo,
    RiskSummary,
    SdkInfo,
    Severity,
    SigningCertificate,
    SigningInfo,
)


def report(*, modified: bool) -> AnalysisReport:
    return AnalysisReport(
        analysis_id="modified" if modified else "reference",
        filename="app.apk",
        size_bytes=100,
        sha256=("a" if modified else "b") * 64,
        received_at=datetime.now(UTC),
        archive=ArchiveSummary(
            entry_count=3,
            compressed_bytes=50,
            uncompressed_bytes=100,
            dex_files=1,
            native_libraries=1,
        ),
        metadata=AppMetadata(
            package_name="com.example.app",
            app_name="Example",
            sdk=SdkInfo(minimum=24, target=35),
            permissions=["android.permission.INTERNET"]
            + (["android.permission.READ_SMS"] if modified else []),
            components=ComponentSummary(
                activities=[ComponentInfo(name="com.example.app.MainActivity", exported=True)],
                services=[ComponentInfo(name="com.example.app.ExtraService")] if modified else [],
            ),
            signing=SigningInfo(
                signed_v2=True,
                certificates=[
                    SigningCertificate(
                        sha256=("C" if modified else "D") * 64,
                        sha1="E" * 40,
                    )
                ],
            ),
        ),
        code=CodeIndicators(
            urls=["https://example.test"] + (["http://added.example.test"] if modified else []),
            native_libraries=[
                NativeLibraryInfo(
                    path="lib/arm64-v8a/libapp.so", architecture="arm64-v8a", size_bytes=10
                )
            ],
        ),
        findings=[],
        risk=RiskSummary(
            score=40 if modified else 10,
            rating="moderate" if modified else "low",
            finding_count=0,
            severity_counts={severity: 0 for severity in Severity},
        ),
    )


def test_compares_identity_permissions_components_and_code() -> None:
    differences = compare_reports(report(modified=True), report(modified=False))

    assert differences.package_name_matches is True
    assert differences.signing_certificate_matches is False
    assert differences.added_permissions == ["android.permission.READ_SMS"]
    assert differences.added_components == ["com.example.app.ExtraService"]
    assert differences.added_urls == ["http://added.example.test"]
    assert differences.risk_score_delta == 30
