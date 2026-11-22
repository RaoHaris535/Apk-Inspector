from app.analyzer.rules import run_rules, summarize_risk
from app.models import (
    ApplicationConfig,
    AppMetadata,
    ComponentInfo,
    ComponentSummary,
    SdkInfo,
    Severity,
    SigningCertificate,
    SigningInfo,
)


def metadata_with_risks() -> AppMetadata:
    return AppMetadata(
        package_name="com.example.risky",
        app_name="Risky Demo",
        main_activity="com.example.risky.MainActivity",
        sdk=SdkInfo(minimum=21, target=28),
        application=ApplicationConfig(
            debuggable=True,
            allow_backup=True,
            uses_cleartext_traffic=True,
        ),
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        components=ComponentSummary(
            activities=[ComponentInfo(name="com.example.risky.MainActivity", exported=True)],
            providers=[ComponentInfo(name="com.example.risky.DataProvider", exported=True)],
        ),
        signing=SigningInfo(
            signed_v1=True,
            certificates=[SigningCertificate(sha256="A" * 64, sha1="B" * 40)],
        ),
    )


def test_rules_explain_high_impact_configuration() -> None:
    findings = run_rules(metadata_with_risks())
    rule_ids = {finding.rule_id for finding in findings}

    assert "MANIFEST_DEBUGGABLE" in rule_ids
    assert "NETWORK_CLEARTEXT" in rule_ids
    assert "PERMISSION_SMS_COMBINATION" in rule_ids
    assert "EXPORTED_PROVIDERS" in rule_ids
    assert "EXPORTED_ACTIVITIES" not in rule_ids
    assert findings[0].severity == Severity.CRITICAL


def test_score_is_capped_and_counts_severities() -> None:
    findings = run_rules(metadata_with_risks())
    summary = summarize_risk(findings)

    assert summary.score == 100
    assert summary.rating == "critical"
    assert summary.finding_count == len(findings)
    assert summary.severity_counts[Severity.CRITICAL] == 1
