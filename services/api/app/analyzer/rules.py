from collections import Counter

from app.models import AppMetadata, CodeIndicators, Finding, RiskSummary, Severity

DANGEROUS_PERMISSIONS: dict[str, tuple[str, Severity, int]] = {
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("All-files storage access", Severity.HIGH, 16),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "Package installation access",
        Severity.HIGH,
        16,
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Screen overlay access", Severity.HIGH, 18),
    "android.permission.READ_CALL_LOG": ("Call log access", Severity.HIGH, 16),
    "android.permission.WRITE_CALL_LOG": ("Call log modification", Severity.HIGH, 18),
    "android.permission.SEND_SMS": ("SMS sending access", Severity.HIGH, 16),
    "android.permission.READ_SMS": ("SMS reading access", Severity.HIGH, 16),
    "android.permission.RECORD_AUDIO": ("Microphone access", Severity.MEDIUM, 8),
    "android.permission.CAMERA": ("Camera access", Severity.MEDIUM, 7),
    "android.permission.ACCESS_FINE_LOCATION": ("Precise location access", Severity.MEDIUM, 8),
    "android.permission.READ_CONTACTS": ("Contacts access", Severity.MEDIUM, 7),
    "android.permission.QUERY_ALL_PACKAGES": (
        "Installed application inventory",
        Severity.MEDIUM,
        9,
    ),
}


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    description: str,
    evidence: list[str],
    remediation: str,
    score: int,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence,
        remediation=remediation,
        score=score,
    )


def _application_rules(metadata: AppMetadata) -> list[Finding]:
    findings = []
    config = metadata.application
    if config.debuggable is True:
        findings.append(
            _finding(
                "MANIFEST_DEBUGGABLE",
                "Application is debuggable",
                Severity.HIGH,
                "Manifest",
                "Production applications with debugging enabled expose additional "
                "inspection and control surfaces.",
                ["android:debuggable=true"],
                "Disable debugging in the release build and verify the signed production manifest.",
                18,
            )
        )
    if config.allow_backup is True:
        findings.append(
            _finding(
                "MANIFEST_BACKUP",
                "Application data backup is allowed",
                Severity.MEDIUM,
                "Data protection",
                "Application data may be included in device backup or transfer flows "
                "depending on Android version and policy.",
                ["android:allowBackup=true"],
                "Disable backup or define explicit data extraction rules for sensitive data.",
                8,
            )
        )
    if config.uses_cleartext_traffic is True:
        findings.append(
            _finding(
                "NETWORK_CLEARTEXT",
                "Cleartext network traffic is permitted",
                Severity.HIGH,
                "Network",
                "Unencrypted HTTP traffic can expose credentials and application data "
                "to interception or modification.",
                ["android:usesCleartextTraffic=true"],
                "Require HTTPS and use a restrictive Network Security Configuration.",
                16,
            )
        )
    return findings


def _sdk_rules(metadata: AppMetadata) -> list[Finding]:
    target = metadata.sdk.target
    if target is None:
        return [
            _finding(
                "SDK_TARGET_MISSING",
                "Target SDK is not declared",
                Severity.MEDIUM,
                "Platform",
                "A missing target SDK makes platform security expectations unclear.",
                ["targetSdkVersion not found"],
                "Declare and test against a supported Android target SDK.",
                8,
            )
        ]
    if target < 31:
        return [
            _finding(
                "SDK_TARGET_LEGACY",
                "Target SDK is significantly outdated",
                Severity.HIGH,
                "Platform",
                "Legacy target behavior can bypass security protections introduced "
                "for newer Android applications.",
                [f"targetSdkVersion={target}"],
                "Update dependencies and target a currently supported Android SDK.",
                15,
            )
        ]
    if target < 34:
        return [
            _finding(
                "SDK_TARGET_AGING",
                "Target SDK is outdated",
                Severity.MEDIUM,
                "Platform",
                "The application does not opt into several recent Android security behaviors.",
                [f"targetSdkVersion={target}"],
                "Raise the target SDK after compatibility testing.",
                8,
            )
        ]
    return []


def _permission_rules(metadata: AppMetadata) -> list[Finding]:
    findings = []
    permissions = set(metadata.permissions)
    for permission, (title, severity, score) in DANGEROUS_PERMISSIONS.items():
        if permission in permissions:
            findings.append(
                _finding(
                    f"PERMISSION_{permission.rsplit('.', 1)[-1]}",
                    title,
                    severity,
                    "Permissions",
                    "This sensitive capability increases impact if the application or "
                    "its account is compromised.",
                    [permission],
                    "Remove the permission when unnecessary and request it only at "
                    "the point of use.",
                    score,
                )
            )
    sms_set = {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
    }
    if len(permissions & sms_set) >= 2:
        findings.append(
            _finding(
                "PERMISSION_SMS_COMBINATION",
                "Broad SMS capability combination",
                Severity.CRITICAL,
                "Permissions",
                "Combined SMS reading, receiving, or sending access can enable "
                "interception and unauthorized messages.",
                sorted(permissions & sms_set),
                "Remove unnecessary SMS permissions and use platform-mediated alternatives.",
                28,
            )
        )
    return findings


def _component_rules(metadata: AppMetadata) -> list[Finding]:
    findings = []
    groups = (
        ("activities", metadata.components.activities, Severity.LOW, 3),
        ("services", metadata.components.services, Severity.MEDIUM, 7),
        ("receivers", metadata.components.receivers, Severity.MEDIUM, 7),
        ("providers", metadata.components.providers, Severity.HIGH, 14),
    )
    for label, components, severity, score in groups:
        exposed = [component.name for component in components if component.exported is True]
        if label == "activities" and metadata.main_activity in exposed:
            exposed.remove(metadata.main_activity)
        if exposed:
            findings.append(
                _finding(
                    f"EXPORTED_{label.upper()}",
                    f"Exported {label} detected",
                    severity,
                    "Components",
                    "Exported components can be invoked by other applications and "
                    "require explicit access controls.",
                    exposed,
                    "Confirm each export is required and enforce permissions plus "
                    "strict input validation.",
                    score,
                )
            )
    return findings


def _signing_rules(metadata: AppMetadata) -> list[Finding]:
    signing = metadata.signing
    if not signing.certificates:
        return [
            _finding(
                "SIGNING_CERTIFICATE_MISSING",
                "Signing certificate was not found",
                Severity.HIGH,
                "Signing",
                "The package identity could not be tied to a signing certificate.",
                ["No certificate parsed from APK signing blocks"],
                "Sign the release APK and verify its certificate chain.",
                18,
            )
        ]
    if signing.signed_v1 and not (signing.signed_v2 or signing.signed_v3):
        return [
            _finding(
                "SIGNING_V1_ONLY",
                "APK uses only legacy JAR signing",
                Severity.MEDIUM,
                "Signing",
                "Version 1 signing does not protect every part of the APK in the same "
                "way as modern schemes.",
                ["v1=true", "v2=false", "v3=false"],
                "Enable APK Signature Scheme v2 or newer for release builds.",
                10,
            )
        ]
    return []


def _code_rules(code: CodeIndicators) -> list[Finding]:
    findings = []
    techniques = {indicator.technique: indicator for indicator in code.techniques}
    if code.secrets:
        findings.append(
            _finding(
                "CODE_HARDCODED_SECRET",
                "Potential hardcoded secrets detected",
                Severity.HIGH,
                "Code",
                "Credential-like values embedded in an APK can be recovered by "
                "anyone who obtains the package.",
                [f"{secret.kind} in {secret.source}: {secret.evidence}" for secret in code.secrets],
                "Remove secrets from client code, rotate exposed values, and use "
                "a server-mediated design.",
                18,
            )
        )
    if code.cleartext_urls:
        findings.append(
            _finding(
                "CODE_CLEARTEXT_ENDPOINT",
                "Cleartext endpoints embedded in code",
                Severity.MEDIUM,
                "Network",
                "HTTP endpoints can expose application traffic to interception and modification.",
                code.cleartext_urls,
                "Replace HTTP endpoints with HTTPS and enforce transport security.",
                9,
            )
        )
    if "dynamic_code_loading" in techniques:
        findings.append(
            _finding(
                "CODE_DYNAMIC_LOADING",
                "Dynamic code loading indicators",
                Severity.MEDIUM,
                "Code",
                "Loading code at runtime can bypass review of the original package "
                "and increases supply-chain risk.",
                techniques["dynamic_code_loading"].evidence,
                "Avoid remote or writable-path code loading and verify all "
                "dynamically loaded modules.",
                11,
            )
        )
    if "runtime_command_execution" in techniques:
        findings.append(
            _finding(
                "CODE_RUNTIME_EXEC",
                "Runtime command execution indicators",
                Severity.HIGH,
                "Code",
                "Process execution can provide powerful behavior outside normal "
                "Android application APIs.",
                techniques["runtime_command_execution"].evidence,
                "Remove shell execution or strictly constrain fixed commands and untrusted input.",
                16,
            )
        )
    if "accessibility_service" in techniques:
        findings.append(
            _finding(
                "CODE_ACCESSIBILITY_SERVICE",
                "Accessibility service implementation detected",
                Severity.HIGH,
                "Behavior",
                "Accessibility services can observe interface content and perform "
                "actions across other applications.",
                techniques["accessibility_service"].evidence,
                "Use accessibility APIs only for a clearly disclosed accessibility purpose.",
                16,
            )
        )
    return findings


def run_rules(metadata: AppMetadata, code: CodeIndicators | None = None) -> list[Finding]:
    findings = [
        *_application_rules(metadata),
        *_sdk_rules(metadata),
        *_permission_rules(metadata),
        *_component_rules(metadata),
        *_signing_rules(metadata),
        *_code_rules(code or CodeIndicators()),
    ]
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return sorted(findings, key=lambda finding: (severity_order[finding.severity], finding.rule_id))


def summarize_risk(findings: list[Finding]) -> RiskSummary:
    score = min(100, sum(finding.score for finding in findings))
    rating = (
        "critical"
        if score >= 75
        else "high"
        if score >= 50
        else "moderate"
        if score >= 20
        else "low"
    )
    counts = Counter(finding.severity for finding in findings)
    return RiskSummary(
        score=score,
        rating=rating,
        finding_count=len(findings),
        severity_counts={severity: counts.get(severity, 0) for severity in Severity},
    )
