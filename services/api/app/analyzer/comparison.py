from app.models import AnalysisReport, ComparisonDiff


def _component_names(report: AnalysisReport) -> set[str]:
    components = report.metadata.components
    return {
        component.name
        for group in (
            components.activities,
            components.services,
            components.receivers,
            components.providers,
        )
        for component in group
    }


def _certificate_fingerprints(report: AnalysisReport) -> set[str]:
    return {certificate.sha256 for certificate in report.metadata.signing.certificates}


def _native_library_paths(report: AnalysisReport) -> set[str]:
    return {library.path for library in report.code.native_libraries}


def compare_reports(submitted: AnalysisReport, reference: AnalysisReport) -> ComparisonDiff:
    submitted_permissions = set(submitted.metadata.permissions)
    reference_permissions = set(reference.metadata.permissions)
    submitted_components = _component_names(submitted)
    reference_components = _component_names(reference)
    submitted_urls = set(submitted.code.urls)
    reference_urls = set(reference.code.urls)
    submitted_native = _native_library_paths(submitted)
    reference_native = _native_library_paths(reference)

    submitted_certificates = _certificate_fingerprints(submitted)
    reference_certificates = _certificate_fingerprints(reference)
    certificate_matches = bool(submitted_certificates) and (
        submitted_certificates == reference_certificates
    )

    return ComparisonDiff(
        identical_file=submitted.sha256 == reference.sha256,
        package_name_matches=(submitted.metadata.package_name == reference.metadata.package_name),
        signing_certificate_matches=certificate_matches,
        added_permissions=sorted(submitted_permissions - reference_permissions),
        removed_permissions=sorted(reference_permissions - submitted_permissions),
        added_components=sorted(submitted_components - reference_components),
        removed_components=sorted(reference_components - submitted_components),
        added_urls=sorted(submitted_urls - reference_urls),
        removed_urls=sorted(reference_urls - submitted_urls),
        added_native_libraries=sorted(submitted_native - reference_native),
        removed_native_libraries=sorted(reference_native - submitted_native),
        risk_score_delta=submitted.risk.score - reference.risk.score,
    )
