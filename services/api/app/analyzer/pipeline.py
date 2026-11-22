from datetime import UTC, datetime
from uuid import uuid4

from app.analyzer.code_scan import scan_code
from app.analyzer.metadata import extract_metadata
from app.analyzer.rules import run_rules, summarize_risk
from app.ingestion import StoredUpload
from app.models import AnalysisReport


def analyze_stored_upload(stored: StoredUpload) -> AnalysisReport:
    metadata = extract_metadata(stored.path)
    code = scan_code(stored.path)
    findings = run_rules(metadata, code)
    return AnalysisReport(
        analysis_id=str(uuid4()),
        filename=stored.original_name,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        received_at=datetime.now(UTC),
        archive=stored.archive,
        metadata=metadata,
        code=code,
        findings=findings,
        risk=summarize_risk(findings),
    )
