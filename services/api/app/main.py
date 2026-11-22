from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.analyzer.metadata import MetadataExtractionError, extract_metadata
from app.analyzer.rules import run_rules, summarize_risk
from app.config import get_settings
from app.ingestion import UploadRejected, ingest_upload
from app.models import AnalysisReport, ErrorDetail

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Explainable static security analysis for Android APK files.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)


@app.get("/api/v1/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "healthy", "service": "apkinspector-api", "version": app.version}


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisReport,
    responses={
        400: {"description": "The upload is not a safe APK"},
        413: {"description": "Upload too large"},
    },
    tags=["analysis"],
)
async def analyze(
    file: Annotated[UploadFile, File(description="Android APK to inspect")],
) -> AnalysisReport:
    try:
        with TemporaryDirectory(prefix="apkinspector-") as temporary_directory:
            stored = await ingest_upload(
                file,
                Path(temporary_directory),
                settings.max_upload_mb * 1024 * 1024,
            )
            metadata = extract_metadata(stored.path)
            findings = run_rules(metadata)
            return AnalysisReport(
                analysis_id=str(uuid4()),
                filename=stored.original_name,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                received_at=datetime.now(UTC),
                archive=stored.archive,
                metadata=metadata,
                findings=findings,
                risk=summarize_risk(findings),
            )
    except UploadRejected as error:
        status_code = 413 if error.code == "file_too_large" else 400
        raise HTTPException(
            status_code=status_code,
            detail=ErrorDetail(code=error.code, message=error.message).model_dump(),
        ) from error
    except MetadataExtractionError as error:
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail(code="invalid_manifest", message=str(error)).model_dump(),
        ) from error
