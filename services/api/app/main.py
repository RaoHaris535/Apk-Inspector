from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.analyzer.comparison import compare_reports
from app.analyzer.metadata import MetadataExtractionError
from app.analyzer.pipeline import analyze_stored_upload
from app.config import get_settings
from app.ingestion import UploadRejected, ingest_upload
from app.models import AnalysisReport, ComparisonReport, ErrorDetail

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
            return analyze_stored_upload(stored)
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


@app.post("/api/v1/compare", response_model=ComparisonReport, tags=["analysis"])
async def compare(
    file: Annotated[UploadFile, File(description="APK to inspect")],
    reference_file: Annotated[UploadFile, File(description="Trusted reference APK")],
) -> ComparisonReport:
    try:
        with TemporaryDirectory(prefix="apkinspector-compare-") as temporary_directory:
            workspace = Path(temporary_directory)
            submitted_workspace = workspace / "submitted"
            reference_workspace = workspace / "reference"
            submitted_workspace.mkdir()
            reference_workspace.mkdir()
            max_bytes = settings.max_upload_mb * 1024 * 1024
            submitted_upload = await ingest_upload(file, submitted_workspace, max_bytes)
            reference_upload = await ingest_upload(reference_file, reference_workspace, max_bytes)
            submitted = analyze_stored_upload(submitted_upload)
            reference = analyze_stored_upload(reference_upload)
            differences = compare_reports(submitted, reference)
            possible_repackaging = (
                differences.package_name_matches and not differences.signing_certificate_matches
            )
            return ComparisonReport(
                comparison_id=str(uuid4()),
                submitted=submitted,
                reference=reference,
                differences=differences,
                possible_repackaging=possible_repackaging,
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
