import io
import zipfile

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from app.main import app
from app.models import (
    ApplicationConfig,
    AppMetadata,
    ComponentSummary,
    SdkInfo,
    SigningCertificate,
    SigningInfo,
)

client = TestClient(app)


def make_apk(*, unsafe_path: bool = False, include_manifest: bool = True) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        if include_manifest:
            archive.writestr("AndroidManifest.xml", b"binary-manifest-placeholder")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"safe-content" * 10)
        archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"native")
        if unsafe_path:
            archive.writestr("../escaped.txt", b"unsafe")
    return output.getvalue()


def safe_metadata() -> AppMetadata:
    return AppMetadata(
        package_name="com.example.demo",
        app_name="Demo",
        version_name="1.0",
        version_code="1",
        sdk=SdkInfo(minimum=24, target=35),
        application=ApplicationConfig(debuggable=False, allow_backup=False),
        components=ComponentSummary(),
        signing=SigningInfo(
            signed_v2=True,
            certificates=[SigningCertificate(sha256="A" * 64, sha1="B" * 40)],
        ),
    )


def test_accepts_structurally_valid_apk(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("app.analyzer.pipeline.extract_metadata", lambda _: safe_metadata())
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("demo.apk", make_apk(), "application/vnd.android.package-archive")},
    )

    assert response.status_code == 200
    report = response.json()
    assert report["status"] == "complete"
    assert report["filename"] == "demo.apk"
    assert report["archive"]["dex_files"] == 1
    assert report["archive"]["native_libraries"] == 1
    assert len(report["sha256"]) == 64
    assert report["metadata"]["package_name"] == "com.example.demo"
    assert report["risk"]["rating"] == "low"


def test_rejects_non_apk_extension() -> None:
    response = client.post("/api/v1/analyze", files={"file": ("demo.zip", make_apk())})

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_extension"


def test_rejects_archive_without_manifest() -> None:
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("demo.apk", make_apk(include_manifest=False))},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "missing_manifest"


def test_rejects_path_traversal() -> None:
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("demo.apk", make_apk(unsafe_path=True))},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unsafe_archive_path"


def test_rejects_file_with_fake_apk_name() -> None:
    response = client.post("/api/v1/analyze", files={"file": ("fake.apk", b"not a zip")})

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_apk"
