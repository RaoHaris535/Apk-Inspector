import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from fastapi import UploadFile

from app.models import ArchiveSummary

CHUNK_SIZE = 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250
APK_MAGIC = b"PK\x03\x04"
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class UploadRejected(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class StoredUpload:
    path: Path
    original_name: str
    size_bytes: int
    sha256: str
    archive: ArchiveSummary


def safe_filename(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise UploadRejected("invalid_filename", "The upload must have a valid filename.")
    basename = Path(filename.replace("\\", "/")).name
    normalized = SAFE_NAME.sub("-", basename).strip(".-")
    if not normalized.lower().endswith(".apk"):
        raise UploadRejected("invalid_extension", "Only Android .apk files are supported.")
    return normalized[:160]


async def store_upload(upload: UploadFile, destination: Path, max_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    first_chunk = True

    with destination.open("wb") as output:
        while chunk := await upload.read(CHUNK_SIZE):
            if first_chunk:
                first_chunk = False
                if not chunk.startswith(APK_MAGIC):
                    raise UploadRejected(
                        "invalid_apk", "The uploaded file is not a valid APK archive."
                    )
            total += len(chunk)
            if total > max_bytes:
                raise UploadRejected(
                    "file_too_large",
                    f"The APK exceeds the {max_bytes // (1024 * 1024)} MB upload limit.",
                )
            digest.update(chunk)
            output.write(chunk)

    if total == 0:
        raise UploadRejected("empty_file", "The uploaded APK is empty.")
    return total, digest.hexdigest()


def _is_unsafe_path(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return path.is_absolute() or ".." in path.parts


def inspect_archive(path: Path) -> ArchiveSummary:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise UploadRejected(
                    "archive_too_complex", "The APK contains too many archive entries."
                )

            names = {entry.filename for entry in entries}
            if "AndroidManifest.xml" not in names:
                raise UploadRejected(
                    "missing_manifest", "The archive does not contain AndroidManifest.xml."
                )
            if any(_is_unsafe_path(entry.filename) for entry in entries):
                raise UploadRejected(
                    "unsafe_archive_path", "The APK contains an unsafe archive path."
                )

            uncompressed = sum(entry.file_size for entry in entries)
            compressed = sum(entry.compress_size for entry in entries)
            if uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise UploadRejected(
                    "archive_too_large", "The APK expands beyond the safe analysis limit."
                )
            if compressed and uncompressed / compressed > MAX_COMPRESSION_RATIO:
                raise UploadRejected(
                    "suspicious_compression", "The APK has a suspicious compression ratio."
                )

            dex_files = sum(
                entry.filename.startswith("classes") and entry.filename.endswith(".dex")
                for entry in entries
            )
            native_libraries = sum(
                entry.filename.startswith("lib/") and entry.filename.endswith(".so")
                for entry in entries
            )
            return ArchiveSummary(
                entry_count=len(entries),
                compressed_bytes=compressed,
                uncompressed_bytes=uncompressed,
                dex_files=dex_files,
                native_libraries=native_libraries,
            )
    except zipfile.BadZipFile as error:
        raise UploadRejected(
            "invalid_apk", "The uploaded file is not a readable APK archive."
        ) from error


async def ingest_upload(upload: UploadFile, workspace: Path, max_bytes: int) -> StoredUpload:
    filename = safe_filename(upload.filename)
    target = workspace / "application.apk"
    try:
        size_bytes, sha256 = await store_upload(upload, target, max_bytes)
        archive = inspect_archive(target)
        return StoredUpload(
            path=target,
            original_name=filename,
            size_bytes=size_bytes,
            sha256=sha256,
            archive=archive,
        )
    finally:
        await upload.close()
