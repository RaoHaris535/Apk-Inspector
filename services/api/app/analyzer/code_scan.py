import re
import zipfile
from pathlib import Path

from app.models import CodeIndicators, NativeLibraryInfo, SecretIndicator, TechniqueIndicator

MAX_SCANNED_FILE_BYTES = 40 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 160 * 1024 * 1024
MAX_RESULTS_PER_TYPE = 40
TEXT_EXTENSIONS = {".xml", ".json", ".txt", ".properties", ".js", ".html", ".yml", ".yaml"}

URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
AWS_KEY_PATTERN = re.compile(rb"AKIA[0-9A-Z]{16}")
GENERIC_SECRET_PATTERN = re.compile(
    rb"(?i)(?:api[_-]?key|secret|token|password)[\x20\t]*[:=][\x20\t]*[\"']?([A-Za-z0-9_./+=-]{10,120})"
)

TECHNIQUE_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "dynamic_code_loading": (
        b"dalvik/system/DexClassLoader",
        b"dalvik/system/PathClassLoader",
        b"dalvik/system/InMemoryDexClassLoader",
    ),
    "runtime_command_execution": (b"java/lang/Runtime;->exec", b"java/lang/ProcessBuilder"),
    "native_code_loading": (b"java/lang/System;->loadLibrary", b"java/lang/System;->load"),
    "accessibility_service": (
        b"android/accessibilityservice/AccessibilityService",
        b"android.permission.BIND_ACCESSIBILITY_SERVICE",
    ),
    "device_administration": (b"android/app/admin/DeviceAdminReceiver",),
    "reflection": (b"java/lang/reflect/Method;->invoke", b"java/lang/Class;->forName"),
}


def _clean_url(raw: bytes) -> str:
    return raw.decode("utf-8", errors="ignore").rstrip(".,);]}\"'")


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "••••••••"
    return f"{value[:4]}…{value[-4:]}"


def _scan_bytes(
    data: bytes,
    source: str,
    urls: set[str],
    secrets: dict[tuple[str, str], SecretIndicator],
    techniques: dict[str, set[str]],
) -> None:
    for match in URL_PATTERN.finditer(data):
        if len(urls) >= MAX_RESULTS_PER_TYPE:
            break
        urls.add(_clean_url(match.group(0)))

    for match in AWS_KEY_PATTERN.finditer(data):
        value = match.group(0).decode("ascii")
        secrets[("AWS access key", value)] = SecretIndicator(
            kind="AWS access key", evidence=_redact(value), source=source
        )
    for match in GENERIC_SECRET_PATTERN.finditer(data):
        value = match.group(1).decode("utf-8", errors="ignore")
        secrets[("Potential hardcoded secret", value)] = SecretIndicator(
            kind="Potential hardcoded secret", evidence=_redact(value), source=source
        )

    for technique, signatures in TECHNIQUE_SIGNATURES.items():
        for signature in signatures:
            if signature in data:
                techniques.setdefault(technique, set()).add(
                    signature.decode("utf-8", errors="replace")
                )


def _native_library(entry: zipfile.ZipInfo) -> NativeLibraryInfo:
    parts = entry.filename.split("/")
    architecture = parts[1] if len(parts) > 2 else "unknown"
    return NativeLibraryInfo(
        path=entry.filename,
        architecture=architecture,
        size_bytes=entry.file_size,
    )


def scan_code(path: Path) -> CodeIndicators:
    urls: set[str] = set()
    secrets: dict[tuple[str, str], SecretIndicator] = {}
    techniques: dict[str, set[str]] = {}
    native_libraries: list[NativeLibraryInfo] = []
    total_scanned = 0
    scanned_files = 0

    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.filename.startswith("lib/") and entry.filename.endswith(".so"):
                native_libraries.append(_native_library(entry))

            suffix = Path(entry.filename).suffix.lower()
            should_scan = suffix == ".dex" or suffix in TEXT_EXTENSIONS
            if not should_scan or entry.file_size > MAX_SCANNED_FILE_BYTES:
                continue
            if total_scanned + entry.file_size > MAX_TOTAL_SCAN_BYTES:
                break
            data = archive.read(entry)
            total_scanned += len(data)
            scanned_files += 1
            _scan_bytes(data, entry.filename, urls, secrets, techniques)

    ordered_urls = sorted(urls)[:MAX_RESULTS_PER_TYPE]
    return CodeIndicators(
        urls=ordered_urls,
        cleartext_urls=[url for url in ordered_urls if url.lower().startswith("http://")],
        secrets=list(secrets.values())[:MAX_RESULTS_PER_TYPE],
        techniques=[
            TechniqueIndicator(technique=name, evidence=sorted(evidence))
            for name, evidence in sorted(techniques.items())
        ],
        native_libraries=sorted(native_libraries, key=lambda library: library.path),
        scanned_files=scanned_files,
    )
