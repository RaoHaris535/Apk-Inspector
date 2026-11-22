import zipfile
from pathlib import Path

from app.analyzer.code_scan import scan_code


def test_scans_dex_indicators_without_extraction(tmp_path: Path) -> None:
    apk_path = tmp_path / "signals.apk"
    dex_content = b"\n".join(
        [
            b"dex\n035\x00",
            b"dalvik/system/DexClassLoader",
            b"java/lang/Runtime;->exec",
            b"http://api.example.test/v1/login",
            b"api_key=super-secret-value-12345",
        ]
    )
    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", dex_content)
        archive.writestr("lib/arm64-v8a/libcrypto.so", b"\x7fELF")

    signals = scan_code(apk_path)

    assert signals.cleartext_urls == ["http://api.example.test/v1/login"]
    assert signals.secrets[0].evidence != "super-secret-value-12345"
    assert {item.technique for item in signals.techniques} == {
        "dynamic_code_loading",
        "runtime_command_execution",
    }
    assert signals.native_libraries[0].architecture == "arm64-v8a"
    assert signals.scanned_files == 2
