from pathlib import Path

from app.analyzer.metadata import extract_metadata


class FakeApk:
    def __init__(self, _: str) -> None:
        pass

    def get_package(self) -> str:
        return "com.example.safe"

    def get_app_name(self) -> str:
        return "Safe Notes"

    def get_androidversion_name(self) -> str:
        return "2.4.1"

    def get_androidversion_code(self) -> str:
        return "24"

    def get_main_activity(self) -> str:
        return "com.example.safe.MainActivity"

    def get_min_sdk_version(self) -> str:
        return "24"

    def get_target_sdk_version(self) -> str:
        return "35"

    def get_max_sdk_version(self) -> None:
        return None

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.INTERNET"]

    def get_declared_permissions(self) -> list[str]:
        return ["com.example.safe.INTERNAL"]

    def get_activities(self) -> list[str]:
        return ["com.example.safe.MainActivity"]

    def get_services(self) -> list[str]:
        return ["com.example.safe.SyncService"]

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []

    def get_element(self, kind: str, attribute: str, name: str) -> str | None:
        del attribute, name
        return "true" if kind == "activity" else "false"

    def get_libraries(self) -> list[str]:
        return ["org.apache.http.legacy"]

    def get_certificates_der_v3(self) -> list[bytes]:
        return [b"test-certificate"]

    def get_certificates_der_v2(self) -> list[bytes]:
        return [b"test-certificate"]

    def get_certificates_der_v1(self) -> list[bytes]:
        return []

    def is_signed_v1(self) -> bool:
        return False

    def is_signed_v2(self) -> bool:
        return True

    def is_signed_v3(self) -> bool:
        return True


def test_extracts_normalized_application_metadata() -> None:
    metadata = extract_metadata(Path("sample.apk"), apk_factory=FakeApk)

    assert metadata.package_name == "com.example.safe"
    assert metadata.app_name == "Safe Notes"
    assert metadata.sdk.minimum == 24
    assert metadata.sdk.target == 35
    assert metadata.permissions == ["android.permission.INTERNET"]
    assert metadata.components.total == 2
    assert metadata.components.activities[0].exported is True
    assert metadata.components.services[0].exported is False
    assert len(metadata.signing.certificates) == 1
    assert metadata.signing.signed_v3 is True
