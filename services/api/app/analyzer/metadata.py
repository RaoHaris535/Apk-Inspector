import hashlib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.models import (
    AppMetadata,
    ComponentInfo,
    ComponentSummary,
    SdkInfo,
    SigningCertificate,
    SigningInfo,
)


class MetadataExtractionError(ValueError):
    """Raised when an APK cannot be parsed as an Android application."""


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _component_exported(apk: Any, kind: str, name: str) -> bool | None:
    try:
        value = apk.get_element(kind, "exported", name)
    except (AttributeError, KeyError, TypeError):
        return None
    if value is None:
        return None
    return str(value).lower() == "true"


def _components(apk: Any, kind: str, getter: str) -> list[ComponentInfo]:
    names = getattr(apk, getter)() or []
    return [
        ComponentInfo(name=name, exported=_component_exported(apk, kind, name))
        for name in sorted(set(names))
    ]


def _certificate_bytes(apk: Any) -> Iterable[bytes]:
    for method_name in (
        "get_certificates_der_v3",
        "get_certificates_der_v2",
        "get_certificates_der_v1",
    ):
        method = getattr(apk, method_name, None)
        if not method:
            continue
        try:
            yield from method() or []
        except (AttributeError, TypeError, ValueError):
            continue


def _certificate_info(der: bytes) -> SigningCertificate:
    sha256 = hashlib.sha256(der).hexdigest().upper()
    sha1 = hashlib.sha1(der, usedforsecurity=False).hexdigest().upper()
    subject = issuer = serial_number = valid_from = valid_until = None
    try:
        certificate = x509.load_der_x509_certificate(der)
        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()
        serial_number = format(certificate.serial_number, "X")
        valid_from = certificate.not_valid_before_utc
        valid_until = certificate.not_valid_after_utc
        sha256 = certificate.fingerprint(hashes.SHA256()).hex().upper()
        sha1 = certificate.fingerprint(hashes.SHA1()).hex().upper()
    except ValueError:
        pass
    return SigningCertificate(
        sha256=sha256,
        sha1=sha1,
        subject=subject,
        issuer=issuer,
        serial_number=serial_number,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _signed(apk: Any, method_name: str) -> bool:
    method = getattr(apk, method_name, None)
    if not method:
        return False
    try:
        return bool(method())
    except (AttributeError, TypeError, ValueError):
        return False


def extract_metadata(
    path: Path,
    apk_factory: Callable[[str], Any] = APK,
) -> AppMetadata:
    try:
        apk = apk_factory(str(path))
        package_name = apk.get_package()
    except Exception as error:
        raise MetadataExtractionError("Android manifest parsing failed.") from error

    if not package_name:
        raise MetadataExtractionError("The APK does not declare a package name.")

    certificates: dict[str, SigningCertificate] = {}
    for der in _certificate_bytes(apk):
        info = _certificate_info(der)
        certificates[info.sha256] = info

    return AppMetadata(
        package_name=package_name,
        app_name=apk.get_app_name() or package_name,
        version_name=apk.get_androidversion_name() or None,
        version_code=apk.get_androidversion_code() or None,
        main_activity=apk.get_main_activity() or None,
        sdk=SdkInfo(
            minimum=_as_int(apk.get_min_sdk_version()),
            target=_as_int(apk.get_target_sdk_version()),
            maximum=_as_int(apk.get_max_sdk_version()),
        ),
        permissions=sorted(set(apk.get_permissions() or [])),
        declared_permissions=sorted(set(apk.get_declared_permissions() or [])),
        components=ComponentSummary(
            activities=_components(apk, "activity", "get_activities"),
            services=_components(apk, "service", "get_services"),
            receivers=_components(apk, "receiver", "get_receivers"),
            providers=_components(apk, "provider", "get_providers"),
        ),
        libraries=sorted(set(apk.get_libraries() or [])),
        signing=SigningInfo(
            signed_v1=_signed(apk, "is_signed_v1"),
            signed_v2=_signed(apk, "is_signed_v2"),
            signed_v3=_signed(apk, "is_signed_v3"),
            certificates=list(certificates.values()),
        ),
    )
