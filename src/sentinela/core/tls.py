"""Inspeção TLS local do certificado apresentado pelo alvo.

A conexão de leitura usa CERT_NONE apenas para obter o certificado mesmo quando
ele é inválido. Uma segunda conexão com o contexto padrão do sistema verifica
cadeia e hostname. Nenhuma verificação de HTTP é relaxada.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Final

from cryptography import x509
from cryptography.x509.oid import NameOID

from sentinela.core.errors import TlsInspectionError
from sentinela.core.models import TlsSnapshot

DEFAULT_TLS_TIMEOUT: Final[float] = 5.0

_NAME_LABELS: Final[dict[NameOID, str]] = {
    NameOID.COMMON_NAME: "CN",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
}


def _as_utc(value: datetime) -> datetime:
    """Garante datetime timezone-aware em UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _name_to_string(name: x509.Name) -> str:
    """Serializa um Distinguished Name de forma legível."""
    parts: list[str] = []
    for attribute in name:
        label = _NAME_LABELS.get(attribute.oid, attribute.oid.dotted_string)
        parts.append(f"{label}={attribute.value}")
    return ", ".join(parts)


def _common_names(certificate: x509.Certificate) -> tuple[str, ...]:
    """Extrai Common Names do subject para fallback de hostname."""
    return tuple(
        attribute.value
        for attribute in certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
    )


def _subject_alt_names(certificate: x509.Certificate) -> tuple[str, ...]:
    """Extrai entradas DNS e IP da extensão Subject Alternative Name."""
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return ()

    values = list(extension.get_values_for_type(x509.DNSName))
    values.extend(str(value) for value in extension.get_values_for_type(x509.IPAddress))
    return tuple(values)


def _hostname_matches(
    host: str,
    san: tuple[str, ...],
    common_names: tuple[str, ...],
) -> bool:
    """Verifica hostname contra SAN, com fallback restrito para CN."""
    target = host.lower().rstrip(".")

    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    if target_ip is not None:
        for entry in san:
            try:
                if ipaddress.ip_address(entry) == target_ip:
                    return True
            except ValueError:
                continue
        return False

    for entry in san:
        candidate = entry.lower().rstrip(".")
        if candidate == target:
            return True
        if candidate.startswith("*.") and target.endswith(candidate[1:]):
            if target.count(".") == candidate.count("."):
                return True

    if not san:
        return any(value.lower().rstrip(".") == target for value in common_names)

    return False


def _validate_chain(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
    """Usa o contexto confiável do sistema para validar cadeia e hostname."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                tls_socket.getpeercert(binary_form=True)
        return True, None
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", None) or str(exc)
        return False, message
    except ssl.SSLError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    except OSError as exc:
        raise TlsInspectionError(
            f"Não foi possível conectar em {host}:{port}: {type(exc).__name__}."
        ) from exc


def _fetch_peer(
    host: str, port: int, timeout: float
) -> tuple[bytes, str, str | None]:
    """Lê certificado, protocolo e cipher apresentados pelo servidor."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)
                if not certificate_der:
                    raise TlsInspectionError(
                        f"O servidor {host}:{port} não apresentou certificado."
                    )
                cipher = tls_socket.cipher()
                protocol = tls_socket.version() or "desconhecido"
                return certificate_der, protocol, cipher[0] if cipher else None
    except (ssl.SSLError, OSError) as exc:
        raise TlsInspectionError(
            f"Falha ao inspecionar TLS de {host}:{port}: {type(exc).__name__}."
        ) from exc


def inspect_tls(
    host: str,
    port: int = 443,
    timeout: float = DEFAULT_TLS_TIMEOUT,
) -> TlsSnapshot:
    """Inspeciona o TLS de um host localmente e retorna dados estruturados."""
    normalized_host = host.strip().rstrip(".")
    if not normalized_host:
        raise TlsInspectionError("Host TLS vazio.")
    if not 1 <= port <= 65535:
        raise TlsInspectionError("Porta TLS inválida.")

    is_trusted, validation_error = _validate_chain(normalized_host, port, timeout)
    certificate_der, protocol, cipher = _fetch_peer(normalized_host, port, timeout)
    certificate = x509.load_der_x509_certificate(certificate_der)

    san = _subject_alt_names(certificate)
    names = _common_names(certificate)

    return TlsSnapshot(
        host=normalized_host,
        port=port,
        protocol=protocol,
        cipher=cipher,
        subject=_name_to_string(certificate.subject),
        issuer=_name_to_string(certificate.issuer),
        serial_number=format(certificate.serial_number, "x").upper(),
        not_before=_as_utc(
            getattr(certificate, "not_valid_before_utc", certificate.not_valid_before)
        ),
        not_after=_as_utc(
            getattr(certificate, "not_valid_after_utc", certificate.not_valid_after)
        ),
        san=san,
        is_trusted=is_trusted,
        hostname_matches=_hostname_matches(normalized_host, san, names),
        validation_error=validation_error,
    )
