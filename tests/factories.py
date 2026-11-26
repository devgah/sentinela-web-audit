"""Fábricas puras para os testes; nenhuma delas acessa a rede."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

from sentinela.core.models import (
    Finding,
    HttpSnapshot,
    HttpTextSnapshot,
    Severity,
    TlsSnapshot,
)


def make_snapshot(
    headers: Mapping[str, str] | None = None,
    *,
    status_code: int = 200,
    url: str = "https://exemplo.test/",
) -> HttpSnapshot:
    """Cria um snapshot HTTP determinístico."""
    normalized = {
        str(name).lower(): str(value) for name, value in (headers or {}).items()
    }
    cookies = tuple(
        str(value)
        for name, value in (headers or {}).items()
        if str(name).lower() == "set-cookie"
    )
    return HttpSnapshot(
        requested_url=url,
        final_url=url,
        status_code=status_code,
        headers=MappingProxyType(normalized),
        set_cookie_headers=cookies,
    )


def make_text(
    body: str,
    *,
    status_code: int = 200,
    url: str = "https://exemplo.test/",
    content_type: str = "text/plain",
) -> HttpTextSnapshot:
    """Cria uma resposta textual já limitada para testes de descoberta."""
    return HttpTextSnapshot(
        response=make_snapshot(status_code=status_code, url=url),
        body=body,
        content_type=content_type,
        truncated=False,
        bytes_read=len(body.encode("utf-8")),
    )


def make_tls(
    *,
    expired: bool = False,
    self_signed: bool = False,
) -> TlsSnapshot:
    """Cria um snapshot TLS com datas estáveis em relação ao presente."""
    now = datetime.now(UTC)
    return TlsSnapshot(
        host="exemplo.test",
        port=443,
        protocol="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        subject="CN=exemplo.test",
        issuer="CN=exemplo.test" if self_signed else "CN=Teste CA",
        serial_number="ABC123",
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1 if expired else 60),
        san=("exemplo.test",),
        is_trusted=not self_signed,
        hostname_matches=True,
        checked_at=now,
    )


def make_finding(
    code: str = "teste.geral",
    severity: Severity = Severity.INFO,
    **overrides: object,
) -> Finding:
    """Cria um achado com valores padrão seguros."""
    values: dict[str, object] = {
        "code": code,
        "title": "Achado de teste",
        "severity": severity,
        "status": "info",
        "message": "Mensagem de teste.",
        "remediation": "Aplicar a correção recomendada.",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]
