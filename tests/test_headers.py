"""Testes dos cabeçalhos de segurança, sem requisições de rede."""

from __future__ import annotations

from sentinela.analyzers.headers import analyze_security_headers
from tests.factories import make_snapshot

_EXPECTED_CODES = {
    "headers.csp",
    "headers.hsts",
    "headers.x_frame_options",
    "headers.x_content_type_options",
    "headers.referrer_policy",
}


def test_cabecalhos_ausentes_geram_achados() -> None:
    findings = analyze_security_headers(make_snapshot())
    assert _EXPECTED_CODES <= {finding.code for finding in findings}


def test_cabecalhos_seguros_nao_geram_alertas() -> None:
    snapshot = make_snapshot(
        {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
    )
    findings = analyze_security_headers(snapshot)
    assert all(finding.status in {"ok", "info"} for finding in findings)
