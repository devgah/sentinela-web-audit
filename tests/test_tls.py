"""Testes dos analisadores de certificado, sem abrir conexões."""

from __future__ import annotations

from sentinela.analyzers.tls import analyze_tls
from sentinela.core.models import Severity
from tests.factories import make_tls


def test_certificado_expirado_e_alto() -> None:
    findings = analyze_tls(make_tls(expired=True))
    validity = next(finding for finding in findings if finding.code == "tls.validity")
    assert validity.severity is Severity.HIGH
    assert validity.status == "warning"


def test_certificado_autoassinado_e_medio() -> None:
    findings = analyze_tls(make_tls(self_signed=True))
    identity = next(finding for finding in findings if finding.code == "tls.identity")
    assert identity.severity is Severity.MEDIUM
    assert "autoassinado" in identity.title.lower()


def test_sem_tls_retorna_informativo() -> None:
    findings = analyze_tls(None)
    assert len(findings) == 1
    assert findings[0].code == "tls.not_applicable"
