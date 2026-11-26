"""Testes de atributos de cookies e redaction de valores."""

from __future__ import annotations

from sentinela.analyzers.cookies import analyze_cookies
from sentinela.core.models import Severity
from tests.factories import make_snapshot


def test_valor_do_cookie_nunca_e_revelado() -> None:
    header = "session=segredoSuperSecreto123; Path=/; HttpOnly; Secure; SameSite=Lax"
    findings = analyze_cookies(make_snapshot({"Set-Cookie": header}))
    text = " ".join(
        finding.message + (finding.evidence or "") for finding in findings
    )
    assert "segredoSuperSecreto123" not in text
    assert "<redacted>" in text


def test_cookie_de_sessao_sem_atributos_gera_medio() -> None:
    findings = analyze_cookies(make_snapshot({"Set-Cookie": "session=abc; Path=/"}))
    by_code = {finding.code: finding for finding in findings}
    assert by_code["cookie.session.httponly"].severity is Severity.MEDIUM
    assert by_code["cookie.session.secure"].status == "missing"
    assert by_code["cookie.session.samesite"].severity is Severity.MEDIUM
