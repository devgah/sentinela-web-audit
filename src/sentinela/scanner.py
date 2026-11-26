"""Orquestração local de uma varredura passiva completa."""

from __future__ import annotations

from collections.abc import Callable
from typing import Final
from urllib.parse import urlsplit

from sentinela.analyzers.cookies import analyze_cookies
from sentinela.analyzers.cors import analyze_cors
from sentinela.analyzers.discovery import run_passive_discovery
from sentinela.analyzers.headers import analyze_security_headers
from sentinela.analyzers.tls import analyze_tls
from sentinela.core.errors import TlsInspectionError
from sentinela.core.http_client import fetch
from sentinela.core.models import Finding, HttpSnapshot, Severity, TlsSnapshot
from sentinela.core.tls import inspect_tls
from sentinela.reports.models import ScanReport

ProgressCallback = Callable[[str, int], None]

_TLS_REFERENCES: Final[tuple[str, ...]] = (
    "OWASP Transport Layer Protection Cheat Sheet",
)


def _progress(callback: ProgressCallback | None, message: str, percent: int) -> None:
    """Notifica a interface sobre o andamento, quando houver callback."""
    if callback is not None:
        callback(message, percent)


def _tls_error_finding(error: TlsInspectionError) -> Finding:
    """Registra falha de inspeção sem expor detalhes da exceção."""
    return Finding(
        code="tls.inspection_error",
        title="Não foi possível inspecionar o TLS",
        severity=Severity.INFO,
        status="info",
        message=f"A inspeção local do certificado falhou: {type(error).__name__}.",
        remediation=(
            "Verifique a conectividade com o alvo e tente novamente. A análise "
            "de cabeçalhos permanece válida."
        ),
        references=_TLS_REFERENCES,
    )


def _inspect(snapshot: HttpSnapshot) -> tuple[TlsSnapshot | None, list[Finding]]:
    """Inspeciona TLS somente quando a resposta final é HTTPS."""
    parsed = urlsplit(snapshot.final_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None, []

    try:
        port = parsed.port or 443
    except ValueError:
        return None, []

    try:
        return inspect_tls(parsed.hostname, port), []
    except TlsInspectionError as exc:
        return None, [_tls_error_finding(exc)]


def run_scan(
    target: str,
    progress: ProgressCallback | None = None,
) -> ScanReport:
    """Executa todas as verificações passivas e devolve o relatório.

    A função não faz exploração, não envia payloads e não consulta serviços
    externos: apenas o alvo informado é contactado.
    """
    _progress(progress, "Validando o alvo...", 5)
    snapshot = fetch(target)
    _progress(progress, "Lendo cabeçalhos e redirecionamentos...", 20)

    findings: list[Finding] = []
    findings.extend(analyze_security_headers(snapshot))
    findings.extend(analyze_cookies(snapshot))
    findings.extend(analyze_cors(snapshot))
    _progress(progress, "Analisando cabeçalhos, cookies e CORS...", 40)

    tls_snapshot, tls_errors = _inspect(snapshot)
    findings.extend(tls_errors)
    findings.extend(analyze_tls(tls_snapshot))
    _progress(progress, "Inspecionando TLS localmente...", 65)

    findings.extend(run_passive_discovery(snapshot))
    _progress(progress, "Lendo arquivos públicos e tecnologias...", 90)

    report = ScanReport(
        target=snapshot.requested_url,
        findings=tuple(findings),
        http=snapshot,
        tls=tls_snapshot,
    )
    _progress(progress, "Análise concluída.", 100)
    return report
