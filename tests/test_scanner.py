"""Testes do orquestrador com dependências substituídas por fakes."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from sentinela import scanner
from sentinela.core.models import Finding, Severity
from sentinela.reports.models import ScanReport
from tests.factories import make_snapshot, make_tls


def _discovery_finding() -> Finding:
    return Finding(
        code="discovery.fake",
        title="Descoberta simulada",
        severity=Severity.INFO,
        status="info",
        message="Etapa simulada.",
        remediation="Nenhuma.",
    )


def test_varredura_https_reune_todas_as_etapas(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int]] = []
    progress: Callable[[str, int], None] = (
        lambda message, percent: calls.append((message, percent))
    )
    tls = make_tls()
    monkeypatch.setattr(
        scanner, "fetch", lambda target: make_snapshot(url="https://exemplo.test/")
    )
    monkeypatch.setattr(scanner, "inspect_tls", lambda host, port: tls)
    monkeypatch.setattr(
        scanner, "run_passive_discovery", lambda snapshot: [_discovery_finding()]
    )

    report = scanner.run_scan("https://exemplo.test", progress)

    assert isinstance(report, ScanReport)
    assert report.tls is tls
    assert report.target == "https://exemplo.test/"
    assert calls[-1][1] == 100
    codes = {finding.code for finding in report.findings}
    assert "headers.csp" in codes
    assert "tls.validity" in codes
    assert "discovery.fake" in codes


def test_alvo_http_nao_abre_conexao_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        scanner, "fetch", lambda target: make_snapshot(url="http://exemplo.test/")
    )

    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("inspect_tls não deveria ser chamado para HTTP")

    monkeypatch.setattr(scanner, "inspect_tls", unexpected)
    report = scanner.run_scan("http://exemplo.test")

    assert report.tls is None
    assert any(finding.code == "tls.not_applicable" for finding in report.findings)
