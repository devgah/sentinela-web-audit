"""Testes dos três formatos de relatório e da API de exportação."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinela.core.models import Severity
from sentinela.reports import (
    DISCLAIMER,
    ReportFormat,
    ScanReport,
    export_report,
    render_html,
    render_markdown,
    render_pdf,
)
from tests.factories import make_finding


def _report() -> ScanReport:
    return ScanReport(
        target="https://exemplo.test/",
        findings=(
            make_finding(code="z.low", severity=Severity.LOW),
            make_finding(code="a.high", severity=Severity.HIGH),
        ),
    )


def test_markdown_agrupa_por_severidade_e_inclui_aviso() -> None:
    text = render_markdown(_report())
    assert DISCLAIMER.splitlines()[0] in text
    assert text.index("### Alto") < text.index("### Baixo")


def test_html_escape_e_csp_offline() -> None:
    report = ScanReport(
        target="https://exemplo.test/",
        findings=(make_finding(title="<script>alert(1)</script>"),),
    )
    html = render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html
    assert "Aviso legal" in html
    assert "autorizados" in html


def test_pdf_e_gerado_em_memoria() -> None:
    assert render_pdf(_report()).startswith(b"%PDF-")


def test_extensoes_reconhecidas() -> None:
    assert ReportFormat.from_suffix(".MD") is ReportFormat.MARKDOWN
    assert ReportFormat.from_suffix("html") is ReportFormat.HTML
    assert ReportFormat.from_suffix(".pdf") is ReportFormat.PDF
    with pytest.raises(ValueError):
        ReportFormat.from_suffix(".txt")


def test_export_report_grava_localmente(tmp_path: Path) -> None:
    destination = tmp_path / "relatorio.pdf"
    written = export_report(_report(), destination)
    assert written.read_bytes().startswith(b"%PDF-")
