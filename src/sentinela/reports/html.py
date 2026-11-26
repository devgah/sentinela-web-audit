"""Renderizador de relatórios em HTML offline com autoescape."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from sentinela.core.models import Severity
from sentinela.reports.models import (
    DISCLAIMER,
    PASSIVE_SCOPE,
    RISK_BY_SEVERITY,
    STATUS_LABELS,
    ScanReport,
)

_ENVIRONMENT = Environment(
    loader=PackageLoader("sentinela.reports", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(report: ScanReport) -> str:
    """Gera um HTML autocontido, sem scripts e sem recursos externos."""
    template = _ENVIRONMENT.get_template("report.html.j2")
    interpretation = (
        "Valores de risco descrevem o impacto potencial de cada categoria. "
        "A presença de um achado informativo não indica vulnerabilidade."
    )
    return template.render(
        report=report,
        grouped=report.findings_by_severity,
        counts=report.counts_by_severity,
        severities=list(Severity),
        disclaimer_lines=DISCLAIMER.splitlines(),
        scope=PASSIVE_SCOPE,
        risk_by_severity=RISK_BY_SEVERITY,
        status_labels=STATUS_LABELS,
        generated_at=report.formatted_generated_at,
        interpretation=interpretation,
    )
