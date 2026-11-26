"""Geração local de relatórios em Markdown, HTML e PDF."""

from sentinela.reports.exporter import (
    ReportFormat,
    export_report,
    render_report,
)
from sentinela.reports.html import render_html
from sentinela.reports.markdown import render_markdown
from sentinela.reports.models import (
    DISCLAIMER,
    PASSIVE_SCOPE,
    RISK_BY_SEVERITY,
    STATUS_LABELS,
    ScanReport,
)
from sentinela.reports.pdf import render_pdf

__all__ = [
    "DISCLAIMER",
    "PASSIVE_SCOPE",
    "RISK_BY_SEVERITY",
    "STATUS_LABELS",
    "ReportFormat",
    "ScanReport",
    "export_report",
    "render_html",
    "render_markdown",
    "render_pdf",
    "render_report",
]
