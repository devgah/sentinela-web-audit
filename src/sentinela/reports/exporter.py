"""API única de renderização e exportação local de relatórios."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from sentinela.reports.html import render_html
from sentinela.reports.markdown import render_markdown
from sentinela.reports.models import ScanReport
from sentinela.reports.pdf import render_pdf


class ReportFormat(str, Enum):
    """Formatos de saída suportados."""

    MARKDOWN = "md"
    HTML = "html"
    PDF = "pdf"

    @classmethod
    def from_suffix(cls, suffix: str) -> ReportFormat:
        """Resolve o formato a partir de uma extensão de arquivo."""
        value = suffix.strip().lower().lstrip(".")
        aliases: dict[str, ReportFormat] = {
            "md": cls.MARKDOWN,
            "markdown": cls.MARKDOWN,
            "htm": cls.HTML,
            "html": cls.HTML,
            "pdf": cls.PDF,
        }
        try:
            return aliases[value]
        except KeyError as exc:
            supported = ", ".join(sorted(aliases))
            raise ValueError(
                f"Formato de relatório não suportado: {suffix!r}. "
                f"Use um destes: {supported}."
            ) from exc


def render_report(report: ScanReport, report_format: ReportFormat) -> bytes:
    """Renderiza o relatório em bytes prontos para gravação local."""
    if report_format is ReportFormat.PDF:
        return render_pdf(report)
    text = (
        render_markdown(report)
        if report_format is ReportFormat.MARKDOWN
        else render_html(report)
    )
    return text.encode("utf-8")


def export_report(
    report: ScanReport,
    destination: str | Path,
    report_format: ReportFormat | None = None,
) -> Path:
    """Grava o relatório no caminho escolhido pelo usuário.

    O formato é inferido da extensão quando não informado explicitamente.
    Nenhum dado é enviado para fora do dispositivo.
    """
    path = Path(destination).expanduser()
    chosen = report_format or ReportFormat.from_suffix(path.suffix)
    payload = render_report(report, chosen)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path
