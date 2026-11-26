"""Renderizador de relatórios em PDF gerado inteiramente no dispositivo."""

from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Flowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from sentinela.core.models import Severity
from sentinela.reports.models import (
    DISCLAIMER,
    PASSIVE_SCOPE,
    RISK_BY_SEVERITY,
    STATUS_LABELS,
    ScanReport,
)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.HIGH: "#b42318",
    Severity.MEDIUM: "#9a6700",
    Severity.LOW: "#0969da",
    Severity.INFO: "#57606a",
}

_REPLACEMENTS: dict[str, str] = {
    "—": "-",
    "–": "-",
    "…": "...",
    "•": "-",
    "→": "->",
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
    "≤": "<=",
    "≥": ">=",
}


def _txt(value: object | None) -> str:
    """Converte texto dinâmico para conteúdo seguro em Paragraph do ReportLab."""
    if value is None:
        return "-"
    text = str(value)
    for old, new in _REPLACEMENTS.items():
        text = text.replace(old, new)
    text = " ".join(text.split())
    text = text.encode("latin-1", "replace").decode("latin-1")
    return xml_escape(text)


def _labeled(label: str, value: object, style: ParagraphStyle) -> Paragraph:
    """Cria um par rótulo/valor com o valor já escapado."""
    return Paragraph(f"<b>{_txt(label)}:</b> {_txt(value)}", style)


def _styles() -> dict[str, ParagraphStyle]:
    """Estilos baseados nos padrões do ReportLab, sem fontes externas."""
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "Corpo",
        parent=base["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=4,
    )
    return {
        "title": ParagraphStyle(
            "TituloRelatorio",
            parent=base["Title"],
            fontSize=18,
            leading=22,
            spaceAfter=4,
        ),
        "heading": ParagraphStyle(
            "Secao",
            parent=base["Heading2"],
            fontSize=12,
            leading=15,
            spaceBefore=10,
            spaceAfter=5,
        ),
        "finding": ParagraphStyle(
            "Achado",
            parent=base["Heading3"],
            fontSize=10,
            leading=13,
            spaceBefore=6,
            spaceAfter=3,
        ),
        "body": body,
        "small": ParagraphStyle(
            "Pequeno",
            parent=body,
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#555555"),
        ),
        "muted": ParagraphStyle(
            "Suave",
            parent=body,
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#57606a"),
        ),
    }


def _table_style() -> TableStyle:
    """Aplica o mesmo estilo discreto às tabelas do relatório."""
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f6f8fa")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def _metadata_table(report: ScanReport, styles: dict[str, ParagraphStyle]) -> Table:
    """Monta a tabela com os metadados da execução."""
    data = [
        ["Campo", "Valor"],
        ["Alvo", Paragraph(_txt(report.target), styles["small"])],
        ["Gerado em", _txt(report.formatted_generated_at)],
        ["Versao da ferramenta", _txt(report.tool_version)],
        ["Risco geral", _txt(report.risk_label)],
        ["Total de achados", str(report.total_findings)],
    ]
    table = Table(data, colWidths=[42 * mm, 126 * mm])
    table.setStyle(_table_style())
    return table


def _summary_table(report: ScanReport) -> Table:
    """Monta a tabela de contagem por severidade."""
    counts = report.counts_by_severity
    data = [["Severidade", "Achados"]]
    data.extend(
        [severity.label, str(counts[severity])]
        for severity in sorted(Severity, key=lambda item: item.rank, reverse=True)
    )
    table = Table(data, colWidths=[84 * mm, 84 * mm])
    table.setStyle(_table_style())
    return table


def _build_story(report: ScanReport) -> list[Flowable]:
    """Monta a sequência de elementos do PDF."""
    styles = _styles()
    story: list[Flowable] = [
        Paragraph("Relatorio de auditoria passiva", styles["title"]),
        Paragraph(
            "Sentinela Web Audit - analise local, passiva e defensiva",
            styles["muted"],
        ),
        Spacer(1, 6),
        Paragraph("Aviso legal", styles["heading"]),
    ]
    story.extend(Paragraph(_txt(line), styles["small"]) for line in DISCLAIMER.splitlines())
    story.extend(
        [
            Spacer(1, 6),
            Paragraph("Contexto da execucao", styles["heading"]),
            _metadata_table(report, styles),
            Spacer(1, 6),
            Paragraph("Escopo passivo permitido", styles["heading"]),
        ]
    )
    story.extend(Paragraph(f"- {_txt(item)}", styles["body"]) for item in PASSIVE_SCOPE)
    story.append(
        Paragraph(
            "Nenhuma exploracao, payload, forca bruta ou modificacao do alvo foi "
            "realizada. Valores de cookies nao sao gravados neste relatorio.",
            styles["body"],
        )
    )
    story.extend(
        [
            Paragraph("Resumo por severidade", styles["heading"]),
            _summary_table(report),
            Paragraph("Achados", styles["heading"]),
        ]
    )

    if not report.findings:
        story.append(
            Paragraph("Nenhum achado foi registrado nesta execucao.", styles["body"])
        )

    for severity, group in report.findings_by_severity:
        story.append(
            Paragraph(f"{_txt(severity.label)} ({len(group)})", styles["heading"])
        )
        story.append(Paragraph(_txt(RISK_BY_SEVERITY[severity]), styles["muted"]))
        for finding in group:
            title = (
                f'<font color="{_SEVERITY_COLORS[severity]}"><b>'
                f"[{_txt(finding.code)}]</b></font> {_txt(finding.title)}"
            )
            story.append(Paragraph(title, styles["finding"]))
            story.append(
                _labeled(
                    "Status",
                    STATUS_LABELS.get(finding.status, finding.status),
                    styles["body"],
                )
            )
            story.append(
                _labeled("Risco", RISK_BY_SEVERITY[severity], styles["body"])
            )
            story.append(_labeled("Diagnostico", finding.message, styles["body"]))
            if finding.evidence:
                story.append(_labeled("Evidencia", finding.evidence, styles["body"]))
            story.append(_labeled("Remediacao", finding.remediation, styles["body"]))
            references = (
                "; ".join(finding.references) if finding.references else "-"
            )
            story.append(_labeled("Referencias", references, styles["small"]))
            story.append(Spacer(1, 5))

    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "Relatorio gerado localmente. Nenhum dado foi enviado a servicos externos.",
            styles["small"],
        )
    )
    return story


def _footer(canvas: Canvas, doc: SimpleDocTemplate) -> None:
    """Desenha rodapé com aviso curto e número da página."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(18 * mm, 12 * mm, "Sentinela Web Audit - relatorio local e passivo")
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Pagina {doc.page}")
    canvas.restoreState()


def render_pdf(report: ScanReport) -> bytes:
    """Gera um PDF em memória, sem gravar arquivos ou contatar serviços."""
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title="Relatorio de auditoria passiva",
        author="Sentinela Web Audit",
        subject="Auditoria passiva local",
    )
    document.build(
        _build_story(report),
        onFirstPage=_footer,
        onLaterPages=_footer,
    )
    return buffer.getvalue()
