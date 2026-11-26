"""Renderizador de relatórios em Markdown."""

from __future__ import annotations

from html import escape as html_escape

from sentinela.reports.models import (
    DISCLAIMER,
    PASSIVE_SCOPE,
    RISK_BY_SEVERITY,
    STATUS_LABELS,
    ScanReport,
)


def _text(value: str | None) -> str:
    """Normaliza texto dinâmico e bloqueia HTML/Markdown injetado."""
    if not value:
        return "-"
    flat = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    return html_escape(flat, quote=False).replace("|", "\\|")


def _quote(text: str) -> str:
    """Formata o aviso legal como citação em Markdown."""
    return "\n".join(f"> {line}" if line else ">" for line in text.splitlines())


def render_markdown(report: ScanReport) -> str:
    """Gera um relatório Markdown completo e autocontido."""
    lines: list[str] = [
        "# Relatório de auditoria passiva — Sentinela Web Audit",
        "",
        "## Aviso legal",
        "",
        _quote(DISCLAIMER),
        "",
        "## Contexto da execução",
        "",
        f"- **Alvo:** {_text(report.target)}",
        f"- **Gerado em:** {_text(report.formatted_generated_at)}",
        f"- **Versão da ferramenta:** {_text(report.tool_version)}",
        f"- **Risco geral:** {_text(report.risk_label)}",
        f"- **Total de achados:** {report.total_findings}",
        "",
        "Escopo passivo permitido:",
        "",
    ]
    lines.extend(f"- {_text(item)}" for item in PASSIVE_SCOPE)
    lines.extend(
        [
            "",
            (
                "Nenhuma exploração, payload, força bruta ou modificação do alvo foi "
                "realizada. Valores de cookies não são gravados neste relatório."
            ),
            "",
            "## Resumo por severidade",
            "",
            "| Severidade | Achados |",
            "| --- | ---: |",
        ]
    )
    for severity, count in report.counts_by_severity.items():
        lines.append(f"| {_text(severity.label)} | {count} |")
    lines.extend(["", "## Achados", ""])

    if not report.findings:
        lines.append("Nenhum achado foi registrado nesta execução.")
    else:
        for severity, group in report.findings_by_severity:
            risk = _text(RISK_BY_SEVERITY[severity])
            lines.extend(
                [
                    f"### {_text(severity.label)} — {len(group)}",
                    "",
                    f"**Interpretação do risco:** {risk}",
                    "",
                ]
            )
            for finding in group:
                lines.extend(
                    [
                        f"#### [{_text(finding.code)}] {_text(finding.title)}",
                        "",
                        f"- **Severidade:** {_text(severity.label)}",
                        f"- **Status:** {_text(STATUS_LABELS.get(finding.status, finding.status))}",
                        f"- **Risco:** {risk}",
                        f"- **Diagnóstico:** {_text(finding.message)}",
                    ]
                )
                if finding.evidence:
                    lines.append(f"- **Evidência:** {_text(finding.evidence)}")
                lines.extend(
                    [
                        f"- **Remediação:** {_text(finding.remediation)}",
                        "- **Referências:** "
                        + (
                            _text("; ".join(finding.references))
                            if finding.references
                            else "-"
                        ),
                        "",
                    ]
                )

    lines.extend(
        [
            "---",
            "",
            (
                "Relatório gerado localmente. Nenhum dado foi enviado a serviços "
                "externos."
            ),
            "",
        ]
    )
    return "\n".join(lines)
