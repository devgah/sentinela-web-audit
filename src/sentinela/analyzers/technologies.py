"""Detecção passiva de tecnologias expostas em cabeçalhos e meta tags."""

from __future__ import annotations

import re
from typing import Final

from bs4 import BeautifulSoup

from sentinela.core.models import Finding, HttpSnapshot, Severity

_REFERENCES: Final[tuple[str, ...]] = (
    "OWASP Testing Guide — Fingerprinting",
    "OWASP Secure Headers Project",
)

_HEADER_SIGNATURES: Final[dict[str, str]] = {
    "server": "Servidor HTTP",
    "x-powered-by": "Runtime/framework",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-generator": "CMS/gerador",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
    "cf-ray": "Cloudflare",
    "via": "Proxy intermediário",
}

_META_NAMES: Final[frozenset[str]] = frozenset(
    {"generator", "framework", "application-name", "x-powered-by"}
)

_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b\d+(?:\.\d+){1,}\b")

_MAX_SIGNALS: Final[int] = 12


def _short(value: str, limit: int = 200) -> str:
    """Limita evidências para não replicar conteúdo extenso da resposta."""
    cleaned = value.strip()
    return cleaned if len(cleaned) <= limit else f"{cleaned[: limit - 1]}…"


def _version_finding(
    code: str,
    source: str,
    label: str,
    value: str,
) -> Finding:
    """Cria um achado padronizado para tecnologia observada."""
    versioned = bool(_VERSION_PATTERN.search(value))
    return Finding(
        code=code,
        title=f"Tecnologia exposta via {source}",
        severity=Severity.LOW if versioned else Severity.INFO,
        status="warning" if versioned else "info",
        message=f"{source} revela {label}: {_short(value)}.",
        remediation=(
            "Remova o cabeçalho ou publique apenas o nome do produto, sem versão, "
            "para reduzir fingerprinting passivo."
            if versioned
            else "Avalie remover este sinal se ele não for necessário ao funcionamento."
        ),
        evidence=_short(f"{source}={value}"),
        references=_REFERENCES,
    )


def analyze_technologies(
    snapshot: HttpSnapshot,
    html: str | None = None,
) -> list[Finding]:
    """Identifica tecnologias a partir de sinais já presentes na resposta."""
    findings: list[Finding] = []

    for header, label in _HEADER_SIGNATURES.items():
        value = snapshot.headers.get(header, "").strip()
        if not value:
            continue
        findings.append(
            _version_finding(
                code=f"tech.header.{header.replace('-', '_')}",
                source=header,
                label=label,
                value=value,
            )
        )

    content_type = snapshot.headers.get("content-type", "").lower()
    looks_like_html = "<html" in html[:200].lower() if html else False
    if html and html.strip().startswith("<") and ("html" in content_type or looks_like_html):
        soup = BeautifulSoup(html, "html.parser")
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("http-equiv") or "").strip().lower()
            if name not in _META_NAMES:
                continue
            content = (meta.get("content") or "").strip()
            if not content:
                continue
            findings.append(
                _version_finding(
                    code=f"tech.meta.{name.replace('-', '_')}",
                    source=f"meta[{name}]",
                    label="tecnologia declarada na página",
                    value=content,
                )
            )

    if not findings:
        return [
            Finding(
                code="tech.none",
                title="Nenhuma tecnologia identificada passivamente",
                severity=Severity.INFO,
                status="info",
                message=(
                    "Não foram encontrados cabeçalhos ou meta tags que revelem "
                    "servidor, runtime ou CMS nesta resposta."
                ),
                remediation="Nenhuma ação necessária.",
                references=_REFERENCES,
            )
        ]

    if len(findings) > _MAX_SIGNALS:
        findings = findings[:_MAX_SIGNALS]
        findings.append(
            Finding(
                code="tech.truncated",
                title="Sinais tecnológicos truncados",
                severity=Severity.INFO,
                status="info",
                message=f"Apenas os primeiros {_MAX_SIGNALS} sinais foram relatados.",
                remediation="Revise a resposta manualmente se precisar do restante.",
                references=_REFERENCES,
            )
        )

    return findings
