"""Modelo agregado da varredura e textos compartilhados pelos relatórios."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinela.core.models import Finding, HttpSnapshot, Severity, TlsSnapshot

DISCLAIMER: str = (
    "Esta ferramenta é fornecida \"como está\", para fins educacionais, "
    "treinamento e auditorias defensivas em domínios próprios ou expressamente "
    "autorizados.\n"
    "Use apenas em alvos que você possui ou para os quais possui autorização "
    "por escrito.\n"
    "A ferramenta realiza análise passiva: não explora vulnerabilidades, não "
    "executa payloads de ataque, não faz força bruta, não realiza scanners "
    "agressivos e não modifica o alvo.\n"
    "Não há envio de dados para serviços externos: nenhuma telemetria, "
    "analytics, autenticação, API de terceiros ou upload de relatórios. A única "
    "comunicação de rede é a requisição ao próprio alvo informado.\n"
    "O uso indevido desta ferramenta é de responsabilidade exclusiva do usuário "
    "e pode violar leis locais. Os mantenedores não se responsabilizam por danos "
    "ou uso inadequado.\n"
    "O código é distribuído sob a licença MIT (arquivo LICENSE)."
)

RISK_BY_SEVERITY: dict[Severity, str] = {
    Severity.HIGH: (
        "Pode comprometer diretamente a aplicação ou os usuários. Corrija antes "
        "de expor o serviço."
    ),
    Severity.MEDIUM: (
        "Pode facilitar ataques direcionados ou vazamento de informações com "
        "impacto relevante."
    ),
    Severity.LOW: (
        "Exposição limitada ou informação útil a um atacante; corrigir reduz o "
        "fingerprinting passivo."
    ),
    Severity.INFO: (
        "Sem impacto direto na segurança. Registrado para dar contexto à "
        "auditoria."
    ),
}

STATUS_LABELS: dict[str, str] = {
    "ok": "Ok / conforme",
    "missing": "Ausente",
    "warning": "Atenção",
    "info": "Informativo",
}

PASSIVE_SCOPE: tuple[str, ...] = (
    "Cabeçalhos HTTP e redirecionamentos",
    "TLS do próprio alvo (certificado, validade e cipher)",
    "Atributos de cookies sem leitura de valores",
    "Política CORS observada na resposta",
    "Arquivos públicos conhecidos (robots.txt, sitemap.xml, security.txt)",
    "Tecnologias reveladas por cabeçalhos e meta tags",
)


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Conjunto imutável de achados de uma execução passiva."""

    target: str
    findings: tuple[Finding, ...] = ()
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
    tool_version: str = "0.1.0"
    http: HttpSnapshot | None = None
    tls: TlsSnapshot | None = None

    @property
    def total_findings(self) -> int:
        """Quantidade total de achados."""
        return len(self.findings)

    @property
    def counts_by_severity(self) -> dict[Severity, int]:
        """Contagem por severidade, incluindo categorias vazias."""
        counts = Counter(finding.severity for finding in self.findings)
        return {severity: counts.get(severity, 0) for severity in Severity}

    @property
    def findings_by_severity(self) -> tuple[tuple[Severity, tuple[Finding, ...]], ...]:
        """Achados agrupados da maior para a menor severidade."""
        grouped: list[tuple[Severity, tuple[Finding, ...]]] = []
        for severity in sorted(Severity, key=lambda item: item.rank, reverse=True):
            items = tuple(
                sorted(
                    (
                        finding
                        for finding in self.findings
                        if finding.severity is severity
                    ),
                    key=lambda finding: (finding.code, finding.title),
                )
            )
            if items:
                grouped.append((severity, items))
        return tuple(grouped)

    @property
    def highest_severity(self) -> Severity | None:
        """Maior severidade presente no relatório."""
        return next((severity for severity, _ in self.findings_by_severity), None)

    @property
    def risk_label(self) -> str:
        """Rótulo do maior risco observado."""
        severity = self.highest_severity
        return severity.label if severity is not None else "Indefinido"

    @property
    def formatted_generated_at(self) -> str:
        """Data de geração em UTC, em formato estável para o relatório."""
        moment = self.generated_at
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
