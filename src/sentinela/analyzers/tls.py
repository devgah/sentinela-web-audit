"""Achados passivos sobre o certificado e a negociação TLS."""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sentinela.core.models import Finding, Severity, TlsSnapshot

_REFERENCES: Final[tuple[str, ...]] = (
    "OWASP Transport Layer Protection Cheat Sheet",
    "RFC 6125 / RFC 9525 — validação de hostname de certificados",
)

_WEAK_PROTOCOLS: Final[frozenset[str]] = frozenset(
    {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}
)


def _date(value: datetime) -> str:
    """Formata datas do certificado de forma estável."""
    return value.strftime("%Y-%m-%d")


def _analyze_protocol(tls: TlsSnapshot) -> Finding:
    """Avalia a versão negociada e a suíte de cifra."""
    normalized = tls.protocol.upper().replace("_", ".").replace(" ", "")
    evidence = f"protocolo={tls.protocol}; cipher={tls.cipher or 'não informado'}"

    if normalized in _WEAK_PROTOCOLS:
        return Finding(
            code="tls.protocol",
            title="Protocolo TLS obsoleto",
            severity=Severity.HIGH,
            status="warning",
            message=(
                "A negociação usou um protocolo sem suporte seguro atualmente, "
                "sujeito a ataques conhecidos."
            ),
            remediation=(
                "Desabilite SSLv3, TLS 1.0 e TLS 1.1; exija TLS 1.2 no mínimo "
                "e prefira TLS 1.3."
            ),
            evidence=evidence,
            references=_REFERENCES,
        )

    if normalized == "TLSV1.2":
        return Finding(
            code="tls.protocol",
            title="TLS 1.2 negociado",
            severity=Severity.INFO,
            status="info",
            message="TLS 1.2 é aceitável, mas TLS 1.3 reduz a complexidade da negociação.",
            remediation="Habilite TLS 1.3 com precedência sobre TLS 1.2.",
            evidence=evidence,
            references=_REFERENCES,
        )

    return Finding(
        code="tls.protocol",
        title="Protocolo TLS observado",
        severity=Severity.INFO,
        status="ok",
        message="A versão negociada não aparece na lista de protocolos obsoletos.",
        remediation=(
            "Mantenha apenas versões atualizadas e revise a configuração "
            "do servidor periodicamente."
        ),
        evidence=evidence,
        references=_REFERENCES,
    )


def _analyze_validity(tls: TlsSnapshot) -> Finding:
    """Verifica janela de validade do certificado."""
    evidence = f"válido de {_date(tls.not_before)} até {_date(tls.not_after)}"

    if tls.is_expired:
        return Finding(
            code="tls.validity",
            title="Certificado expirado",
            severity=Severity.HIGH,
            status="warning",
            message="O certificado apresentado já expirou e não deve ser confiado.",
            remediation=(
                "Renove o certificado e configure renovação automática antes do vencimento."
            ),
            evidence=evidence,
            references=_REFERENCES,
        )

    if tls.is_not_yet_valid:
        return Finding(
            code="tls.validity",
            title="Certificado ainda não válido",
            severity=Severity.HIGH,
            status="warning",
            message="A data de início de validade do certificado está no futuro.",
            remediation="Confira a data do sistema e reemita o certificado se necessário.",
            evidence=evidence,
            references=_REFERENCES,
        )

    if tls.days_remaining < 30:
        return Finding(
            code="tls.validity",
            title="Certificado próximo do vencimento",
            severity=Severity.MEDIUM,
            status="warning",
            message=f"Restam {tls.days_remaining} dias para o vencimento do certificado.",
            remediation=(
                "Renove com antecedência e automatize o processo para evitar interrupções."
            ),
            evidence=evidence,
            references=_REFERENCES,
        )

    return Finding(
        code="tls.validity",
        title="Certificado dentro da validade",
        severity=Severity.INFO,
        status="ok",
        message=f"O certificado é válido por mais {tls.days_remaining} dias.",
        remediation="Mantenha monitoramento de expiração.",
        evidence=evidence,
        references=_REFERENCES,
    )


def _analyze_identity(tls: TlsSnapshot) -> Finding:
    """Avalia cadeia de confiança, hostname e autoassinatura."""
    evidence = f"emissor={tls.issuer}; serial={tls.serial_number}"

    if not tls.hostname_matches:
        return Finding(
            code="tls.identity",
            title="Certificado não cobre o hostname",
            severity=Severity.HIGH,
            status="warning",
            message="O nome solicitado não corresponde ao SAN/CN apresentado no certificado.",
            remediation=(
                "Reemita o certificado incluindo o hostname em Subject Alternative Name."
            ),
            evidence=f"{evidence}; host={tls.host}",
            references=_REFERENCES,
        )

    if tls.is_self_signed:
        return Finding(
            code="tls.identity",
            title="Certificado autoassinado",
            severity=Severity.MEDIUM,
            status="warning",
            message="Subject e issuer são iguais, indicando certificado autoassinado.",
            remediation=(
                "Use um certificado emitido por autoridade confiável em ambiente público."
            ),
            evidence=evidence,
            references=_REFERENCES,
        )

    if not tls.is_trusted:
        return Finding(
            code="tls.identity",
            title="Cadeia de certificados não confiável",
            severity=Severity.MEDIUM,
            status="warning",
            message="A validação com o armazenamento local do sistema falhou.",
            remediation=(
                "Instale a cadeia intermediária correta e use uma autoridade "
                "de certificação reconhecida."
            ),
            evidence=(
                f"{evidence}; validacao={tls.validation_error or 'falha não detalhada'}"
            ),
            references=_REFERENCES,
        )

    return Finding(
        code="tls.identity",
        title="Identidade TLS validada",
        severity=Severity.INFO,
        status="ok",
        message="Cadeia confiável e hostname correspondente ao certificado.",
        remediation="Mantenha a cadeia completa e monitore renovações.",
        evidence=evidence,
        references=_REFERENCES,
    )


def _analyze_san(tls: TlsSnapshot) -> Finding:
    """Verifica a presença de Subject Alternative Name."""
    if not tls.san:
        return Finding(
            code="tls.san",
            title="Certificado sem Subject Alternative Name",
            severity=Severity.LOW,
            status="missing",
            message=(
                "Não há extensão SAN; navegadores modernos ignoram o Common Name "
                "para validação de hostname."
            ),
            remediation=(
                "Inclua todos os nomes e IPs atendidos na extensão "
                "Subject Alternative Name."
            ),
            evidence=f"subject={tls.subject}",
            references=_REFERENCES,
        )

    shown = ", ".join(tls.san[:8])
    if len(tls.san) > 8:
        shown += f" (+{len(tls.san) - 8})"
    return Finding(
        code="tls.san",
        title="Subject Alternative Name presente",
        severity=Severity.INFO,
        status="ok",
        message="O certificado declara nomes alternativos para validação.",
        remediation="Revise a lista ao adicionar novos subdomínios ou domínios.",
        evidence=f"SAN={shown}",
        references=_REFERENCES,
    )


def analyze_tls(tls: TlsSnapshot | None) -> list[Finding]:
    """Executa as verificações TLS do Dia 3.

    Quando não há snapshot TLS, a resposta final não foi HTTPS e o resultado
    é apenas informativo.
    """
    if tls is None:
        return [
            Finding(
                code="tls.not_applicable",
                title="TLS não aplicável",
                severity=Severity.INFO,
                status="info",
                message=(
                    "A resposta final foi HTTP, portanto não houve handshake TLS "
                    "para inspecionar."
                ),
                remediation="Publique o serviço em HTTPS com um certificado válido.",
                references=_REFERENCES,
            )
        ]

    return [
        _analyze_protocol(tls),
        _analyze_validity(tls),
        _analyze_identity(tls),
        _analyze_san(tls),
    ]
