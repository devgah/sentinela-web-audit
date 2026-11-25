"""Modelos compartilhados pelos analisadores e pelo futuro gerador de relatórios."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    """Níveis de severidade suportados no relatório."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def label(self) -> str:
        """Rótulo legível em português."""
        return {
            Severity.INFO: "Informativo",
            Severity.LOW: "Baixo",
            Severity.MEDIUM: "Médio",
            Severity.HIGH: "Alto",
        }[self]

    @property
    def rank(self) -> int:
        """Ordem crescente de gravidade, útil para ordenação."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
        }[self]


FindingStatus = Literal["ok", "missing", "warning", "info"]


@dataclass(frozen=True, slots=True)
class Finding:
    """Um achado passivo com diagnóstico e remediação."""

    code: str
    title: str
    severity: Severity
    status: FindingStatus
    message: str
    remediation: str
    evidence: str | None = None
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Redirect:
    """Um salto de redirecionamento observado, já sanitizado."""

    url: str
    status_code: int


@dataclass(frozen=True, slots=True)
class TlsSnapshot:
    """Dados observados de um handshake TLS, sem serviços externos."""

    host: str
    port: int
    protocol: str
    cipher: str | None
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: tuple[str, ...]
    is_trusted: bool
    hostname_matches: bool
    validation_error: str | None = None
    checked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_expired(self) -> bool:
        """Indica se o certificado já expirou."""
        return self.not_after < self.checked_at

    @property
    def is_not_yet_valid(self) -> bool:
        """Indica se o certificado ainda não entrou em vigor."""
        return self.not_before > self.checked_at

    @property
    def days_remaining(self) -> int:
        """Dias inteiros restantes até o vencimento."""
        return int((self.not_after - self.checked_at).total_seconds() // 86_400)

    @property
    def is_self_signed(self) -> bool:
        """Compara subject e issuer para detectar autoassinatura aparente."""
        return self.subject == self.issuer


@dataclass(frozen=True, slots=True)
class HttpTextSnapshot:
    """Resposta HTTP textual com limite de bytes previamente aplicado."""

    response: HttpSnapshot
    body: str
    content_type: str
    truncated: bool
    bytes_read: int


@dataclass(frozen=True, slots=True)
class HttpSnapshot:
    """Resposta HTTP capturada localmente.

    Os nomes de cabeçalhos são normalizados em minúsculas. As URLs já foram
    sanitizadas (sem credenciais, query ou fragmento) para uso em relatórios.
    """

    requested_url: str
    final_url: str
    status_code: int
    headers: Mapping[str, str]
    set_cookie_headers: tuple[str, ...] = ()
    redirect_chain: tuple[Redirect, ...] = ()
    elapsed_ms: int = 0

    @property
    def is_https(self) -> bool:
        """Indica se a resposta final foi obtida via HTTPS."""
        return self.final_url.lower().startswith("https://")
