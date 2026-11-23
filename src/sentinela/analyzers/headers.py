"""Análise passiva dos cabeçalhos de segurança HTTP."""

from __future__ import annotations

import re
from typing import Final

from sentinela.core.models import Finding, HttpSnapshot, Severity

_REFERENCES: Final[tuple[str, ...]] = (
    "OWASP Secure Headers Project",
    "OWASP Cheat Sheet Series — HTTP Security Response Headers",
)

_VALID_REFERRER_POLICIES: Final[frozenset[str]] = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)

_MIN_HSTS_AGE: Final[int] = 31_536_000


def _header(snapshot: HttpSnapshot, name: str) -> str:
    """Retorna um cabeçalho normalizado ou string vazia."""
    return snapshot.headers.get(name.lower(), "").strip()


def _short(value: str, limit: int = 240) -> str:
    """Limita evidências longas para manter o relatório legível."""
    cleaned = value.strip()
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 1]}…"


def _directives(value: str) -> dict[str, str]:
    """Converte uma lista de diretivas em um dicionário minúsculo."""
    result: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, separator, content = part.partition(" ")
        result[name.lower()] = content.strip() if separator else ""
    return result


def _max_age(value: str) -> int | None:
    """Extrai o max-age de um cabeçalho HSTS."""
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _has_frame_ancestors(csp: str) -> bool:
    """Indica se a CSP já define política de incorporação em frames."""
    return "frame-ancestors" in _directives(csp)


def _csp_allows_unsafe_script(csp: str) -> bool:
    """Detecta script-src permissivo sem nonce/hash compensatório."""
    directives = _directives(csp)
    source = directives.get("script-src") or directives.get("default-src", "")
    lowered = source.lower()
    has_unsafe = "'unsafe-inline'" in lowered or "'unsafe-eval'" in lowered
    has_nonce_or_hash = any(
        marker in lowered
        for marker in ("nonce-", "sha256-", "sha384-", "sha512-")
    )
    return has_unsafe and not has_nonce_or_hash


def analyze_csp(snapshot: HttpSnapshot) -> Finding:
    """Avalia a presença e a qualidade básica da Content-Security-Policy."""
    value = _header(snapshot, "Content-Security-Policy")
    legacy = _header(snapshot, "X-Content-Security-Policy") or _header(
        snapshot, "X-WebKit-CSP"
    )

    if not value:
        if legacy:
            return Finding(
                code="headers.csp",
                title="CSP apenas em cabeçalho legado",
                severity=Severity.LOW,
                status="warning",
                message=(
                    "Foi encontrada apenas uma variante prefixada da CSP; "
                    "navegadores modernos a ignoram."
                ),
                remediation=(
                    "Publique Content-Security-Policy padrão e remova "
                    "X-Content-Security-Policy/X-WebKit-CSP."
                ),
                evidence=_short(legacy),
                references=_REFERENCES,
            )
        return Finding(
            code="headers.csp",
            title="Content-Security-Policy ausente",
            severity=Severity.MEDIUM,
            status="missing",
            message=(
                "Não há CSP na resposta. A aplicação perde uma camada "
                "importante de defesa em profundidade contra XSS e injeção de conteúdo."
            ),
            remediation=(
                "Defina uma CSP restritiva começando com default-src 'self'; "
                "prefira nonce/hash a 'unsafe-inline' e valide em modo report-only "
                "antes de aplicar."
            ),
            references=_REFERENCES,
        )

    directives = _directives(value)
    if not {"default-src", "script-src"}.intersection(directives):
        return Finding(
            code="headers.csp",
            title="CSP com cobertura limitada",
            severity=Severity.MEDIUM,
            status="warning",
            message="A CSP está presente, mas não define default-src nem script-src.",
            remediation=(
                "Inclua default-src como fallback e uma política explícita para script-src."
            ),
            evidence=_short(value),
            references=_REFERENCES,
        )

    if _csp_allows_unsafe_script(value):
        return Finding(
            code="headers.csp",
            title="CSP permite scripts inseguros",
            severity=Severity.MEDIUM,
            status="warning",
            message=(
                "script-src (ou default-src) usa 'unsafe-inline'/'unsafe-eval' "
                "sem nonce ou hash, reduzindo a proteção contra XSS."
            ),
            remediation=(
                "Remova 'unsafe-inline' e 'unsafe-eval'; use nonce ou hash por script "
                "e mantenha script-src restrito a origens confiáveis."
            ),
            evidence=_short(value),
            references=_REFERENCES,
        )

    return Finding(
        code="headers.csp",
        title="Content-Security-Policy presente",
        severity=Severity.INFO,
        status="ok",
        message="CSP encontrada com diretivas básicas para scripts.",
        remediation=(
            "Mantenha a política revisada e monitorize violações com report-uri/report-to."
        ),
        evidence=_short(value),
        references=_REFERENCES,
    )


def analyze_hsts(snapshot: HttpSnapshot) -> Finding:
    """Avalia Strict-Transport-Security no contexto do protocolo final."""
    value = _header(snapshot, "Strict-Transport-Security")

    if not snapshot.is_https:
        if value:
            return Finding(
                code="headers.hsts",
                title="HSTS ignorado em conexão HTTP",
                severity=Severity.INFO,
                status="warning",
                message="O cabeçalho HSTS foi enviado, mas navegadores o ignoram em HTTP.",
                remediation="Publique o serviço em HTTPS e mantenha HSTS apenas na resposta TLS.",
                evidence=_short(value),
                references=_REFERENCES,
            )
        return Finding(
            code="headers.hsts",
            title="HSTS não aplicável em HTTP",
            severity=Severity.INFO,
            status="info",
            message="A resposta final foi HTTP; HSTS só produz efeito em HTTPS.",
            remediation="Habilite HTTPS com certificado válido e redirecione HTTP para HTTPS.",
            references=_REFERENCES,
        )

    if not value:
        return Finding(
            code="headers.hsts",
            title="HSTS ausente",
            severity=Severity.MEDIUM,
            status="missing",
            message=(
                "O site é HTTPS, mas não declara HSTS; o primeiro acesso via HTTP "
                "pode ser rebaixado por um atacante na rede."
            ),
            remediation=(
                "Envie Strict-Transport-Security: max-age=31536000; includeSubDomains "
                "e considere preload após validar subdomínios."
            ),
            references=_REFERENCES,
        )

    age = _max_age(value)
    if age is None:
        return Finding(
            code="headers.hsts",
            title="HSTS sem max-age válido",
            severity=Severity.MEDIUM,
            status="warning",
            message="O cabeçalho HSTS não contém um max-age numérico interpretável.",
            remediation="Defina max-age em segundos, com valor mínimo recomendado de 31536000.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    if age < _MIN_HSTS_AGE:
        return Finding(
            code="headers.hsts",
            title="HSTS com tempo curto",
            severity=Severity.MEDIUM,
            status="warning",
            message=f"max-age={age}s é inferior ao recomendado de {_MIN_HSTS_AGE}s.",
            remediation="Aumente max-age para pelo menos um ano (31536000 segundos).",
            evidence=_short(value),
            references=_REFERENCES,
        )

    lowered = value.lower()
    if "includesubdomains" not in lowered:
        return Finding(
            code="headers.hsts",
            title="HSTS sem includeSubDomains",
            severity=Severity.LOW,
            status="warning",
            message="A política não protege subdomínios do mesmo domínio.",
            remediation=(
                "Confirme que todos os subdomínios usam HTTPS e adicione includeSubDomains."
            ),
            evidence=_short(value),
            references=_REFERENCES,
        )

    if "preload" not in lowered:
        return Finding(
            code="headers.hsts",
            title="HSTS válido sem preload",
            severity=Severity.INFO,
            status="info",
            message="HSTS está correto, mas o domínio não solicitou inclusão na lista preload.",
            remediation=(
                "Se todos os subdomínios estiverem prontos, avalie submeter o domínio "
                "à lista preload de navegadores."
            ),
            evidence=_short(value),
            references=_REFERENCES,
        )

    return Finding(
        code="headers.hsts",
        title="HSTS corretamente configurado",
        severity=Severity.INFO,
        status="ok",
        message="HSTS possui max-age adequado, includeSubDomains e preload.",
        remediation="Mantenha a configuração e monitore subdomínios novos.",
        evidence=_short(value),
        references=_REFERENCES,
    )


def analyze_x_frame_options(snapshot: HttpSnapshot) -> Finding:
    """Avalia proteção contra clickjacking, considerando CSP frame-ancestors."""
    value = _header(snapshot, "X-Frame-Options")
    csp = _header(snapshot, "Content-Security-Policy")

    if not value:
        if _has_frame_ancestors(csp):
            return Finding(
                code="headers.x_frame_options",
                title="Proteção de frames via CSP",
                severity=Severity.INFO,
                status="ok",
                message=(
                    "X-Frame-Options está ausente, mas a CSP define frame-ancestors, "
                    "que é a forma preferida de controlar incorporação."
                ),
                remediation=(
                    "Mantenha frame-ancestors na CSP; X-Frame-Options pode ficar "
                    "como fallback para navegadores antigos."
                ),
                evidence=_short(csp),
                references=_REFERENCES,
            )
        return Finding(
            code="headers.x_frame_options",
            title="X-Frame-Options ausente",
            severity=Severity.MEDIUM,
            status="missing",
            message=(
                "Não há X-Frame-Options nem CSP frame-ancestors; a página pode "
                "ser incorporada em frames de terceiros."
            ),
            remediation=(
                "Use Content-Security-Policy: frame-ancestors 'none' (ou 'self') "
                "e, para compatibilidade, X-Frame-Options: DENY ou SAMEORIGIN."
            ),
            references=_REFERENCES,
        )

    token = value.lower().split()[0] if value.split() else ""
    if token in {"deny", "sameorigin"}:
        return Finding(
            code="headers.x_frame_options",
            title="X-Frame-Options presente",
            severity=Severity.INFO,
            status="ok",
            message="A resposta define uma política válida de incorporação em frames.",
            remediation="Prefira também frame-ancestors na CSP para navegadores modernos.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    if token == "allow-from":
        return Finding(
            code="headers.x_frame_options",
            title="X-Frame-Options ALLOW-FROM obsoleto",
            severity=Severity.LOW,
            status="warning",
            message="ALLOW-FROM é deprecated e ignorado por navegadores atuais.",
            remediation="Substitua por CSP frame-ancestors com as origens autorizadas.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    return Finding(
        code="headers.x_frame_options",
        title="X-Frame-Options inválido",
        severity=Severity.MEDIUM,
        status="warning",
        message="O valor informado não é uma diretiva reconhecida.",
        remediation="Use DENY, SAMEORIGIN ou, preferencialmente, CSP frame-ancestors.",
        evidence=_short(value),
        references=_REFERENCES,
    )


def analyze_x_content_type_options(snapshot: HttpSnapshot) -> Finding:
    """Verifica a diretiva nosniff contra sniffing de MIME."""
    value = _header(snapshot, "X-Content-Type-Options")

    if not value:
        return Finding(
            code="headers.x_content_type_options",
            title="X-Content-Type-Options ausente",
            severity=Severity.LOW,
            status="missing",
            message=(
                "Sem nosniff, navegadores podem interpretar arquivos como um tipo "
                "diferente do declarado pelo servidor."
            ),
            remediation=(
                "Envie X-Content-Type-Options: nosniff e corrija os Content-Type retornados."
            ),
            references=_REFERENCES,
        )

    if value.lower() != "nosniff":
        return Finding(
            code="headers.x_content_type_options",
            title="X-Content-Type-Options inválido",
            severity=Severity.LOW,
            status="warning",
            message="A única diretiva válida para este cabeçalho é nosniff.",
            remediation="Substitua o valor por nosniff.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    return Finding(
        code="headers.x_content_type_options",
        title="X-Content-Type-Options presente",
        severity=Severity.INFO,
        status="ok",
        message="A resposta bloqueia MIME sniffing.",
        remediation=(
            "Mantenha o cabeçalho em todas as respostas de arquivos estáticos e dinâmicos."
        ),
        evidence=_short(value),
        references=_REFERENCES,
    )


def analyze_referrer_policy(snapshot: HttpSnapshot) -> Finding:
    """Avalia a política de envio do cabeçalho Referer."""
    value = _header(snapshot, "Referrer-Policy")
    code = "headers.referrer_policy"

    if not value:
        return Finding(
            code=code,
            title="Referrer-Policy ausente",
            severity=Severity.LOW,
            status="missing",
            message=(
                "Sem política explícita, o navegador usa o comportamento padrão, "
                "que pode vazar caminhos e parâmetros da URL."
            ),
            remediation=(
                "Defina Referrer-Policy: strict-origin-when-cross-origin "
                "ou política mais restritiva."
            ),
            references=_REFERENCES,
        )

    token = value.split(",", 1)[0].strip().lower()
    if token not in _VALID_REFERRER_POLICIES:
        return Finding(
            code=code,
            title="Referrer-Policy inválida",
            severity=Severity.LOW,
            status="warning",
            message="O valor não corresponde a uma política reconhecida.",
            remediation="Use uma política válida, como strict-origin-when-cross-origin.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    if token == "unsafe-url":
        return Finding(
            code=code,
            title="Referrer-Policy vaza URL completa",
            severity=Severity.MEDIUM,
            status="warning",
            message=(
                "unsafe-url envia caminho e query string mesmo em mudanças de origem, "
                "podendo expor tokens em parâmetros."
            ),
            remediation="Troque por strict-origin-when-cross-origin ou no-referrer.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    if token == "no-referrer-when-downgrade":
        return Finding(
            code=code,
            title="Referrer-Policy legada",
            severity=Severity.LOW,
            status="warning",
            message=(
                "Esta é a política padrão antiga; em transições para HTTPS ela ainda "
                "pode divulgar a URL completa."
            ),
            remediation="Prefira strict-origin-when-cross-origin.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    recommended = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if token in recommended:
        return Finding(
            code=code,
            title="Referrer-Policy presente",
            severity=Severity.INFO,
            status="ok",
            message="A política limita adequadamente as informações enviadas como Referer.",
            remediation="Mantenha a política em todas as respostas.",
            evidence=_short(value),
            references=_REFERENCES,
        )

    return Finding(
        code=code,
        title="Referrer-Policy válida, porém permissiva",
        severity=Severity.INFO,
        status="info",
        message="A política é válida, mas compartilha mais dados que a recomendação atual.",
        remediation="Avalie migrar para strict-origin-when-cross-origin ou no-referrer.",
        evidence=_short(value),
        references=_REFERENCES,
    )


def analyze_security_headers(snapshot: HttpSnapshot) -> list[Finding]:
    """Executa todas as verificações de cabeçalhos do Dia 2."""
    return [
        analyze_csp(snapshot),
        analyze_hsts(snapshot),
        analyze_x_frame_options(snapshot),
        analyze_x_content_type_options(snapshot),
        analyze_referrer_policy(snapshot),
    ]
