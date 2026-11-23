"""Auditoria passiva de atributos de cookies em respostas HTTP."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from sentinela.core.models import Finding, HttpSnapshot, Severity

_REFERENCES: Final[tuple[str, ...]] = (
    "OWASP Session Management Cheat Sheet",
    "OWASP Cross-Site Request Forgery Prevention Cheat Sheet",
)

_SESSION_HINTS: Final[tuple[str, ...]] = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "login",
)

_MAX_COOKIES: Final[int] = 20


@dataclass(frozen=True, slots=True)
class _Cookie:
    """Representação mínima de um cookie observado."""

    name: str
    attributes: Mapping[str, str | None]


def _slug(name: str) -> str:
    """Gera um identificador seguro para códigos de achados."""
    cleaned = "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in name
    )
    return cleaned[:40] or "cookie"


def _parse(header: str) -> _Cookie | None:
    """Divide um cabeçalho Set-Cookie sem expor o valor do cookie."""
    parts = [part.strip() for part in header.split(";") if part.strip()]
    if not parts:
        return None

    name, separator, _value = parts[0].partition("=")
    name = name.strip()
    if not separator or not name:
        return None

    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        key, has_value, content = part.partition("=")
        key = key.strip().lower()
        if key:
            attributes[key] = content.strip() if has_value else None

    return _Cookie(name=name, attributes=MappingProxyType(attributes))


def _evidence(cookie: _Cookie, detail: str) -> str:
    """Mostra o nome do cookie, nunca seu valor."""
    return f"{cookie.name}=<redacted>; {detail}"


def _is_session_cookie(name: str) -> bool:
    """Heurística simples para cookies com potencial impacto de sessão."""
    lowered = name.lower()
    return any(hint in lowered for hint in _SESSION_HINTS)


def _httponly_finding(cookie: _Cookie, session_like: bool) -> Finding:
    """Avalia a flag HttpOnly."""
    code = f"cookie.{_slug(cookie.name)}.httponly"
    if "httponly" in cookie.attributes:
        return Finding(
            code=code,
            title=f"Cookie {cookie.name!r} com HttpOnly",
            severity=Severity.INFO,
            status="ok",
            message="O cookie não é acessível por JavaScript via document.cookie.",
            remediation="Mantenha HttpOnly em cookies de sessão e autenticação.",
            evidence=_evidence(cookie, "HttpOnly=presente"),
            references=_REFERENCES,
        )

    return Finding(
        code=code,
        title=f"Cookie {cookie.name!r} sem HttpOnly",
        severity=Severity.MEDIUM if session_like else Severity.LOW,
        status="missing",
        message=(
            "O cookie pode ser lido por scripts da página, aumentando o impacto "
            "de um XSS."
        ),
        remediation="Adicione HttpOnly a cookies que não precisam ser lidos pelo frontend.",
        evidence=_evidence(cookie, "HttpOnly=ausente"),
        references=_REFERENCES,
    )


def _secure_finding(
    cookie: _Cookie,
    snapshot: HttpSnapshot,
    session_like: bool,
) -> Finding:
    """Avalia a flag Secure no contexto do protocolo da resposta."""
    code = f"cookie.{_slug(cookie.name)}.secure"

    if "secure" in cookie.attributes:
        return Finding(
            code=code,
            title=f"Cookie {cookie.name!r} com Secure",
            severity=Severity.INFO,
            status="ok",
            message="O cookie será enviado apenas em conexões HTTPS.",
            remediation="Mantenha Secure e garanta que toda a aplicação use HTTPS.",
            evidence=_evidence(cookie, "Secure=presente"),
            references=_REFERENCES,
        )

    if not snapshot.is_https:
        return Finding(
            code=code,
            title=f"Cookie {cookie.name!r} sem Secure em HTTP",
            severity=Severity.INFO,
            status="info",
            message=(
                "A resposta final foi HTTP; Secure não pode ser aplicado sem quebrar "
                "o envio do cookie. O problema raiz é a ausência de HTTPS."
            ),
            remediation="Habilite HTTPS e então defina Secure em todos os cookies sensíveis.",
            evidence=_evidence(cookie, "Secure=ausente; esquema=http"),
            references=_REFERENCES,
        )

    return Finding(
        code=code,
        title=f"Cookie {cookie.name!r} sem Secure",
        severity=Severity.MEDIUM if session_like else Severity.LOW,
        status="missing",
        message="O cookie pode ser transmitido em conexões HTTP não criptografadas.",
        remediation="Adicione Secure e redirecione todo HTTP para HTTPS.",
        evidence=_evidence(cookie, "Secure=ausente; esquema=https"),
        references=_REFERENCES,
    )


def _samesite_finding(cookie: _Cookie, session_like: bool) -> Finding:
    """Avalia a diretiva SameSite."""
    code = f"cookie.{_slug(cookie.name)}.samesite"
    raw = cookie.attributes.get("samesite")
    value = raw.strip().lower() if raw else None

    if value is None:
        return Finding(
            code=code,
            title=f"Cookie {cookie.name!r} sem SameSite",
            severity=Severity.MEDIUM if session_like else Severity.LOW,
            status="missing",
            message="Sem SameSite, o cookie pode acompanhar requisições cross-site.",
            remediation=(
                "Defina SameSite=Lax por padrão e SameSite=Strict para cookies sensíveis."
            ),
            evidence=_evidence(cookie, "SameSite=ausente"),
            references=_REFERENCES,
        )

    if value == "none":
        if "secure" not in cookie.attributes:
            return Finding(
                code=code,
                title=f"Cookie {cookie.name!r} com SameSite=None sem Secure",
                severity=Severity.MEDIUM,
                status="warning",
                message="Navegadores modernos rejeitam SameSite=None sem o atributo Secure.",
                remediation=(
                    "Adicione Secure ou remova SameSite=None se o cookie não for cross-site."
                ),
                evidence=_evidence(cookie, "SameSite=None; Secure=ausente"),
                references=_REFERENCES,
            )
        return Finding(
            code=code,
            title=f"Cookie {cookie.name!r} com SameSite=None",
            severity=Severity.INFO,
            status="info",
            message="O cookie é enviado em contextos cross-site de forma explícita.",
            remediation="Confirme que isso é necessário e mantenha Secure obrigatório.",
            evidence=_evidence(cookie, "SameSite=None; Secure=presente"),
            references=_REFERENCES,
        )

    if value in {"lax", "strict"}:
        return Finding(
            code=code,
            title=f"Cookie {cookie.name!r} com SameSite={value.title()}",
            severity=Severity.INFO,
            status="ok",
            message="A diretiva limita o envio do cookie em requisições cross-site.",
            remediation=(
                "Mantenha a política mais restritiva compatível com o fluxo da aplicação."
            ),
            evidence=_evidence(cookie, f"SameSite={value}"),
            references=_REFERENCES,
        )

    return Finding(
        code=code,
        title=f"Cookie {cookie.name!r} com SameSite inválido",
        severity=Severity.LOW,
        status="warning",
        message="O valor informado não é reconhecido como Strict, Lax ou None.",
        remediation="Use SameSite=Strict, Lax ou None com Secure.",
        evidence=_evidence(cookie, f"SameSite={value}"),
        references=_REFERENCES,
    )


def analyze_cookies(snapshot: HttpSnapshot) -> list[Finding]:
    """Audita os cookies definidos na resposta sem revelar seus valores."""
    headers = snapshot.set_cookie_headers
    if not headers:
        return [
            Finding(
                code="cookies.none",
                title="Nenhum cookie observado",
                severity=Severity.INFO,
                status="info",
                message="A resposta analisada não definiu cookies via Set-Cookie.",
                remediation="Nenhuma ação necessária para esta resposta.",
                references=_REFERENCES,
            )
        ]

    findings: list[Finding] = []
    for header in headers[:_MAX_COOKIES]:
        cookie = _parse(header)
        if cookie is None:
            continue
        session_like = _is_session_cookie(cookie.name)
        findings.extend(
            (
                _httponly_finding(cookie, session_like),
                _secure_finding(cookie, snapshot, session_like),
                _samesite_finding(cookie, session_like),
            )
        )

    if len(headers) > _MAX_COOKIES:
        findings.append(
            Finding(
                code="cookies.truncated",
                title="Lista de cookies truncada",
                severity=Severity.INFO,
                status="info",
                message=(
                    f"Foram observados {len(headers)} cookies; apenas os primeiros "
                    f"{_MAX_COOKIES} foram auditados."
                ),
                remediation="Revise manualmente os cookies restantes se necessário.",
                references=_REFERENCES,
            )
        )

    if not findings:
        findings.append(
            Finding(
                code="cookies.unparsed",
                title="Cookies não interpretados",
                severity=Severity.INFO,
                status="info",
                message="Set-Cookie presente, mas nenhum par nome/valor foi interpretado.",
                remediation="Verifique se o cabeçalho segue o formato padrão.",
                references=_REFERENCES,
            )
        )

    return findings
