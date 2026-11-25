"""Descoberta passiva de arquivos públicos e dicas de configuração."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Final
from xml.etree import ElementTree

from sentinela.analyzers.technologies import analyze_technologies
from sentinela.core.errors import SentinelaError
from sentinela.core.http_client import (
    fetch_text,
    normalize_target,
    same_origin,
    sanitize_url,
    with_path,
)
from sentinela.core.models import Finding, HttpSnapshot, HttpTextSnapshot, Severity

_REFERENCES: Final[tuple[str, ...]] = (
    "RFC 9309 — robots.txt",
    "RFC 9116 — security.txt",
    "sitemaps.org — protocolo de sitemap",
)

_ROBOTS_PATH: Final[str] = "/robots.txt"
_SITEMAP_PATH: Final[str] = "/sitemap.xml"
_SECURITY_PATHS: Final[tuple[str, ...]] = (
    "/.well-known/security.txt",
    "/security.txt",
)

_SENSITIVE_HINTS: Final[tuple[str, ...]] = (
    "admin",
    "backup",
    "config",
    "private",
    "internal",
    "upload",
    ".git",
    ".env",
    "phpmyadmin",
)

_MAX_PATHS: Final[int] = 8


def _is_usable(snapshot: HttpTextSnapshot) -> bool:
    """Considera utilizável uma resposta 2xx com corpo não vazio."""
    return (
        200 <= snapshot.response.status_code < 300
        and bool(snapshot.body.strip())
    )


def _safe_url(value: str, base_url: str) -> str:
    """Normaliza URLs descobertas sem expor query ou credenciais."""
    candidate = with_path(base_url, value) if value.startswith("/") else value
    try:
        return sanitize_url(normalize_target(candidate))
    except SentinelaError:
        return value[:120]


def _join(values: list[str]) -> str:
    """Formata uma amostra curta de valores para evidência."""
    shown = values[:_MAX_PATHS]
    if len(values) > _MAX_PATHS:
        shown.append(f"(+{len(values) - _MAX_PATHS})")
    return " | ".join(shown)


def _try_fetch(
    url: str,
    label: str,
    findings: list[Finding],
) -> HttpTextSnapshot | None:
    """Busca um arquivo passivo e registra falha sem abortar a varredura."""
    try:
        return fetch_text(url)
    except SentinelaError as exc:
        findings.append(
            Finding(
                code=f"discovery.{label}.error",
                title=f"Falha ao ler {label}",
                severity=Severity.INFO,
                status="info",
                message=str(exc),
                remediation="Verifique conectividade e tente novamente em outro momento.",
                references=_REFERENCES,
            )
        )
        return None


def analyze_robots(snapshot: HttpTextSnapshot, base_url: str) -> list[Finding]:
    """Analisa robots.txt por exposição de caminhos e declaração de sitemap."""
    status = snapshot.response.status_code
    if status == 404:
        return [
            Finding(
                code="discovery.robots",
                title="robots.txt não publicado",
                severity=Severity.INFO,
                status="info",
                message="O servidor respondeu 404 para /robots.txt.",
                remediation=(
                    "Nenhuma ação obrigatória; robots.txt é uma diretiva de "
                    "rastreamento, não um controle de acesso."
                ),
                references=_REFERENCES,
            )
        ]

    if not _is_usable(snapshot):
        return [
            Finding(
                code="discovery.robots",
                title="robots.txt indisponível",
                severity=Severity.INFO,
                status="info",
                message=f"Não foi possível analisar robots.txt (status {status}).",
                remediation="Confirme se o arquivo é servido publicamente.",
                references=_REFERENCES,
            )
        ]

    disallows: list[str] = []
    sitemaps: list[str] = []
    for line in snapshot.body.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#") or ":" not in cleaned:
            continue
        key, value = cleaned.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "disallow" and value:
            disallows.append(value.split("?", 1)[0])
        elif key == "sitemap" and value:
            sitemaps.append(_safe_url(value, base_url))

    findings = [
        Finding(
            code="discovery.robots",
            title="robots.txt disponível",
            severity=Severity.INFO,
            status="ok",
            message=(
                f"Foram observadas {len(disallows)} regras Disallow e "
                f"{len(sitemaps)} declarações Sitemap."
            ),
            remediation=(
                "Lembre-se: robots.txt não impede acesso; use autenticação e "
                "controle de acesso para conteúdo sensível."
            ),
            evidence=_join(disallows) if disallows else None,
            references=_REFERENCES,
        )
    ]

    sensitive = [
        path
        for path in disallows
        if any(hint in path.lower() for hint in _SENSITIVE_HINTS)
    ]
    if sensitive:
        findings.append(
            Finding(
                code="discovery.robots.sensitive_paths",
                title="Caminhos sensíveis revelados no robots.txt",
                severity=Severity.LOW,
                status="warning",
                message=(
                    "Disallow entries apontam para nomes comuns de áreas "
                    "administrativas ou arquivos sensíveis."
                ),
                remediation=(
                    "Evite listar caminhos sensíveis publicamente e garanta "
                    "controlo de acesso real para esses recursos."
                ),
                evidence=_join(sensitive),
                references=_REFERENCES,
            )
        )

    if sitemaps:
        findings.append(
            Finding(
                code="discovery.robots.sitemap",
                title="Sitemap declarado no robots.txt",
                severity=Severity.INFO,
                status="info",
                message="A diretiva Sitemap foi encontrada no robots.txt.",
                remediation="Mantenha o sitemap atualizado e livre de URLs internas.",
                evidence=_join(sitemaps),
                references=_REFERENCES,
            )
        )

    return findings


def _choose_sitemap_url(
    robots: HttpTextSnapshot | None,
    base_url: str,
) -> tuple[str, bool]:
    """Escolhe o sitemap a ler, restrito à mesma origem do alvo."""
    if robots and _is_usable(robots):
        for line in robots.body.splitlines():
            cleaned = line.strip()
            if not cleaned.lower().startswith("sitemap:"):
                continue
            value = cleaned.split(":", 1)[1].strip()
            candidate = with_path(base_url, value) if value.startswith("/") else value
            try:
                normalized = normalize_target(candidate)
            except SentinelaError:
                break
            if same_origin(normalized, base_url):
                return normalized, False
            return with_path(base_url, _SITEMAP_PATH), True

    return with_path(base_url, _SITEMAP_PATH), False


def _local_tag(tag: str) -> str:
    """Remove o namespace de uma tag XML."""
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(element: ElementTree.Element, name: str) -> str:
    """Retorna o texto do primeiro filho com determinado nome local."""
    for child in element:
        if _local_tag(child.tag) == name:
            return (child.text or "").strip()
    return ""


def analyze_sitemap(
    snapshot: HttpTextSnapshot,
    base_url: str,
    external_declared: bool = False,
) -> list[Finding]:
    """Contabiliza entradas de sitemap sem seguir links externos."""
    status = snapshot.response.status_code
    if status == 404:
        return [
            Finding(
                code="discovery.sitemap",
                title="sitemap.xml não publicado",
                severity=Severity.INFO,
                status="info",
                message="O servidor respondeu 404 para o sitemap verificado.",
                remediation="Publique um sitemap se desejar facilitar a indexação.",
                references=_REFERENCES,
            )
        ]

    if not _is_usable(snapshot):
        return [
            Finding(
                code="discovery.sitemap",
                title="sitemap.xml indisponível",
                severity=Severity.INFO,
                status="info",
                message=f"Não foi possível analisar o sitemap (status {status}).",
                remediation="Confirme se o sitemap é servido com status 2xx.",
                references=_REFERENCES,
            )
        ]

    findings: list[Finding] = []
    if external_declared:
        findings.append(
            Finding(
                code="discovery.sitemap.external",
                title="Sitemap externo ignorado",
                severity=Severity.INFO,
                status="info",
                message=(
                    "O robots.txt declarou um sitemap em outra origem; "
                    "a ferramenta não consulta hosts externos ao alvo."
                ),
                remediation="Analise esse sitemap separadamente se tiver autorização.",
                references=_REFERENCES,
            )
        )

    body_lower = snapshot.body.lower()
    if "<!doctype" in body_lower or "<!entity" in body_lower:
        return findings + [
            Finding(
                code="discovery.sitemap.entities",
                title="Sitemap com DOCTYPE/ENTITY",
                severity=Severity.LOW,
                status="warning",
                message=(
                    "O documento declara entidades; o parser foi ignorado por "
                    "precaução contra expansão de entidades."
                ),
                remediation="Gere o sitemap sem DOCTYPE e sem entidades personalizadas.",
                references=_REFERENCES,
            )
        ]

    try:
        root = ElementTree.fromstring(snapshot.body)
    except ElementTree.ParseError as exc:
        return findings + [
            Finding(
                code="discovery.sitemap.invalid",
                title="sitemap.xml inválido",
                severity=Severity.LOW,
                status="warning",
                message=f"O XML não pôde ser interpretado: {type(exc).__name__}.",
                remediation="Corrija o XML e valide-o antes de publicar.",
                references=_REFERENCES,
            )
        ]

    urls: list[str] = []
    child_sitemaps: list[str] = []
    for element in root.iter():
        local = _local_tag(element.tag)
        if local == "url":
            value = _child_text(element, "loc")
            if value:
                urls.append(_safe_url(value, base_url))
        elif local == "sitemap":
            value = _child_text(element, "loc")
            if value:
                child_sitemaps.append(_safe_url(value, base_url))

    if snapshot.truncated:
        findings.append(
            Finding(
                code="discovery.sitemap.truncated",
                title="Sitemap truncado pelo limite local",
                severity=Severity.INFO,
                status="info",
                message=(
                    f"O arquivo excedeu o limite de leitura e apenas "
                    f"{snapshot.bytes_read} bytes foram processados."
                ),
                remediation="Divida sitemaps grandes em arquivos menores ou índices.",
                references=_REFERENCES,
            )
        )

    if child_sitemaps:
        findings.append(
            Finding(
                code="discovery.sitemap.index",
                title="Índice de sitemaps encontrado",
                severity=Severity.INFO,
                status="info",
                message=(
                    f"O índice declara {len(child_sitemaps)} sitemaps filhos; "
                    "eles não foram buscados automaticamente."
                ),
                remediation="Revise os sitemaps filhos em uma execução separada, se autorizado.",
                evidence=_join(child_sitemaps),
                references=_REFERENCES,
            )
        )

    findings.append(
        Finding(
            code="discovery.sitemap",
            title="sitemap.xml disponível",
            severity=Severity.INFO,
            status="ok",
            message=f"Foram contabilizadas {len(urls)} URLs no sitemap lido.",
            remediation=(
                "Remova URLs internas, parâmetros sensíveis e conteúdo que não "
                "deve ser indexado."
            ),
            evidence=_join(urls) if urls else None,
            references=_REFERENCES,
        )
    )
    return findings


def analyze_security_txt(snapshots: tuple[HttpTextSnapshot, ...]) -> list[Finding]:
    """Verifica a política de divulgação de vulnerabilidades."""
    usable = next((item for item in snapshots if _is_usable(item)), None)
    if usable is None:
        return [
            Finding(
                code="discovery.security_txt",
                title="security.txt não publicado",
                severity=Severity.INFO,
                status="info",
                message=(
                    "Não foi encontrado security.txt em /.well-known/ nem na raiz."
                ),
                remediation=(
                    "Publique /.well-known/security.txt com Contact e Expires "
                    "para orientar relatos de vulnerabilidade."
                ),
                references=_REFERENCES,
            )
        ]

    fields: dict[str, str] = {}
    for line in usable.body.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#") or ":" not in cleaned:
            continue
        key, value = cleaned.split(":", 1)
        fields.setdefault(key.strip().lower(), value.strip())

    findings = [
        Finding(
            code="discovery.security_txt",
            title="security.txt disponível",
            severity=Severity.INFO,
            status="ok",
            message=(
                "Arquivo de política de divulgação encontrado em "
                f"{usable.response.final_url}."
            ),
            remediation="Mantenha os dados de contato atualizados.",
            evidence=f"campos={len(fields)}",
            references=_REFERENCES,
        )
    ]

    if "contact" not in fields:
        findings.append(
            Finding(
                code="discovery.security_txt.contact",
                title="security.txt sem Contact",
                severity=Severity.LOW,
                status="missing",
                message="O campo obrigatório Contact não foi encontrado.",
                remediation=(
                    "Inclua pelo menos um canal de contato, preferencialmente "
                    "mailto: ou https:."
                ),
                references=_REFERENCES,
            )
        )

    expires = fields.get("expires")
    if not expires:
        findings.append(
            Finding(
                code="discovery.security_txt.expires",
                title="security.txt sem Expires",
                severity=Severity.LOW,
                status="missing",
                message="O campo Expires não foi encontrado.",
                remediation="Defina uma data de expiração em formato ISO 8601.",
                references=_REFERENCES,
            )
        )
    else:
        try:
            parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if parsed < datetime.now(timezone.utc):
                findings.append(
                    Finding(
                        code="discovery.security_txt.expires",
                        title="security.txt expirado",
                        severity=Severity.LOW,
                        status="warning",
                        message="A data de expiração informada já passou.",
                        remediation="Atualize o campo Expires e revise os contatos.",
                        evidence=f"Expires={expires}",
                        references=_REFERENCES,
                    )
                )
        except ValueError:
            findings.append(
                Finding(
                    code="discovery.security_txt.expires",
                    title="Expires inválido",
                    severity=Severity.LOW,
                    status="warning",
                    message="A data de expiração não está no formato ISO 8601.",
                    remediation="Use um valor como 2027-01-01T00:00:00Z.",
                    evidence=f"Expires={expires}",
                    references=_REFERENCES,
                )
            )

    return findings


def run_passive_discovery(snapshot: HttpSnapshot) -> list[Finding]:
    """Executa a descoberta passiva completa a partir de um snapshot HTTP."""
    base_url = snapshot.final_url
    findings: list[Finding] = []

    robots = _try_fetch(with_path(base_url, _ROBOTS_PATH), "robots", findings)
    if robots is not None:
        findings.extend(analyze_robots(robots, base_url))

    sitemap_url, external_declared = _choose_sitemap_url(robots, base_url)
    sitemap = _try_fetch(sitemap_url, "sitemap", findings)
    if sitemap is not None:
        findings.extend(analyze_sitemap(sitemap, base_url, external_declared))

    security_snapshots: list[HttpTextSnapshot] = []
    for path in _SECURITY_PATHS:
        candidate = _try_fetch(with_path(base_url, path), "security", findings)
        if candidate is not None and _is_usable(candidate):
            security_snapshots.append(candidate)
            break
    findings.extend(analyze_security_txt(tuple(security_snapshots)))

    page = _try_fetch(base_url, "pagina", findings)
    findings.extend(analyze_technologies(snapshot, page.body if page else None))

    return findings
