"""Análise passiva da configuração de CORS declarada em cabeçalhos."""

from __future__ import annotations

from typing import Final

from sentinela.core.models import Finding, HttpSnapshot, Severity

_REFERENCES: Final[tuple[str, ...]] = (
    "OWASP Cross-Origin Resource Sharing (CORS) Security Guide",
    "MDN — Cross-Origin Resource Sharing (CORS)",
)

_ORIGIN: Final[str] = "access-control-allow-origin"
_CREDENTIALS: Final[str] = "access-control-allow-credentials"
_METHODS: Final[str] = "access-control-allow-methods"
_ALLOWED_HEADERS: Final[str] = "access-control-allow-headers"


def _header(snapshot: HttpSnapshot, name: str) -> str:
    """Retorna um cabeçalho normalizado ou string vazia."""
    return snapshot.headers.get(name.lower(), "").strip()


def _allows_credentials(snapshot: HttpSnapshot) -> bool:
    """Indica se o servidor declarou suporte a credenciais."""
    return _header(snapshot, _CREDENTIALS).lower() == "true"


def _vary_has_origin(snapshot: HttpSnapshot) -> bool:
    """Verifica se Vary inclui Origin para evitar cache cross-origin."""
    vary = _header(snapshot, "vary").lower()
    return any(value.strip() == "origin" for value in vary.split(","))


def analyze_cors(snapshot: HttpSnapshot) -> list[Finding]:
    """Avalia a superfície CORS sem enviar requisições com Origin forjado."""
    origin = _header(snapshot, _ORIGIN)
    credentials = _allows_credentials(snapshot)
    findings: list[Finding] = []

    if not origin:
        if credentials:
            return [
                Finding(
                    code="cors.credentials_without_origin",
                    title="Credenciais CORS sem origem declarada",
                    severity=Severity.LOW,
                    status="warning",
                    message=(
                        "Access-Control-Allow-Credentials=true foi declarado, "
                        "mas não há Access-Control-Allow-Origin correspondente."
                    ),
                    remediation=(
                        "Declare uma origem específica e confira se a configuração "
                        "foi aplicada ao ambiente correto."
                    ),
                    evidence="Access-Control-Allow-Credentials=true; ACAO=ausente",
                    references=_REFERENCES,
                )
            ]

        return [
            Finding(
                code="cors.not_declared",
                title="CORS não declarado",
                severity=Severity.INFO,
                status="info",
                message=(
                    "Não há cabeçalhos CORS na resposta; navegadores bloqueiam "
                    "leituras cross-origin por padrão."
                ),
                remediation=(
                    "Nenhuma ação necessária se a aplicação não precisa de acesso "
                    "cross-origin."
                ),
                references=_REFERENCES,
            )
        ]

    lowered = origin.lower()
    if lowered == "*":
        if credentials:
            findings.append(
                Finding(
                    code="cors.wildcard_credentials",
                    title="CORS curinga com credenciais",
                    severity=Severity.HIGH,
                    status="warning",
                    message=(
                        "ACAO=* combinado com credenciais é inválido na especificação "
                        "e indica configuração perigosa."
                    ),
                    remediation=(
                        "Substitua * por uma allowlist explícita de origens e "
                        "remova Access-Control-Allow-Credentials se não for necessário."
                    ),
                    evidence="ACAO=*; ACAC=true",
                    references=_REFERENCES,
                )
            )
        else:
            findings.append(
                Finding(
                    code="cors.wildcard",
                    title="CORS com origem curinga",
                    severity=Severity.INFO,
                    status="info",
                    message=(
                        "Qualquer origem pode ler esta resposta, mas credenciais "
                        "não foram autorizadas."
                    ),
                    remediation=(
                        "Aceitável para recursos públicos; para dados sensíveis, "
                        "use allowlist de origens."
                    ),
                    evidence="ACAO=*; ACAC!=true",
                    references=_REFERENCES,
                )
            )

    elif lowered == "null":
        findings.append(
            Finding(
                code="cors.null_origin",
                title="CORS aceita origem null",
                severity=Severity.MEDIUM,
                status="warning",
                message=(
                    "A origem null pode ser reivindicada por sandboxes, arquivos "
                    "locais e iframes opacos."
                ),
                remediation="Substitua null por origens HTTPS explícitas autorizadas.",
                evidence="ACAO=null",
                references=_REFERENCES,
            )
        )

    elif "," in origin:
        findings.append(
            Finding(
                code="cors.multiple_origins",
                title="Múltiplas origens em ACAO",
                severity=Severity.LOW,
                status="warning",
                message=(
                    "A especificação espera uma única origem por resposta; "
                    "listas separadas por vírgula podem ser ignoradas."
                ),
                remediation=(
                    "Selecione dinamicamente uma única origem autorizada por requisição."
                ),
                evidence=f"ACAO={origin}",
                references=_REFERENCES,
            )
        )

    elif credentials:
        if _vary_has_origin(snapshot):
            findings.append(
                Finding(
                    code="cors.explicit_credentials",
                    title="CORS com origem explícita e credenciais",
                    severity=Severity.INFO,
                    status="ok",
                    message=(
                        "A resposta declara uma origem específica, credenciais e "
                        "Vary: Origin, reduzindo risco de cache."
                    ),
                    remediation=(
                        "Confirme que o servidor valida a origem recebida contra "
                        "uma allowlist, sem espelhar valores arbitrários."
                    ),
                    evidence=f"ACAO={origin}; ACAC=true; Vary contém Origin",
                    references=_REFERENCES,
                )
            )
        else:
            findings.append(
                Finding(
                    code="cors.missing_vary",
                    title="CORS credenciado sem Vary: Origin",
                    severity=Severity.MEDIUM,
                    status="warning",
                    message=(
                        "A origem é explícita e credenciais são permitidas, mas "
                        "sem Vary: Origin uma resposta pode ser reutilizada "
                        "incorretamente por caches intermediários."
                    ),
                    remediation="Adicione Vary: Origin às respostas que variam por origem.",
                    evidence=f"ACAO={origin}; ACAC=true; Vary=ausente ou sem Origin",
                    references=_REFERENCES,
                )
            )

    else:
        findings.append(
            Finding(
                code="cors.explicit_origin",
                title="CORS com origem explícita",
                severity=Severity.INFO,
                status="ok",
                message="A resposta restringe o acesso cross-origin a uma origem declarada.",
                remediation=(
                    "Mantenha a allowlist revisada e evite espelhar origens não autorizadas."
                ),
                evidence=f"ACAO={origin}",
                references=_REFERENCES,
            )
        )

    methods = _header(snapshot, _METHODS)
    allowed_headers = _header(snapshot, _ALLOWED_HEADERS)
    if credentials and (methods == "*" or allowed_headers == "*"):
        findings.append(
            Finding(
                code="cors.wildcard_credentials_detail",
                title="Curinga em métodos/cabeçalhos com credenciais",
                severity=Severity.MEDIUM,
                status="warning",
                message=(
                    "Métodos ou cabeçalhos curinga foram declarados junto com "
                    "credenciais, ampliando a superfície cross-origin."
                ),
                remediation=(
                    "Liste explicitamente métodos e cabeçalhos necessários à aplicação."
                ),
                evidence=(
                    f"Allow-Methods={methods or 'ausente'}; "
                    f"Allow-Headers={allowed_headers or 'ausente'}"
                ),
                references=_REFERENCES,
            )
        )

    return findings
