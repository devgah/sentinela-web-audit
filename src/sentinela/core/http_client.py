"""Cliente HTTP local, passivo e com limites explícitos.

Nenhuma requisição é enviada a serviços de terceiros: apenas ao host informado
pelo usuário. Variáveis de ambiente de proxy e arquivos .netrc são ignorados.
"""

from __future__ import annotations

from time import monotonic
from types import MappingProxyType
from typing import Final
from urllib.parse import urlsplit, urlunsplit

import requests

from sentinela.core.errors import HttpRequestError, InvalidTargetError
from sentinela.core.models import HttpSnapshot, HttpTextSnapshot, Redirect

DEFAULT_TIMEOUT: Final[tuple[float, float]] = (5.0, 10.0)
MAX_REDIRECTS: Final[int] = 5
MAX_TEXT_BYTES: Final[int] = 512 * 1024
_CHUNK_SIZE: Final[int] = 8192
USER_AGENT: Final[str] = "SentinelaWebAudit/0.1 (local-passive-audit)"

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


def sanitize_url(url: str) -> str:
    """Remove credenciais, query e fragmento antes de exibir uma URL."""
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise InvalidTargetError("URL inválida.") from exc

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]

    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def normalize_target(raw_target: str) -> str:
    """Valida e normaliza a entrada do usuário para uma URL absoluta HTTP(S)."""
    value = (raw_target or "").strip()
    if not value:
        raise InvalidTargetError("Informe uma URL.")

    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise InvalidTargetError("A URL contém caracteres de controle.")

    if "://" not in value:
        value = f"https://{value}"

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise InvalidTargetError("Não foi possível interpretar a URL informada.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise InvalidTargetError("Use apenas http:// ou https://.")

    if parsed.username or parsed.password:
        raise InvalidTargetError("Não informe credenciais na URL.")

    if not parsed.hostname:
        raise InvalidTargetError("A URL não contém um host válido.")

    if " " in parsed.netloc:
        raise InvalidTargetError("O host da URL contém espaços.")

    return urlunsplit(
        (scheme, parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment)
    )


def with_path(url: str, path: str) -> str:
    """Substitui o caminho de uma URL mantendo esquema, host e porta."""
    parsed = urlsplit(url)
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def same_origin(first: str, second: str) -> bool:
    """Compara esquema, host e porta efetiva de duas URLs."""
    return _origin(first) == _origin(second)


def _origin(url: str) -> tuple[str, str, int | None]:
    """Extrai a origem normalizada de uma URL HTTP(S)."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = None
    return scheme, host, port


def _snapshot_from_response(
    response: requests.Response,
    display_url: str,
    started_at: float,
) -> HttpSnapshot:
    """Constrói o snapshot imutável a partir de uma resposta já obtida."""
    headers = {name.lower(): value for name, value in response.headers.items()}

    if hasattr(response.headers, "getlist"):
        cookie_values = tuple(response.headers.getlist("Set-Cookie"))
    elif "Set-Cookie" in response.headers:
        cookie_values = (response.headers["Set-Cookie"],)
    else:
        cookie_values = ()

    redirect_chain = tuple(
        Redirect(
            url=sanitize_url(hop.url),
            status_code=hop.status_code,
        )
        for hop in response.history
    )

    return HttpSnapshot(
        requested_url=display_url,
        final_url=sanitize_url(response.url),
        status_code=response.status_code,
        headers=MappingProxyType(headers),
        set_cookie_headers=cookie_values,
        redirect_chain=redirect_chain,
        elapsed_ms=int((monotonic() - started_at) * 1000),
    )


def _configure_session(session: requests.Session) -> None:
    """Aplica as restrições de rede e o identificador local do agente."""
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    session.max_redirects = MAX_REDIRECTS


def fetch(
    target: str,
    *,
    timeout: tuple[float, float] = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
) -> HttpSnapshot:
    """Obtém cabeçalhos e metadados da resposta sem baixar o corpo.

    A verificação de certificado permanece ativa. O corpo não é lido porque
    esta etapa analisa apenas a superfície de cabeçalhos.
    """
    normalized = normalize_target(target)
    display_url = sanitize_url(normalized)
    started_at = monotonic()
    response: requests.Response | None = None
    snapshot: HttpSnapshot | None = None

    try:
        with requests.Session() as session:
            _configure_session(session)
            response = session.get(
                normalized,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=True,
                stream=True,
            )
            snapshot = _snapshot_from_response(response, display_url, started_at)
    except requests.exceptions.Timeout as exc:
        raise HttpRequestError(f"Tempo limite ao acessar {display_url}.") from exc
    except requests.exceptions.TooManyRedirects as exc:
        raise HttpRequestError(
            f"Redirecionamentos excessivos em {display_url} (máximo: {MAX_REDIRECTS})."
        ) from exc
    except requests.exceptions.SSLError as exc:
        raise HttpRequestError(
            f"Falha de validação TLS em {display_url}: {type(exc).__name__}."
        ) from exc
    except (
        requests.exceptions.InvalidURL,
        requests.exceptions.InvalidSchema,
        requests.exceptions.MissingSchema,
    ) as exc:
        raise InvalidTargetError(f"Alvo inválido: {display_url}.") from exc
    except requests.exceptions.RequestException as exc:
        raise HttpRequestError(
            f"Não foi possível acessar {display_url}: {type(exc).__name__}."
        ) from exc
    finally:
        if response is not None:
            response.close()

    if snapshot is None:  # pragma: no cover - defensivo
        raise HttpRequestError(f"Não foi possível obter uma resposta de {display_url}.")

    return snapshot


def fetch_text(
    target: str,
    *,
    timeout: tuple[float, float] = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_bytes: int = MAX_TEXT_BYTES,
) -> HttpTextSnapshot:
    """Obtém uma resposta textual com limite rígido de bytes lidos."""
    normalized = normalize_target(target)
    display_url = sanitize_url(normalized)
    started_at = monotonic()
    limit = max(1, int(max_bytes))
    response: requests.Response | None = None
    snapshot: HttpSnapshot | None = None
    payload = bytearray()
    truncated = False
    content_type = ""
    encoding = "utf-8"

    try:
        with requests.Session() as session:
            _configure_session(session)
            session.headers.update(
                {
                    "Accept": (
                        "text/*, application/xml, application/json;q=0.9, */*;q=0.5"
                    )
                }
            )
            response = session.get(
                normalized,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=True,
                stream=True,
            )
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
            content_type = content_type.strip().lower()
            encoding = response.encoding or "utf-8"

            for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
                if not chunk:
                    continue
                remaining = limit - len(payload)
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    payload.extend(chunk[:remaining])
                    truncated = True
                    break
                payload.extend(chunk)

            snapshot = _snapshot_from_response(response, display_url, started_at)
    except requests.exceptions.Timeout as exc:
        raise HttpRequestError(f"Tempo limite ao acessar {display_url}.") from exc
    except requests.exceptions.TooManyRedirects as exc:
        raise HttpRequestError(
            f"Redirecionamentos excessivos em {display_url} (máximo: {MAX_REDIRECTS})."
        ) from exc
    except requests.exceptions.SSLError as exc:
        raise HttpRequestError(
            f"Falha de validação TLS em {display_url}: {type(exc).__name__}."
        ) from exc
    except (
        requests.exceptions.InvalidURL,
        requests.exceptions.InvalidSchema,
        requests.exceptions.MissingSchema,
    ) as exc:
        raise InvalidTargetError(f"Alvo inválido: {display_url}.") from exc
    except requests.exceptions.RequestException as exc:
        raise HttpRequestError(
            f"Não foi possível acessar {display_url}: {type(exc).__name__}."
        ) from exc
    finally:
        if response is not None:
            response.close()

    if snapshot is None:  # pragma: no cover - defensivo
        raise HttpRequestError(f"Não foi possível obter uma resposta de {display_url}.")

    try:
        body = bytes(payload).decode(encoding, errors="replace")
    except LookupError:
        body = bytes(payload).decode("utf-8", errors="replace")

    return HttpTextSnapshot(
        response=snapshot,
        body=body,
        content_type=content_type,
        truncated=truncated,
        bytes_read=len(payload),
    )
