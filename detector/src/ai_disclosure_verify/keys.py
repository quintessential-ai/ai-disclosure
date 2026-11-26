"""Where the verification keys come from: the published key set, or a local file."""

from __future__ import annotations

import importlib.metadata
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import IO, TYPE_CHECKING, Protocol, Self

from ai_disclosure_verify.jws import keys_from_jwks, parse_json

if TYPE_CHECKING:
    from http.client import HTTPMessage

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Where the published key set is served. The one place the address lives.
DEFAULT_JWKS_URL = (
    "https://ai-disclosure.complexio.com/.well-known/ai-disclosure-jwks.json"
)
# The whole fetch, redirects and reading included, must finish within this.
FETCH_TIMEOUT_SECONDS = 10.0


def _user_agent() -> str:
    # Cloudflare refuses a library's default User-Agent (HTTP 403, error 1010).
    try:
        return (
            f"ai-disclosure-verify/{importlib.metadata.version('ai-disclosure-verify')}"
        )
    except importlib.metadata.PackageNotFoundError:
        return "ai-disclosure-verify"


MAX_JWKS_BYTES = 1024 * 1024


class KeyLoadError(ValueError):
    """The key set could not be fetched or read."""


def load_jwks_file(path: Path) -> dict[str, Ed25519PublicKey]:
    """Read the keys from a local JWKS file."""
    try:
        document = parse_json(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"cannot read the key set {path}: {exc.strerror or exc}"
        raise KeyLoadError(msg) from exc
    except ValueError as exc:
        msg = f"the key set {path} is not valid JSON: {exc}"
        raise KeyLoadError(msg) from exc
    return keys_from_jwks(document)


def fetch_jwks(
    url: str = DEFAULT_JWKS_URL, timeout: float = FETCH_TIMEOUT_SECONDS
) -> dict[str, Ed25519PublicKey]:
    """Fetch the key set over HTTPS: one attempt, no retries, no caching.

    Every redirect must stay on https, and the whole fetch must finish within
    ``timeout`` seconds.
    """
    if not _is_https(url):
        msg = f"the key set address {url} is not https"
        raise KeyLoadError(msg)
    body = _fetch_within(url, timeout)
    if len(body) > MAX_JWKS_BYTES:
        msg = f"the key set at {url} is larger than {MAX_JWKS_BYTES} bytes"
        raise KeyLoadError(msg)
    if not body.strip():
        msg = f"the key set at {url} is empty: no signing key is published yet"
        raise KeyLoadError(msg)
    try:
        document = parse_json(body)
    except ValueError as exc:
        msg = f"the key set at {url} is not valid JSON: {exc}"
        raise KeyLoadError(msg) from exc
    return keys_from_jwks(document)


_HINT = "pass --jwks PATH to use a local key set, or --offline to skip the check"


def _is_https(url: str) -> bool:
    return urllib.parse.urlsplit(url).scheme.lower() == "https"


class _HttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to another https address."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _is_https(newurl):
            fp.close()
            message = f"the key set at {req.full_url} redirects to {newurl}, not https"
            raise KeyLoadError(message)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsRedirectHandler)


class _Response(Protocol):
    def __enter__(self) -> Self: ...
    def __exit__(self, *_: object) -> None: ...
    def geturl(self) -> str: ...
    def read(self, amt: int, /) -> bytes: ...


def urlopen(request: urllib.request.Request, timeout: float) -> _Response:
    """Open ``request`` following https redirects only; tests replace this."""
    return _OPENER.open(request, timeout=timeout)


def _fetch_within(url: str, timeout: float) -> bytes:
    """The response body, or ``KeyLoadError`` if it is not read within ``timeout``.

    The socket timeout bounds each read, not the fetch: name resolution is
    not covered, and a server can send a byte at a time. So the fetch runs on
    a daemon thread that is abandoned at the deadline.
    """
    outcome: list[bytes | Exception] = []

    def fetch() -> None:
        try:
            outcome.append(_get(url, timeout))
        except Exception as exc:  # re-raised on the caller's thread
            outcome.append(exc)

    worker = threading.Thread(target=fetch, name="ai-disclosure-jwks", daemon=True)
    worker.start()
    worker.join(timeout)
    if not outcome:
        msg = f"could not fetch the key set from {url} within {timeout:g}s ({_HINT})"
        raise KeyLoadError(msg)
    if isinstance(outcome[0], Exception):
        raise outcome[0]
    return outcome[0]


def _get(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(  # noqa: S310 - https checked by the caller
        url,
        headers={"Accept": "application/json", "User-Agent": _user_agent()},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            final = response.geturl()
            if not _is_https(final):
                msg = f"the key set at {url} was served from {final}, not https"
                raise KeyLoadError(msg)
            return response.read(MAX_JWKS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        msg = f"could not fetch the key set from {url}: HTTP {exc.code} ({_HINT})"
        raise KeyLoadError(msg) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        msg = (
            f"could not fetch the key set from {url} within {timeout:g}s: "
            f"{reason} ({_HINT})"
        )
        raise KeyLoadError(msg) from exc


class LazyKeys(Mapping[str, "Ed25519PublicKey"]):
    """A key set loaded on first use, so a message with no signed marker needs none."""

    def __init__(self, load: Callable[[], dict[str, Ed25519PublicKey]]) -> None:
        self._load = load
        self._keys: dict[str, Ed25519PublicKey] | None = None

    def _resolve(self) -> dict[str, Ed25519PublicKey]:
        if self._keys is None:
            self._keys = self._load()
        return self._keys

    def __getitem__(self, key: str) -> Ed25519PublicKey:
        return self._resolve()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._resolve())

    def __len__(self) -> int:
        return len(self._resolve())
