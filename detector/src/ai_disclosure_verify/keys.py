"""Where the verification keys come from: the published key set, or a local file."""

from __future__ import annotations

import functools
import http.client
import importlib.metadata
import math
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Protocol, Self

from ai_disclosure_verify.jws import keys_from_jwks, parse_json

if TYPE_CHECKING:
    from http.client import HTTPMessage

    from _typeshed import WriteableBuffer
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Where the published key set is served. The one place the address lives.
DEFAULT_JWKS_URL = (
    "https://ai-disclosure.complexio.com/.well-known/ai-disclosure-jwks.json"
)
# Connecting, the TLS handshake, every read and every redirect of the fetch
# end within this. Name resolution is not counted.
FETCH_TIMEOUT_SECONDS = 10.0
MAX_FETCH_TIMEOUT_SECONDS = 3600.0


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
        document = parse_json(path.read_bytes())
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

    Every redirect must stay on https. Connecting to each address, the TLS
    handshake, every read and every redirect end within ``timeout`` seconds
    of the call, which must be more than 0 and at most
    ``MAX_FETCH_TIMEOUT_SECONDS``. Name resolution is left to the system
    resolver's own timeout: only a thread could bound it, and that thread
    would outlive the call.
    """
    if not 0 < timeout <= MAX_FETCH_TIMEOUT_SECONDS:
        msg = (
            f"the timeout must be more than 0 and at most "
            f"{MAX_FETCH_TIMEOUT_SECONDS:g} seconds, not {timeout!r}"
        )
        raise ValueError(msg)
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
    """Follows a redirect only to another https address, before ``deadline``."""

    def __init__(self, deadline: float = math.inf) -> None:
        self._deadline = deadline

    def http_error_302(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
    ) -> Any:
        # Closed unread: urllib's own handler reads the whole body first, with
        # no size cap.
        fp.close()
        try:
            return super().http_error_302(req, fp, code, msg, headers)
        except KeyLoadError:
            raise
        except ValueError as exc:
            message = (
                f"the key set at {req.full_url} redirects to an invalid address: {exc}"
            )
            raise KeyLoadError(message) from exc

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

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
        _remaining(self._deadline)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _remaining(deadline: float) -> float:
    """Seconds left before ``deadline`` (``time.monotonic``); TimeoutError when none."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        msg = "timed out"
        raise TimeoutError(msg)
    return remaining


def _connect(
    plain: type[socket.socket], deadline: float, address: tuple[str, int], *_: object
) -> socket.socket:
    """``socket.create_connection``, with every attempt ending by ``deadline``.

    ``create_connection`` gives each address the whole timeout, so an
    unreachable first address could use it up and the next start afresh.
    """
    host, port = address
    errors: list[OSError] = []
    for family, kind, proto, _name, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    ):
        timeout = _remaining(deadline)
        sock = plain(family, kind, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
        except OSError as exc:
            sock.close()
            errors.append(exc)
            continue
        return sock
    if errors:
        raise errors[0]
    msg = f"no address found for {host}"
    raise OSError(msg)


def _connection_class(deadline: float) -> type[http.client.HTTPSConnection]:
    """An HTTPS connection whose connect, TLS handshake and reads end by ``deadline``.

    A per-read timeout alone lets a server that sends a byte at a time hold
    the fetch open for ever. The plain socket also reads a proxy's answer to
    CONNECT.
    """

    class _Plain(socket.socket):
        def recv(self, bufsize: int, flags: int = 0) -> bytes:
            self.settimeout(_remaining(deadline))
            return super().recv(bufsize, flags)

        def recv_into(
            self, buffer: WriteableBuffer, nbytes: int = 0, flags: int = 0
        ) -> int:
            self.settimeout(_remaining(deadline))
            return super().recv_into(buffer, nbytes, flags)

    class _Tls(ssl.SSLSocket):
        def do_handshake(self, block: bool = False) -> None:
            self.settimeout(_remaining(deadline))
            super().do_handshake(block)

        def recv(self, buflen: int = 1024, flags: int = 0) -> bytes:
            self.settimeout(_remaining(deadline))
            return super().recv(buflen, flags)

        def recv_into(
            self, buffer: WriteableBuffer, nbytes: int | None = None, flags: int = 0
        ) -> int:
            self.settimeout(_remaining(deadline))
            return super().recv_into(buffer, nbytes, flags)

    context = ssl.create_default_context()
    context.sslsocket_class = _Tls

    class _Connection(http.client.HTTPSConnection):
        def __init__(self, host: str, **kwargs: Any) -> None:
            kwargs["context"] = context
            super().__init__(host, **kwargs)
            # http.client's hook for making the socket, which connect() calls.
            self._create_connection = functools.partial(_connect, _Plain, deadline)

    return _Connection


class _HttpsHandler(urllib.request.HTTPSHandler):
    """Opens every connection, a redirect's included, to end by ``deadline``."""

    def __init__(self, deadline: float) -> None:
        super().__init__()
        self._connection = _connection_class(deadline)

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(self._connection, req)


class _Response(Protocol):
    def __enter__(self) -> Self: ...
    def __exit__(self, *_: object) -> None: ...
    def geturl(self) -> str: ...
    def read(self, amt: int, /) -> bytes: ...


def urlopen(request: urllib.request.Request, deadline: float) -> _Response:
    """Open ``request``, following https redirects only; tests replace this.

    ``deadline`` is a ``time.monotonic`` value. Connecting to each address,
    the TLS handshake, every read and every redirect end by it.
    """
    opener = urllib.request.build_opener(
        _HttpsRedirectHandler(deadline), _HttpsHandler(deadline)
    )
    return opener.open(request, timeout=_remaining(deadline))


def _fetch_within(url: str, timeout: float) -> bytes:
    """The response body, or ``KeyLoadError`` if it is not read within ``timeout``.

    No thread is involved: on a timeout nothing of the fetch keeps running.
    """
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(  # noqa: S310 - https checked by the caller
        url,
        headers={"Accept": "application/json", "User-Agent": _user_agent()},
    )
    try:
        with urlopen(request, deadline) as response:
            final = response.geturl()
            if not _is_https(final):
                msg = f"the key set at {url} was served from {final}, not https"
                raise KeyLoadError(msg)
            return response.read(MAX_JWKS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        msg = f"could not fetch the key set from {url}: HTTP {exc.code} ({_HINT})"
        raise KeyLoadError(msg) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        msg = (
            f"could not fetch the key set from {url} within {timeout:g}s: "
            f"{reason} ({_HINT})"
        )
        raise KeyLoadError(msg) from exc
    except http.client.HTTPException as exc:
        msg = f"could not fetch the key set from {url}: bad HTTP response {exc!r}"
        msg += f" ({_HINT})"
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
