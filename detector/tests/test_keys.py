"""Fetching the published key set: https all the way, one deadline, a named client."""

from __future__ import annotations

import datetime
import http.client
import ipaddress
import json
import math
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Self

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from helpers import FakeResponse, golden_jwks

from ai_disclosure_verify import keys
from ai_disclosure_verify.jws import jwk_thumbprint, keys_from_jwks, parse_json
from ai_disclosure_verify.keys import KeyLoadError, fetch_jwks, load_jwks_file

URL = keys.DEFAULT_JWKS_URL


class _Redirects(BaseHTTPRequestHandler):
    """``/to-http`` redirects to plain http; anything else serves a key set."""

    def do_GET(self) -> None:  # noqa: N802 - the http.server hook name
        if self.path == "/to-http":
            self.send_response(302)
            self.send_header("Location", f"http://{self.headers['Host']}/jwks")
            self.end_headers()
            return
        body = json.dumps(golden_jwks()).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return None


@pytest.fixture
def server() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Redirects)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def serve(monkeypatch: pytest.MonkeyPatch, body: bytes, url: str = URL) -> list:
    """Make ``keys.urlopen`` answer with ``body`` from ``url``; returns the requests."""
    seen: list[tuple[urllib.request.Request, float]] = []

    def fake(request: urllib.request.Request, deadline: float) -> FakeResponse:
        seen.append((request, deadline))
        return FakeResponse(body, url)

    monkeypatch.setattr(keys, "urlopen", fake)
    return seen


def test_a_redirect_to_plain_http_is_refused(server: str) -> None:
    request = urllib.request.Request(f"{server}/to-http")

    with pytest.raises(KeyLoadError, match="redirects to http://.*not https"):
        keys.urlopen(request, time.monotonic() + 5)


def test_a_redirect_to_https_is_followed() -> None:
    handler = keys._HttpsRedirectHandler()
    request = urllib.request.Request(URL)

    followed = handler.redirect_request(
        request, BytesIO(), 301, "Moved", HTTPMessage(), "https://x.test/jwks.json"
    )

    assert followed is not None
    assert followed.full_url == "https://x.test/jwks.json"


def test_no_redirect_is_followed_after_the_deadline() -> None:
    handler = keys._HttpsRedirectHandler(time.monotonic() - 1)
    request = urllib.request.Request(URL)

    with pytest.raises(TimeoutError):
        handler.redirect_request(
            request, BytesIO(), 301, "Moved", HTTPMessage(), "https://x.test/jwks.json"
        )


def test_a_key_set_served_from_a_plain_http_address_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, json.dumps(golden_jwks()).encode(), "http://x.test/jwks.json")

    with pytest.raises(KeyLoadError, match="served from http://x.test/jwks.json"):
        fetch_jwks()


def test_a_plain_http_address_is_refused_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = serve(monkeypatch, b"{}")

    with pytest.raises(KeyLoadError, match="not https"):
        fetch_jwks("http://x.test/jwks.json")
    assert seen == []


def test_the_fetch_names_itself_and_reads_the_key_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = serve(monkeypatch, json.dumps(golden_jwks()).encode())

    started = time.monotonic()
    assert list(fetch_jwks(timeout=4)) == ["golden-vectors"]

    ((request, deadline),) = seen
    assert request.full_url == URL
    assert started + 4 <= deadline <= time.monotonic() + 4
    # Cloudflare answers 403 to urllib's default "Python-urllib/3.x".
    agent = request.get_header("User-agent") or ""
    assert agent.startswith("ai-disclosure-verify")


def _certificates(directory: Path) -> tuple[Path, Path]:
    """A test CA's certificate, and a key and chain for 127.0.0.1 it issued."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, chain_path = directory / "ca.pem", directory / "server.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    chain_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + leaf.public_bytes(serialization.Encoding.PEM)
    )
    return ca_path, chain_path


class _TlsServer:
    """An https server on 127.0.0.1 that answers every connection with ``prefix``.

    ``answers``, when set before the server starts, replaces ``prefix`` with
    one answer per connection, the last repeated.

    It then sends one more byte of ``drip`` every 20 ms, or closes the
    connection if ``close``. After ``LIFETIME`` seconds it closes every
    connection, so a fetch its deadline fails to end errs instead of hanging.
    """

    LIFETIME = 10.0

    def __init__(
        self, chain: Path, prefix: bytes, drip: bytes = b"", *, close: bool = False
    ) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(chain)
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.02)
        self.answers = [prefix]
        self._drip, self._close = drip, close
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.port = self._listener.getsockname()[1]
        self.url = f"https://127.0.0.1:{self.port}/jwks.json"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(5)
        self._listener.close()

    def _serve(self) -> None:
        clients: list[ssl.SSLSocket] = []
        accepted = 0
        give_up = time.monotonic() + self.LIFETIME
        while not self._stop.is_set() and time.monotonic() < give_up:
            try:
                raw, _ = self._listener.accept()
                raw.settimeout(2)
                client = self._context.wrap_socket(raw, server_side=True)
                client.recv(65536)
                answer = self.answers[min(accepted, len(self.answers) - 1)]
                accepted += 1
                client.sendall(answer)
                if self._close:
                    client.close()
                else:
                    clients.append(client)
            except (TimeoutError, OSError):
                pass
            for client in list(clients):
                try:
                    client.sendall(self._drip)
                except OSError:
                    clients.remove(client)
                    client.close()
        for client in clients:
            client.close()


@pytest.fixture
def certificates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The server chain; the client trusts only the test CA."""
    ca, chain = _certificates(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    return chain


_SLOW_HEADERS = (b"HTTP/1.1 200 OK\r\nX-Slow: ", b"a")
_SLOW_BODY = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    b"Content-Length: 100000\r\n\r\n",
    b" ",
)


@pytest.mark.parametrize(
    ("prefix", "drip"), [_SLOW_HEADERS, _SLOW_BODY], ids=["headers", "body"]
)
def test_a_server_sending_a_byte_at_a_time_meets_the_deadline(
    certificates: Path, prefix: bytes, drip: bytes
) -> None:
    """Every read finishes well within a per-read timeout; the fetch must not."""
    with (
        _TlsServer(certificates, prefix, drip) as server,
        pytest.raises(KeyLoadError, match=r"within 0\.5s: .*timed out"),
    ):
        fetch_jwks(server.url, timeout=0.5)


def test_a_timed_out_fetch_starts_no_thread(
    certificates: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A thread could not be stopped at the deadline, so none is started."""
    started: list[threading.Thread] = []

    def record(thread: threading.Thread) -> None:
        started.append(thread)

    with _TlsServer(certificates, *_SLOW_HEADERS) as server:
        with monkeypatch.context() as patch:
            patch.setattr(threading.Thread, "start", record)
            with pytest.raises(KeyLoadError, match=r"within 0\.2s: .*timed out"):
                fetch_jwks(server.url, timeout=0.2)

    assert started == []


def test_the_test_server_is_trusted(certificates: Path) -> None:
    """The deadline tests above fail for the deadline, not for the certificate."""
    body = json.dumps(golden_jwks()).encode()
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    with _TlsServer(certificates, prefix) as server:
        assert list(fetch_jwks(server.url, timeout=5)) == ["golden-vectors"]


def test_a_refused_address_falls_through_to_the_next(
    certificates: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.dumps(golden_jwks()).encode()
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    with socket.create_server(("127.0.0.1", 0)) as closed:
        refusing = closed.getsockname()
    with _TlsServer(certificates, prefix) as server:
        addresses = [refusing, ("127.0.0.1", server.port)]
        monkeypatch.setattr(socket, "getaddrinfo", _resolving_to(addresses))

        assert list(fetch_jwks(server.url, timeout=5)) == ["golden-vectors"]


def test_an_address_family_the_host_cannot_open_falls_through_to_the_next(
    certificates: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A family number no system implements: creating its socket fails, as
    # IPv6 does on a host without it.
    unsupported = 250
    body = json.dumps(golden_jwks()).encode()
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    with _TlsServer(certificates, prefix) as server:
        answers = [
            (unsupported, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 1)),
            *_resolving_to([("127.0.0.1", server.port)])(),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *_, **__: answers)

        assert list(fetch_jwks(server.url, timeout=5)) == ["golden-vectors"]


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(b"garbage\r\n\r\n", id="bad-status-line"),
        pytest.param(b"HTTP/1.1 200 " + b"a" * 70_000 + b"\r\n", id="line-too-long"),
        pytest.param(
            b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 101 + b"\r\n", id="too-many-headers"
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{",
            id="truncated-body",
        ),
    ],
)
def test_a_malformed_http_response_is_a_key_load_error(
    certificates: Path, answer: bytes
) -> None:
    with (
        _TlsServer(certificates, answer, close=True) as server,
        pytest.raises(KeyLoadError, match="bad HTTP response"),
    ):
        fetch_jwks(server.url, timeout=5)


def _resolving_to(addresses: list[tuple[str, int]]) -> Callable[..., list[tuple]]:
    """A ``socket.getaddrinfo`` that answers every name with ``addresses``."""

    def getaddrinfo(*_: object, **__: object) -> list[tuple]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)
            for address in addresses
        ]

    return getaddrinfo


class _Network:
    """A simulated network on a fake ``time.monotonic`` for keys.py.

    Every name resolves to two addresses of a local listener that never
    answers the TLS handshake. ``connects`` scripts each connect attempt:
    ``("connect", s)`` connects after ``s`` seconds, ``("refuse", s)`` is
    refused after ``s`` seconds and ``("stall", 0)`` waits out its socket
    timeout. A handshake waits out its socket timeout too. Waits only move
    the clock, so a test takes no real time.
    """

    def __init__(self, port: int) -> None:
        self.now = 1000.0
        self.connects: list[tuple[str, float]] = []
        self.attempts = 0
        self.port = port

    def monotonic(self) -> float:
        return self.now

    def connect(self, sock: socket.socket, address: tuple[str, int]) -> None:
        outcome, seconds = self.connects[self.attempts]
        self.attempts += 1
        if outcome == "stall":
            self.now += sock.gettimeout() or 0
            raise TimeoutError("timed out")
        self.now += seconds
        if outcome == "refuse":
            raise ConnectionRefusedError("refused")
        _REAL_CONNECT(sock, address)

    def handshake(self, sock: ssl.SSLSocket, block: bool = False) -> None:
        self.now += sock.gettimeout() or 0
        raise TimeoutError("the handshake timed out")


_REAL_CONNECT = socket.socket.connect


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Network]:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        address = listener.getsockname()
        net = _Network(address[1])
        monkeypatch.setattr(keys, "time", net)
        monkeypatch.setattr(socket, "getaddrinfo", _resolving_to([address] * 2))
        monkeypatch.setattr(
            socket.socket, "connect", lambda sock, to: net.connect(sock, to)
        )
        monkeypatch.setattr(
            ssl.SSLSocket, "do_handshake", lambda sock, block=False: net.handshake(sock)
        )
        yield net


def test_a_slow_connect_leaves_the_handshake_only_what_remains(
    network: _Network,
) -> None:
    network.connects = [("connect", 6)]

    with pytest.raises(KeyLoadError, match="within 10s: the handshake timed out"):
        fetch_jwks("https://key-set.test/jwks.json", timeout=10)

    assert network.now == 1010


def test_an_unreachable_first_address_leaves_no_time_for_the_next(
    network: _Network,
) -> None:
    network.connects = [("stall", 0), ("connect", 0)]

    with pytest.raises(KeyLoadError, match="within 10s: timed out"):
        fetch_jwks("https://key-set.test/jwks.json", timeout=10)

    assert network.now == 1010
    assert network.attempts == 1


def test_a_refused_first_address_leaves_the_next_only_what_remains(
    network: _Network,
) -> None:
    network.connects = [("refuse", 4), ("stall", 0)]

    with pytest.raises(KeyLoadError, match="within 10s: refused"):
        fetch_jwks("https://key-set.test/jwks.json", timeout=10)

    assert network.now == 1010
    assert network.attempts == 2


def test_a_network_error_is_a_key_load_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: object, **__: object) -> FakeResponse:
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(keys, "urlopen", refuse)

    with pytest.raises(KeyLoadError, match="name resolution failed.*--jwks"):
        fetch_jwks()


@pytest.mark.parametrize(
    "body",
    [b'{"keys":[],"keys":[]}', b'{"keys":[{"kty":"OKP","x":NaN}]}'],
    ids=["duplicate_member", "nan"],
)
def test_a_fetched_key_set_is_parsed_strictly(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    serve(monkeypatch, body)

    with pytest.raises(KeyLoadError, match="not valid JSON"):
        fetch_jwks()


def test_a_local_key_set_is_parsed_strictly(tmp_path: Path) -> None:
    path = tmp_path / "jwks.json"
    path.write_text('{"keys":[],"keys":[]}', encoding="utf-8")

    with pytest.raises(KeyLoadError, match="not valid JSON"):
        load_jwks_file(path)


PUBLISHED = Path(__file__).resolve().parents[2] / "public/.well-known"


def published_key_problems(document: object) -> list[str]:
    """Why a key set may not be published: KEYS.md's rules for each entry."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        return ["not a JWKS document"]
    problems = []
    usable = keys_from_jwks(document)
    for index, entry in enumerate(document["keys"]):
        kid = entry.get("kid") if isinstance(entry, dict) else None
        key = usable.get(kid) if isinstance(kid, str) else None
        if key is None:
            problems.append(f"key {index} is not a usable Ed25519 entry with a kid")
        elif kid != jwk_thumbprint(key):
            problems.append(f"key {index}'s kid is not its RFC 7638 thumbprint")
        elif entry.get("use") != "sig" or entry.get("alg") != "EdDSA":
            problems.append(f"key {index} lacks use: sig and alg: EdDSA")
    return problems


def test_the_published_key_set_follows_the_publishing_rules() -> None:
    """A verifier treats a kid as a name; publishing holds it to the thumbprint."""
    path = PUBLISHED / "ai-disclosure-jwks.json"
    document = parse_json(path.read_text(encoding="utf-8"))

    assert published_key_problems(document) == []


def test_the_publishing_rules_catch_a_named_kid() -> None:
    entry = golden_jwks()["keys"][0]
    thumbprint = jwk_thumbprint(keys_from_jwks(golden_jwks())["golden-vectors"])

    assert published_key_problems({"keys": [{**entry, "kid": thumbprint}]}) == []
    assert published_key_problems(golden_jwks()) == [
        "key 0's kid is not its RFC 7638 thumbprint"
    ]
    without_use = {k: v for k, v in entry.items() if k != "use"}
    assert published_key_problems({"keys": [{**without_use, "kid": thumbprint}]}) == [
        "key 0 lacks use: sig and alg: EdDSA"
    ]
    assert published_key_problems({"keys": [{**entry, "use": "enc"}]}) == [
        "key 0 is not a usable Ed25519 entry with a kid"
    ]


@pytest.mark.parametrize("timeout", [0, -1, math.inf, math.nan, 3601])
def test_fetch_takes_a_finite_positive_timeout(
    monkeypatch: pytest.MonkeyPatch, timeout: float
) -> None:
    seen = serve(monkeypatch, json.dumps(golden_jwks()).encode())

    with pytest.raises(ValueError, match="more than 0 and at most 3600"):
        fetch_jwks(timeout=timeout)
    assert seen == []


def _redirect(location: str, body: bytes = b"", code: int = 302) -> bytes:
    head = f"HTTP/1.1 {code} Moved\r\nLocation: {location}\r\n"
    return head.encode() + b"Content-Length: %d\r\n\r\n%s" % (len(body), body)


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_body_is_closed_unread(
    certificates: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """urllib reads a redirect's whole body, with no cap, unless it is closed first."""
    body = json.dumps(golden_jwks()).encode()
    served = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    responses: list[http.client.HTTPResponse] = []
    read: list[tuple[int, int]] = []
    real_begin, real_read = (
        http.client.HTTPResponse.begin,
        http.client.HTTPResponse.read,
    )

    def begin(response: http.client.HTTPResponse) -> None:
        real_begin(response)
        responses.append(response)

    def counting_read(
        response: http.client.HTTPResponse, amt: int | None = None
    ) -> bytes:
        data = real_read(response, amt)
        read.append((response.status, len(data)))
        return data

    monkeypatch.setattr(http.client.HTTPResponse, "begin", begin)
    monkeypatch.setattr(http.client.HTTPResponse, "read", counting_read)
    server = _TlsServer(certificates, b"", close=True)
    over_the_cap = b" " * (2 * keys.MAX_JWKS_BYTES)
    server.answers = [
        _redirect(f"https://127.0.0.1:{server.port}/b", over_the_cap, code),
        served,
    ]

    with server:
        assert list(fetch_jwks(f"https://127.0.0.1:{server.port}/a", timeout=5)) == [
            "golden-vectors"
        ]

    assert [r.status for r in responses] == [code, 200]
    assert all(response.isclosed() for response in responses)
    assert sum(n for status, n in read if status == code) == 0


@pytest.mark.parametrize("location", ["https://[::1/", "https://a..b/"])
def test_a_malformed_redirect_address_is_a_key_load_error(
    certificates: Path, location: str
) -> None:
    with (
        _TlsServer(certificates, _redirect(location), close=True) as server,
        pytest.raises(KeyLoadError, match="redirects to an invalid address"),
    ):
        fetch_jwks(server.url, timeout=5)


class _Body(BytesIO):
    """A response body that, like http.client's, reads empty once closed."""

    def read(self, size: int | None = -1) -> bytes:
        return b"" if self.closed else super().read(size)


def test_a_redirect_past_the_deadline_closes_its_body() -> None:
    handler = keys._HttpsRedirectHandler(time.monotonic() - 1)

    with pytest.raises(TimeoutError):
        handler.http_error_302(
            urllib.request.Request(URL), body := _Body(b"x"), 302, "Found", _location()
        )
    assert body.closed


def test_a_redirect_to_plain_http_closes_its_body() -> None:
    handler = keys._HttpsRedirectHandler()

    with pytest.raises(KeyLoadError, match="not https"):
        handler.http_error_302(
            urllib.request.Request(URL),
            body := _Body(b"x"),
            302,
            "Found",
            _location("http://x.test/jwks.json"),
        )
    assert body.closed


def _location(url: str = "https://x.test/jwks.json") -> HTTPMessage:
    headers = HTTPMessage()
    headers["Location"] = url
    return headers


def test_an_http_error_response_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    body = BytesIO(b"not found")
    # Held here, so collecting the error cannot be what closes its body.
    error = urllib.error.HTTPError(URL, 404, "Not Found", HTTPMessage(), body)

    def not_found(*_: object, **__: object) -> FakeResponse:
        raise error

    monkeypatch.setattr(keys, "urlopen", not_found)

    with pytest.raises(KeyLoadError, match="HTTP 404"):
        fetch_jwks()
    assert body.closed
