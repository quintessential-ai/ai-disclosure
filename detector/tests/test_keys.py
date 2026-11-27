"""Fetching the published key set: https all the way, one deadline, a named client."""

from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
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


class _DrippingServer:
    """An https server on 127.0.0.1 that sends one byte at a time, forever.

    It answers every connection with ``prefix`` and then one more byte of
    ``drip`` every 20 ms. One thread serves every connection, so the test
    can count the client's threads.
    """

    def __init__(self, chain: Path, prefix: bytes, drip: bytes) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(chain)
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.02)
        self._prefix, self._drip = prefix, drip
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.url = f"https://127.0.0.1:{self._listener.getsockname()[1]}/jwks.json"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(5)
        self._listener.close()

    def _serve(self) -> None:
        clients: list[ssl.SSLSocket] = []
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
                raw.settimeout(2)
                client = self._context.wrap_socket(raw, server_side=True)
                client.recv(65536)
                client.sendall(self._prefix)
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
    with _DrippingServer(certificates, prefix, drip) as server:
        started = time.monotonic()
        with pytest.raises(KeyLoadError, match="within 0.5s"):
            fetch_jwks(server.url, timeout=0.5)

        assert time.monotonic() - started < 2


def test_a_timed_out_fetch_leaves_nothing_running(certificates: Path) -> None:
    with _DrippingServer(certificates, *_SLOW_HEADERS) as server:
        before = threading.active_count()
        for _ in range(5):
            with pytest.raises(KeyLoadError, match="within 0.2s"):
                fetch_jwks(server.url, timeout=0.2)

        assert threading.active_count() == before


def test_the_test_server_is_trusted(certificates: Path) -> None:
    """The deadline tests above fail for the deadline, not for the certificate."""
    body = json.dumps(golden_jwks()).encode()
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    with _DrippingServer(certificates, prefix, b"") as server:
        assert list(fetch_jwks(server.url, timeout=5)) == ["golden-vectors"]


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
