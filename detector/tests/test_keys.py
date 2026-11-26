"""Fetching the published key set: https all the way, one deadline, a named client."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path

import pytest
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

    def fake(request: urllib.request.Request, timeout: float) -> FakeResponse:
        seen.append((request, timeout))
        return FakeResponse(body, url)

    monkeypatch.setattr(keys, "urlopen", fake)
    return seen


def test_a_redirect_to_plain_http_is_refused(server: str) -> None:
    request = urllib.request.Request(f"{server}/to-http")

    with pytest.raises(KeyLoadError, match="redirects to http://.*not https"):
        keys.urlopen(request, timeout=5)


def test_a_redirect_to_https_is_followed() -> None:
    handler = keys._HttpsRedirectHandler()
    request = urllib.request.Request(URL)

    followed = handler.redirect_request(
        request, BytesIO(), 301, "Moved", HTTPMessage(), "https://x.test/jwks.json"
    )

    assert followed is not None
    assert followed.full_url == "https://x.test/jwks.json"


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

    assert list(fetch_jwks(timeout=4)) == ["golden-vectors"]

    ((request, timeout),) = seen
    assert request.full_url == URL
    assert timeout == 4
    # Cloudflare answers 403 to urllib's default "Python-urllib/3.x".
    agent = request.get_header("User-agent") or ""
    assert agent.startswith("ai-disclosure-verify")


def test_the_whole_fetch_has_one_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()

    def never_answers(_: urllib.request.Request, timeout: float) -> FakeResponse:
        release.wait(30)
        return FakeResponse(b"{}", URL)

    monkeypatch.setattr(keys, "urlopen", never_answers)
    started = time.monotonic()
    try:
        with pytest.raises(KeyLoadError, match="within 0.2s"):
            fetch_jwks(timeout=0.2)
    finally:
        release.set()

    assert time.monotonic() - started < 5


def test_a_slow_body_counts_against_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A server that sends a byte at a time never trips a per-read timeout."""

    stop = threading.Event()

    class Dripping(FakeResponse):
        def read(self, limit: int) -> bytes:
            chunks = []
            while len(chunks) < limit and not stop.wait(0.01):
                chunks.append(b" ")
            return b"".join(chunks)

    monkeypatch.setattr(keys, "urlopen", lambda *_, **__: Dripping(b"", URL))
    try:
        with pytest.raises(KeyLoadError, match="within 0.3s"):
            fetch_jwks(timeout=0.3)
    finally:
        stop.set()


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
