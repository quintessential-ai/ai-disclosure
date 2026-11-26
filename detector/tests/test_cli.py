"""The command line: key set sources, offline mode and exit codes."""

from __future__ import annotations

import json
import re
import urllib.error
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from helpers import FakeResponse, golden_jwks, signed_vector_body

from ai_disclosure_verify import cli, keys


@pytest.fixture
def eml(tmp_path: Path, vectors: dict[str, Any]) -> Path:
    body, token = signed_vector_body(vectors["signed_as_written"][0])
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "reader@example.test"
    message["Subject"] = "Payment"
    message["X-AI-Generated"] = "true"
    message["X-Complexio-AI-Disclosure"] = token
    # A plain-text alternative with the signed words, as mail clients add one.
    message.set_content(re.sub(r"<[^>]+>", " ", body))
    message.add_alternative(body, subtype="html")
    path = tmp_path / "message.eml"
    path.write_bytes(bytes(message))
    return path


@pytest.fixture
def jwks_file(tmp_path: Path) -> Path:
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(golden_jwks()), encoding="utf-8")
    return path


def test_the_default_key_set_address_lives_in_one_constant() -> None:
    assert keys.DEFAULT_JWKS_URL.startswith("https://")


def test_local_key_set_verifies_a_message(
    eml: Path, jwks_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = cli.main([str(eml), "--jwks", str(jwks_file)])

    assert status == cli.EXIT_VERIFIED
    assert "Verdict: verified" in capsys.readouterr().out


def test_json_report(
    eml: Path, jwks_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main([str(eml), "--jwks", str(jwks_file), "--json"])

    assert json.loads(capsys.readouterr().out)["verdict"] == "verified"


def test_offline_without_a_key_set_reads_as_marked_but_unverified(
    eml: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*_: object, **__: object) -> None:
        raise AssertionError("offline must not touch the network")

    monkeypatch.setattr(keys, "urlopen", no_network)

    status = cli.main([str(eml), "--offline"])

    assert status == cli.EXIT_UNVERIFIED
    assert "Verdict: ai_marked_unverified" in capsys.readouterr().out


def test_default_fetches_the_key_set_from_the_constant(
    eml: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[tuple[str, float | None]] = []
    agents: list[str] = []

    def fake_urlopen(request: Any, timeout: float | None = None) -> FakeResponse:
        seen.append((request.full_url, timeout))
        agents.append(request.get_header("User-agent"))
        return FakeResponse(json.dumps(golden_jwks()).encode(), keys.DEFAULT_JWKS_URL)

    monkeypatch.setattr(keys, "urlopen", fake_urlopen)

    status = cli.main([str(eml), "--timeout", "3"])

    assert status == cli.EXIT_VERIFIED
    assert seen == [(keys.DEFAULT_JWKS_URL, 3.0)]
    # Cloudflare refuses a library's default User-Agent, so the fetch names itself.
    assert [a.partition("/")[0] for a in agents] == ["ai-disclosure-verify"]
    assert "Verdict: verified" in capsys.readouterr().out


def test_unreachable_key_set_is_a_clear_error(
    eml: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(keys, "urlopen", refuse)

    status = cli.main([str(eml)])

    captured = capsys.readouterr()
    assert status == cli.EXIT_ERROR
    assert "could not fetch the key set" in captured.err
    assert "--jwks" in captured.err
    assert captured.out == ""


def test_empty_published_key_set_says_so(
    eml: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        keys, "urlopen", lambda *_, **__: FakeResponse(b"", keys.DEFAULT_JWKS_URL)
    )

    status = cli.main([str(eml)])

    captured = capsys.readouterr()
    assert status == cli.EXIT_ERROR
    assert "is empty" in captured.err
    assert captured.out == ""


def test_message_without_a_signed_marker_needs_no_key_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("no signed marker, no fetch")

    monkeypatch.setattr(keys, "urlopen", refuse)
    path = tmp_path / "plain.html"
    path.write_text("<p>Hello</p>", encoding="utf-8")

    assert cli.main([str(path)]) == cli.EXIT_NO_MARKER


def test_a_differing_plain_text_alternative_is_not_checked(
    eml: Path, jwks_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Mail clients show the HTML; the plain-text alternative is passed over."""
    eml.write_bytes(eml.read_bytes().replace(b"Friday", b"Monday", 1))

    status = cli.main([str(eml), "--jwks", str(jwks_file)])

    assert status == cli.EXIT_VERIFIED
    assert "Content outside the marker: no" in capsys.readouterr().out


def test_missing_file_is_an_error(tmp_path: Path) -> None:
    assert cli.main([str(tmp_path / "absent.eml"), "--offline"]) == cli.EXIT_ERROR


def test_malformed_key_set_is_an_error(
    eml: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")

    assert cli.main([str(eml), "--jwks", str(bad)]) == cli.EXIT_ERROR
