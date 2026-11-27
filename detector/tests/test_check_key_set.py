"""The key set check CI runs on every pull request."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Self

import pytest
from check_key_set import main
from helpers import golden_jwks, golden_public_key

from ai_disclosure_verify.jws import jwk_thumbprint
from ai_disclosure_verify.keys import MAX_JWKS_BYTES


def good_entry() -> dict[str, Any]:
    entry = golden_jwks()["keys"][0]
    entry["kid"] = jwk_thumbprint(golden_public_key())
    return entry


def run(tmp_path: Path, document: object, capsys: pytest.CaptureFixture[str]):
    path = tmp_path / "jwks.json"
    path.write_text(
        document if isinstance(document, str) else json.dumps(document),
        encoding="utf-8",
    )
    code = main(["check_key_set", str(path)])
    return code, capsys.readouterr()


def test_empty_key_set_passes(tmp_path: Path, capsys) -> None:
    assert run(tmp_path, {"keys": []}, capsys)[0] == 0


def test_good_key_passes(tmp_path: Path, capsys) -> None:
    code, out = run(tmp_path, {"keys": [good_entry()]}, capsys)
    assert code == 0, out.err


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"d": "AAAA"}, "private 'd'"),
        ({"kid": "golden-vectors"}, "RFC 7638"),
        ({"use": "enc"}, "'use'"),
        ({"alg": "RS256"}, "'alg'"),
    ],
)
def test_bad_key_fails_naming_it(
    tmp_path: Path, capsys, change: dict[str, str], message: str
) -> None:
    entry = good_entry() | change
    code, out = run(tmp_path, {"keys": [entry]}, capsys)
    assert code == 1
    assert message in out.err
    assert f"key 0 (kid {entry['kid']!r})" in out.err


def test_missing_use_and_alg_fail(tmp_path: Path, capsys) -> None:
    entry = good_entry()
    del entry["use"], entry["alg"]
    code, out = run(tmp_path, {"keys": [entry]}, capsys)
    assert code == 1
    assert "'use'" in out.err
    assert "'alg'" in out.err


def test_duplicate_kid_fails(tmp_path: Path, capsys) -> None:
    code, out = run(tmp_path, {"keys": [good_entry(), good_entry()]}, capsys)
    assert code == 1
    assert "duplicate kid" in out.err


def test_non_ed25519_entry_fails(tmp_path: Path, capsys) -> None:
    entry = {"kty": "RSA", "kid": "x", "n": "AQAB", "e": "AQAB"}
    code, out = run(tmp_path, {"keys": [entry]}, capsys)
    assert code == 1
    assert "not an Ed25519" in out.err


def test_wrong_x_fails(tmp_path: Path, capsys) -> None:
    code, out = run(tmp_path, {"keys": [good_entry() | {"x": "AAAA"}]}, capsys)
    assert code == 1
    assert "'x'" in out.err


def test_invalid_json_fails(tmp_path: Path, capsys) -> None:
    code, out = run(tmp_path, '{"keys": [', capsys)
    assert code == 1
    assert "not valid JSON" in out.err


def test_not_a_jwks_fails(tmp_path: Path, capsys) -> None:
    code, out = run(tmp_path, [1], capsys)
    assert code == 1
    assert '"keys" array' in out.err


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param('{"keys": [], "keys": []}', id="repeated member"),
        pytest.param('{"keys": [NaN]}', id="NaN"),
        pytest.param('\ufeff{"keys": []}', id="byte-order mark"),
        pytest.param('{"keys": []' + ', "x": ' + "[" * 40 + "]" * 40 + "}", id="deep"),
    ],
)
def test_json_checkers_refuse_fails(tmp_path: Path, capsys, raw: str) -> None:
    code, out = run(tmp_path, raw, capsys)
    assert code == 1
    assert "not valid JSON" in out.err


def test_entry_checkers_would_skip_fails(tmp_path: Path, capsys) -> None:
    """Well formed, but a checker skips a key it may not use to verify."""
    entry = good_entry() | {"key_ops": ["sign"]}
    code, out = run(tmp_path, {"keys": [entry]}, capsys)
    assert code == 1
    (problem,) = out.err.splitlines()
    assert problem.endswith(
        f"key 0 (kid {entry['kid']!r}): checkers would skip this entry"
    )


def test_missing_kid_fails(tmp_path: Path, capsys) -> None:
    entry = good_entry()
    del entry["kid"]
    code, out = run(tmp_path, {"keys": [entry]}, capsys)
    assert code == 1
    assert "key 0 (kid None): missing 'kid'" in out.err


def test_non_object_entry_fails(tmp_path: Path, capsys) -> None:
    code, out = run(tmp_path, {"keys": [good_entry(), 1]}, capsys)
    assert code == 1
    assert "key 1: not a JSON object" in out.err
    assert "key 0" not in out.err


def test_many_skipped_entries_are_each_named(tmp_path: Path, capsys) -> None:
    """Each entry is checked against the set once, not against every other."""
    entry = good_entry() | {"use": "enc"}
    document = {"keys": [entry | {"kid": f"kid-{i}"} for i in range(5_000)]}

    code, out = run(tmp_path, document, capsys)

    assert code == 1
    assert out.err.count("checkers would skip this entry") == 5_000
    assert "key 4999 (kid 'kid-4999')" in out.err


def test_a_set_at_the_size_cap_passes(tmp_path: Path, capsys) -> None:
    document = '{"keys": []}'
    padded = document + " " * (MAX_JWKS_BYTES - len(document))

    code, out = run(tmp_path, padded, capsys)

    assert code == 0, out.err


def test_a_set_over_the_size_cap_fails_unread(tmp_path: Path, capsys) -> None:
    """Checkers refuse a fetched set over the cap, so it must not pass here."""
    document = '{"keys": []}'
    padded = document + " " * (MAX_JWKS_BYTES - len(document) + 1)

    code, out = run(tmp_path, padded, capsys)

    assert code == 1
    assert f"larger than {MAX_JWKS_BYTES} bytes" in out.err


def test_a_large_file_fails_before_it_is_read(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "jwks.json"
    with path.open("wb") as file:
        file.truncate(64 * MAX_JWKS_BYTES)

    opened = Path.open

    class Unread:
        """The file, open for its size only."""

        def __init__(self, target: Path) -> None:
            self._file = opened(target, "rb")

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            self._file.close()

        def fileno(self) -> int:
            return self._file.fileno()

        def read(self, *_: object) -> bytes:
            raise AssertionError("read")

    monkeypatch.setattr(Path, "open", lambda target, *_: Unread(target))
    code = main(["check_key_set", str(path)])

    assert code == 1
    assert f"larger than {MAX_JWKS_BYTES} bytes" in capsys.readouterr().err


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="no /dev/zero")
def test_an_endless_file_fails_after_the_cap(capsys) -> None:
    """``/dev/zero`` reports no size, so only the bounded read stops it."""
    code = main(["check_key_set", "/dev/zero"])

    assert code == 1
    assert f"larger than {MAX_JWKS_BYTES} bytes" in capsys.readouterr().err
