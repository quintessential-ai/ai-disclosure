"""The JWS and JWKS profile: what a token and a key set must look like to be read.

The reference implementation's tests of the same rules, with the issuer's
``sign_compact`` and ``public_jwk`` written out here.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ai_disclosure_verify import jws
from ai_disclosure_verify.jws import (
    JwksError,
    MalformedTokenError,
    SignatureStatus,
    b64url_decode,
    b64url_encode,
    check_signature,
    decode_compact,
    jwk_thumbprint,
    keys_from_jwks,
    parse_json,
)

_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_KID = jwk_thumbprint(_KEY.public_key())
_KEYS = {_KID: _KEY.public_key()}
_HEADER = {"typ": "ai-disclosure+jwt", "kid": _KID}


def sign_compact(
    payload: Mapping[str, Any], header: Mapping[str, Any], key: Ed25519PrivateKey | None
) -> str:
    """As the issuer signs: ``alg`` added, compact sorted JSON."""

    def compact(value: Mapping[str, Any]) -> bytes:
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    protected = {**header, "alg": "EdDSA" if key is not None else "none"}
    signing_input = f"{_part(compact(protected))}.{_part(compact(payload))}"
    signature = key.sign(signing_input.encode("ascii")) if key is not None else b""
    return f"{signing_input}.{_part(signature)}"


def public_jwk(key: Ed25519PublicKey, kid: str) -> dict[str, str]:
    """As the issuer publishes a key."""
    x = b64url_encode(key.public_bytes_raw())
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


def _part(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _signed(header_json: bytes, payload_json: bytes = b'{"a":1}') -> str:
    signing_input = f"{_part(header_json)}.{_part(payload_json)}"
    signature = _KEY.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{_part(signature)}"


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------


def test_b64url_round_trips_every_length() -> None:
    for length in range(70):
        data = bytes(range(length))
        assert b64url_decode(b64url_encode(data)) == data


@pytest.mark.parametrize("text", ["QR", "QUF", "QUG", "AB", "AAB"])
def test_b64url_refuses_non_zero_trailing_bits(text: str) -> None:
    with pytest.raises(ValueError, match="trailing bits"):
        b64url_decode(text)


@pytest.mark.parametrize("text", ["A", "QQ==", "Q Q", "Q+", "Q/"])
def test_b64url_refuses_what_is_not_unpadded_base64url(text: str) -> None:
    with pytest.raises(ValueError):
        b64url_decode(text)


def test_only_the_canonical_last_signature_character_verifies() -> None:
    token = sign_compact({"a": 1}, _HEADER, _KEY)
    stem = token[:-1]

    verifying = []
    for char in _B64URL:
        try:
            decoded = decode_compact(stem + char)
        except MalformedTokenError:
            continue
        if check_signature(decoded, _KEYS) is SignatureStatus.VALID:
            verifying.append(char)

    assert verifying == [token[-1]]


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":2}',
        '{"o":{"b":1,"b":1}}',
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":-Infinity}',
        '{"a":1e999}',
        '{"a":-1e999}',
        '{"a":' + "1" * 5000 + "}",
        "﻿{}",
    ],
    ids=[
        "duplicate",
        "nested_duplicate",
        "nan",
        "infinity",
        "minus_infinity",
        "float_overflow",
        "minus_float_overflow",
        "integer_too_long",
        "byte_order_mark",
    ],
)
def test_parse_json_refuses_what_rfc_8259_leaves_open(text: str) -> None:
    with pytest.raises(ValueError):
        parse_json(text)


def test_parse_json_refuses_json_nested_past_its_cap() -> None:
    # The cap holds however deep the interpreter's own parser would go.
    for deep in ("[" * 33 + "]" * 33, '{"a":' * 33 + "1" + "}" * 33):
        with pytest.raises(ValueError, match="nested more than 32 deep"):
            parse_json(deep)
    with pytest.raises(ValueError, match="nested more than 32 deep"):
        parse_json("[" * 50_000 + "]" * 50_000)
    assert parse_json("[" * 32 + "]" * 32) is not None


def test_brackets_inside_strings_do_not_count() -> None:
    text = '{"a":"' + "[" * 40 + '\\"{"}'

    assert parse_json(text) == {"a": "[" * 40 + '"{'}


def test_an_unterminated_string_ends_the_depth_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scanning on would retry every later quote, in quadratic time."""
    text = '{"a":"' + '\\"' * 1_000
    tokens: list[str] = []
    pattern = jws._JSON_TOKEN

    class Counting:
        def finditer(self, string: str) -> Iterator[re.Match[str]]:
            for match in pattern.finditer(string):
                tokens.append(match.group())
                yield match

    monkeypatch.setattr(jws, "_JSON_TOKEN", Counting())

    with pytest.raises(ValueError):
        parse_json(text)
    assert tokens == ["{", '"a"', '"']


def test_parse_json_reads_utf8_bytes_only() -> None:
    assert parse_json('{"a":"é"}'.encode()) == {"a": "é"}
    with pytest.raises(ValueError):
        parse_json('{"a":1}'.encode("utf-16"))


@pytest.mark.parametrize(
    ("header", "payload"),
    [
        (b'{"alg":"EdDSA","alg":"none","typ":"ai-disclosure+jwt"}', b'{"a":1}'),
        (b'{"alg":"EdDSA","typ":"ai-disclosure+jwt"}', b'{"mid":"a","mid":"b"}'),
        (b'{"alg":"EdDSA","typ":"ai-disclosure+jwt"}', b'{"iat":NaN}'),
        (b'{"alg":"EdDSA","typ":"ai-disclosure+jwt"}', b'{"iat":1e999}'),
        (b'{"alg":"EdDSA","typ":"ai-disclosure+jwt"}', '{"a":1}'.encode("utf-16")),
    ],
    ids=[
        "duplicate_header",
        "duplicate_claim",
        "nan_claim",
        "overflowing_claim",
        "utf16_payload",
    ],
)
def test_decode_compact_refuses_ambiguous_json(header: bytes, payload: bytes) -> None:
    with pytest.raises(MalformedTokenError):
        decode_compact(_signed(header, payload))


def test_parse_json_reads_finite_floats() -> None:
    assert parse_json('{"a":1.5e308,"b":-2.5}') == {"a": 1.5e308, "b": -2.5}


def _token_of_length(length: int) -> str:
    """A signed token exactly ``length`` characters long."""
    # Base64url skips one length in four; a space in the header shifts it.
    for pad in range(3):
        header = json.dumps({**_HEADER, "alg": "EdDSA"}).encode() + b" " * pad
        for size in range(length * 3 // 4 - 300, length):
            token = _signed(header, b'{"a":"' + b"x" * size + b'"}')
            if len(token) == length:
                return token
            if len(token) > length:
                break
    msg = f"no token is {length} characters"
    raise AssertionError(msg)


def test_a_token_at_the_length_cap_decodes() -> None:
    token = _token_of_length(jws.MAX_TOKEN_CHARS)

    assert check_signature(decode_compact(token), _KEYS) is SignatureStatus.VALID
    # Whitespace around a token is not part of it.
    assert decode_compact(f"  {token}\n").payload == decode_compact(token).payload


def test_a_token_over_the_length_cap_is_malformed() -> None:
    with pytest.raises(MalformedTokenError, match="at most 8192 characters"):
        decode_compact(_token_of_length(jws.MAX_TOKEN_CHARS + 1))


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def test_the_issued_header_verifies() -> None:
    token = decode_compact(sign_compact({"a": 1}, _HEADER, _KEY))

    assert set(token.header) == {"alg", "typ", "kid"}
    assert check_signature(token, _KEYS) is SignatureStatus.VALID


def test_an_issued_unsigned_header_reads_unsigned() -> None:
    token = decode_compact(sign_compact({"a": 1}, {"typ": "ai-disclosure+jwt"}, None))

    assert check_signature(token, _KEYS) is SignatureStatus.UNSIGNED


@pytest.mark.parametrize(
    "extra",
    [
        {"b64": False},
        {"b64": True},
        {"crit": ["b64"], "b64": False},
        {"jku": "https://evil.test/jwks.json"},
        {"jwk": public_jwk(_KEY.public_key(), _KID)},
        {"x5u": "https://evil.test/c.pem"},
        {"cty": "JWT"},
        {"zip": "DEF"},
    ],
    ids=["b64_false", "b64_true", "crit_b64", "jku", "jwk", "x5u", "cty", "zip"],
)
def test_a_header_member_outside_the_profile_invalidates_a_good_signature(
    extra: dict[str, object],
) -> None:
    token = decode_compact(sign_compact({"a": 1}, {**_HEADER, **extra}, _KEY))

    assert check_signature(token, _KEYS) is SignatureStatus.INVALID


def test_a_header_member_outside_the_profile_invalidates_an_unsigned_token() -> None:
    header = {"typ": "ai-disclosure+jwt", "x5u": "https://evil.test/c.pem"}
    token = decode_compact(sign_compact({"a": 1}, header, None))

    assert check_signature(token, _KEYS) is SignatureStatus.INVALID


@pytest.mark.parametrize("kid", [7, None, [_KID], {"k": _KID}])
def test_a_kid_that_is_not_a_string_is_invalid(kid: object) -> None:
    keys = {**_KEYS, str(kid): _KEY.public_key()}
    token = decode_compact(sign_compact({"a": 1}, {**_HEADER, "kid": kid}, _KEY))

    assert check_signature(token, keys) is SignatureStatus.INVALID


# ---------------------------------------------------------------------------
# Key sets
# ---------------------------------------------------------------------------


def _jwk(key: Ed25519PrivateKey = _KEY, /, **changes: object) -> dict[str, object]:
    jwk: dict[str, object] = {**public_jwk(key.public_key(), "k"), **changes}
    return {name: value for name, value in jwk.items() if value is not None}


def test_a_published_entry_is_read_under_its_kid() -> None:
    keys = keys_from_jwks({"keys": [_jwk()]})

    assert list(keys) == ["k"]


def test_an_entry_without_kid_takes_its_thumbprint() -> None:
    assert list(keys_from_jwks({"keys": [_jwk(kid=None)]})) == [_KID]


def test_a_kid_is_a_name_and_need_not_be_the_thumbprint() -> None:
    """RFC 7517 leaves ``kid`` opaque; the key set, not the name, is trusted."""
    assert keys_from_jwks({"keys": [_jwk(kid="example-2026-11")]}) != {}


@pytest.mark.parametrize(
    "changes",
    [
        {"use": "enc"},
        {"use": 1},
        {"alg": "RS256"},
        {"alg": "Ed25519"},
        {"key_ops": ["sign"]},
        {"key_ops": "verify"},
        {"key_ops": []},
        {"kid": 7},
        {"x": "c2hvcnQ"},
        {"x": 7},
        {"x": None},
        {"x": b64url_encode(bytes(32)) + "A"},
    ],
    ids=[
        "use_enc",
        "use_not_a_string",
        "alg_rs256",
        "alg_not_jose_name",
        "key_ops_without_verify",
        "key_ops_not_a_list",
        "key_ops_empty",
        "kid_not_a_string",
        "x_short",
        "x_not_a_string",
        "x_missing",
        "x_not_canonical",
    ],
)
def test_an_unusable_entry_is_skipped_and_the_others_kept(
    changes: dict[str, object],
) -> None:
    other = Ed25519PrivateKey.generate()
    good = _jwk(other, kid="good")

    keys = keys_from_jwks({"keys": [_jwk(**changes), good]})

    assert list(keys) == ["good"]


@pytest.mark.parametrize(
    "changes",
    [{"use": None, "alg": None}, {"key_ops": ["verify"]}, {"key_ops": ["verify", "x"]}],
    ids=["no_use_no_alg", "key_ops_verify", "key_ops_verify_and_more"],
)
def test_optional_members_that_allow_verification_are_accepted(
    changes: dict[str, object],
) -> None:
    assert list(keys_from_jwks({"keys": [_jwk(**changes)]})) == ["k"]


def test_entries_of_other_key_types_and_non_objects_are_skipped() -> None:
    entries = [
        "not-an-object",
        {"kty": "RSA", "kid": "k", "n": "AQAB", "e": "AQAB"},
        {"kty": "OKP", "crv": "X25519", "kid": "x", "x": b64url_encode(bytes(32))},
        _jwk(),
    ]

    keys = keys_from_jwks({"keys": entries})

    assert keys["k"].public_bytes_raw() == _KEY.public_key().public_bytes_raw()
    assert list(keys) == ["k"]


def test_a_kid_on_two_usable_entries_names_no_key() -> None:
    other = Ed25519PrivateKey.generate()

    keys = keys_from_jwks({"keys": [_jwk(), _jwk(other), _jwk(other, kid="b")]})

    assert list(keys) == ["b"]


def test_a_kid_shared_with_another_key_type_is_not_a_duplicate() -> None:
    rsa = {"kty": "RSA", "kid": "k", "n": "AQAB", "e": "AQAB"}

    assert list(keys_from_jwks({"keys": [rsa, _jwk()]})) == ["k"]


def test_a_jwks_names_the_entries_it_skips(caplog: pytest.LogCaptureFixture) -> None:
    broken = {"kty": "OKP", "crv": "Ed25519", "kid": "broken"}
    other = Ed25519PrivateKey.generate()
    twice = _jwk(other, kid="twice")

    with caplog.at_level(logging.WARNING, logger="ai_disclosure_verify.jws"):
        keys = keys_from_jwks({"keys": [_jwk(), broken, twice, twice]})

    assert list(keys) == ["k"]
    # The kid comes from the key set, so it is a field, not message text.
    logged = [
        (r.getMessage(), getattr(r, "entry", None), getattr(r, "kid", None))
        for r in caplog.records
    ]
    assert logged == [
        ("JWKS Ed25519 entry not usable, skipped", 1, None),
        ("JWKS kid names more than one key, skipped", None, "twice"),
    ]


def test_a_jwks_of_other_key_types_only_is_empty_not_an_error() -> None:
    assert keys_from_jwks({"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}]}) == {}


@pytest.mark.parametrize("jwks", [[], {"keys": "nope"}, {"key": []}, "x", None])
def test_a_document_that_is_not_a_jwks_raises(jwks: object) -> None:
    with pytest.raises(JwksError):
        keys_from_jwks(jwks)


def test_the_issued_jwks_entry_parses_strictly() -> None:
    document = json.dumps({"keys": [public_jwk(_KEY.public_key(), _KID)]})

    assert list(keys_from_jwks(parse_json(document))) == [_KID]
