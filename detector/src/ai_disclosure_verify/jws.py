# Generated from the reference implementation. Do not edit by hand:
# changes are made there and regenerated.
"""Compact JWS (RFC 7515) with EdDSA over Ed25519 (RFC 8037), and JWK helpers.

Only what the disclosure marker needs: one algorithm (``EdDSA``), the
unsecured form (``alg: none``) for an unsigned marker, OKP keys, and RFC 7638
thumbprints for key ids. Implemented on ``cryptography`` rather than a JOSE
library, so a verifier can audit the whole path in one file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

ALG_EDDSA = "EdDSA"
ALG_NONE = "none"

# The protected header members this profile uses. Any other member, ``b64``
# and ``crit`` included, makes the token invalid: a member a verifier ignores
# may be one another verifier acts on.
HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})

# Arrays and objects nested deeper than this make JSON unreadable here. A
# token or key set needs three levels; Python's own recursion limit differs
# between versions, so it cannot be the bound.
MAX_JSON_DEPTH = 32
# A longer token is malformed, and the issuer issues none over this.
MAX_TOKEN_CHARS = 8192
# A whole string, a bracket, or a quote that opens a string never closed.
_JSON_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]|"', re.DOTALL)

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class MalformedTokenError(ValueError):
    """The token is not a three-part compact JWS with JSON header and payload."""


class JwksError(ValueError):
    """The key set is not a usable JWKS document."""


class SignatureStatus(StrEnum):
    """Outcome of checking a token's signature."""

    VALID = "valid"
    INVALID = "invalid"
    UNSIGNED = "unsigned"
    UNKNOWN_KEY = "unknown_key"
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class DecodedToken:
    """A compact JWS split into its parts, signature not yet checked."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signing_input: bytes
    signature: bytes


def b64url_encode(data: bytes) -> str:
    """Base64url without padding (RFC 7515 section 2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url; raises ``ValueError`` on bad input.

    Only the canonical encoding is accepted: the unused bits of the last
    character must be zero, so each byte string has one spelling.
    """
    if any(c not in _B64URL_ALPHABET for c in text):
        msg = "not base64url"
        raise ValueError(msg)
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except binascii.Error as exc:
        raise ValueError(str(exc)) from exc
    if b64url_encode(data) != text:
        msg = "non-zero trailing bits"
        raise ValueError(msg)
    return data


def parse_json(data: str | bytes) -> object:
    """Parse UTF-8 JSON text, refusing what RFC 8259 leaves to the parser.

    Raises ``ValueError`` for such text and for nesting deeper than
    ``MAX_JSON_DEPTH``.
    """
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    _check_depth(text)
    return json.loads(
        text,
        object_pairs_hook=_unique_members,
        parse_constant=_refuse_constant,
        parse_float=_finite_float,
    )


def _check_depth(text: str) -> None:
    depth = 0
    for match in _JSON_TOKEN.finditer(text):
        token = match.group()
        if token == '"':
            # Not JSON: the parser rejects it, within the depth counted so
            # far. Scanning on would retry every later quote.
            return
        if token[0] == '"':
            continue
        depth += 1 if token in "[{" else -1
        if depth > MAX_JSON_DEPTH:
            msg = f"JSON nested more than {MAX_JSON_DEPTH} deep"
            raise ValueError(msg)


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    members = dict(pairs)
    if len(members) != len(pairs):
        msg = "duplicate member name"
        raise ValueError(msg)
    return members


def _refuse_constant(name: str) -> NoReturn:
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        msg = f"{text} is out of range for a float"
        raise ValueError(msg)
    return value


def _compact_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def decode_compact(token: str) -> DecodedToken:
    """Split and JSON-decode a compact JWS without checking the signature.

    A token longer than ``MAX_TOKEN_CHARS`` is malformed.
    """
    token = token.strip()
    if len(token) > MAX_TOKEN_CHARS:
        msg = f"a token is at most {MAX_TOKEN_CHARS} characters"
        raise MalformedTokenError(msg)
    parts = token.split(".")
    if len(parts) != 3:
        msg = "a compact JWS has exactly three dot-separated parts"
        raise MalformedTokenError(msg)
    try:
        header = parse_json(b64url_decode(parts[0]))
        payload = parse_json(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except ValueError as exc:
        raise MalformedTokenError(str(exc)) from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        msg = "JWS header and payload must be JSON objects"
        raise MalformedTokenError(msg)
    return DecodedToken(
        header=header,
        payload=payload,
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature=signature,
    )


def check_signature(
    token: DecodedToken, keys: Mapping[str, Ed25519PublicKey] | None
) -> SignatureStatus:
    """Check ``token`` against ``keys`` (kid to public key).

    ``keys=None`` means the caller has no key set, so a signed token is
    reported ``NOT_CHECKED`` rather than valid. A header member other than
    ``HEADER_MEMBERS`` (``crit`` and ``b64`` among them), a ``kid`` that is
    not a string, or an algorithm other than ``EdDSA``/``none`` is
    ``INVALID``: this profile understands no extensions.
    """
    alg = token.header.get("alg")
    if not HEADER_MEMBERS.issuperset(token.header):
        return SignatureStatus.INVALID
    kid = token.header.get("kid", "")
    if not isinstance(kid, str):
        return SignatureStatus.INVALID
    if alg == ALG_NONE:
        if token.signature:
            return SignatureStatus.INVALID
        return SignatureStatus.UNSIGNED
    if alg != ALG_EDDSA:
        return SignatureStatus.INVALID
    if keys is None:
        return SignatureStatus.NOT_CHECKED
    key = keys.get(kid)
    if key is None:
        return SignatureStatus.UNKNOWN_KEY
    try:
        key.verify(token.signature, token.signing_input)
    except InvalidSignature:
        return SignatureStatus.INVALID
    return SignatureStatus.VALID


def jwk_thumbprint(key: Ed25519PublicKey) -> str:
    """RFC 7638 thumbprint (SHA-256, base64url) of the key's OKP JWK."""
    members = {"crv": "Ed25519", "kty": "OKP", "x": b64url_encode(_raw_public(key))}
    return b64url_encode(hashlib.sha256(_compact_json(members)).digest())


def keys_from_jwks(jwks: object) -> dict[str, Ed25519PublicKey]:
    """Read the Ed25519 verification keys of a JWKS document, keyed by ``kid``.

    As RFC 7517 section 5 asks, an entry this profile cannot use is skipped
    rather than failing the set (``_verification_key`` says which). An
    Ed25519 entry without a ``kid`` takes its RFC 7638 thumbprint. The
    ``kid`` is a name: it is not compared with the thumbprint. A ``kid``
    that two usable entries share names no key, since either could be meant.
    An Ed25519 entry skipped, and a shared ``kid``, are logged as warnings:
    a marker signed with that key would otherwise read as an unknown key.

    Raises:
        JwksError: The document is not a JSON object with a ``keys`` array.

    """
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        msg = 'JWKS must be a JSON object with a "keys" array'
        raise JwksError(msg)
    keys: dict[str, Ed25519PublicKey] = {}
    shared: set[str] = set()
    for position, entry in enumerate(jwks["keys"]):
        claims_ed25519 = (
            isinstance(entry, dict)
            and entry.get("kty") == "OKP"
            and entry.get("crv") == "Ed25519"
        )
        key = _verification_key(entry)
        if key is None:
            if claims_ed25519:
                logger.warning(
                    "JWKS entry %d: Ed25519 key not usable, skipped", position
                )
            continue
        kid = entry.get("kid") or jwk_thumbprint(key)
        if kid in keys:
            shared.add(kid)
        keys[kid] = key
    for kid in sorted(shared):
        logger.warning("JWKS kid %r names more than one key, skipped", kid)
    return {kid: key for kid, key in keys.items() if kid not in shared}


def _verification_key(entry: object) -> Ed25519PublicKey | None:
    """The Ed25519 key of one JWKS entry, or None when it is not usable here."""
    if not isinstance(entry, dict):
        return None
    if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
        return None
    if entry.get("use", "sig") != "sig" or entry.get("alg", ALG_EDDSA) != ALG_EDDSA:
        return None
    key_ops = entry.get("key_ops", ["verify"])
    if not isinstance(key_ops, list) or "verify" not in key_ops:
        return None
    if not isinstance(entry.get("kid", ""), str):
        return None
    x = entry.get("x")
    if not isinstance(x, str):
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(b64url_decode(x))
    except ValueError:
        return None


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
