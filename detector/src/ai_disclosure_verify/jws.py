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
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from collections.abc import Mapping

ALG_EDDSA = "EdDSA"
ALG_NONE = "none"

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
    """Decode unpadded base64url; raises ``ValueError`` on bad input."""
    if any(c not in _B64URL_ALPHABET for c in text):
        msg = "not base64url"
        raise ValueError(msg)
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except binascii.Error as exc:
        raise ValueError(str(exc)) from exc


def _compact_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def decode_compact(token: str) -> DecodedToken:
    """Split and JSON-decode a compact JWS without checking the signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        msg = "a compact JWS has exactly three dot-separated parts"
        raise MalformedTokenError(msg)
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
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
    reported ``NOT_CHECKED`` rather than valid. A ``crit`` header or an
    algorithm other than ``EdDSA``/``none`` is ``INVALID``: this profile
    understands no extensions.
    """
    alg = token.header.get("alg")
    if "crit" in token.header:
        return SignatureStatus.INVALID
    if alg == ALG_NONE:
        if token.signature:
            return SignatureStatus.INVALID
        return SignatureStatus.UNSIGNED
    if alg != ALG_EDDSA:
        return SignatureStatus.INVALID
    if keys is None:
        return SignatureStatus.NOT_CHECKED
    key = keys.get(str(token.header.get("kid", "")))
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
    """Read the Ed25519 keys of a JWKS document, keyed by ``kid``.

    Entries of other key types are skipped, so a shared JWKS can carry them.
    An Ed25519 entry without a ``kid`` takes its RFC 7638 thumbprint.

    Raises:
        JwksError: The document is not a JWKS object, or an Ed25519 entry has
            no valid 32-byte ``x``.

    """
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        msg = 'JWKS must be a JSON object with a "keys" array'
        raise JwksError(msg)
    keys: dict[str, Ed25519PublicKey] = {}
    for index, entry in enumerate(jwks["keys"]):
        if not isinstance(entry, dict):
            msg = f"JWKS key {index} is not an object"
            raise JwksError(msg)
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            continue
        try:
            raw = b64url_decode(entry["x"])
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (KeyError, TypeError, ValueError) as exc:
            msg = f"JWKS key {index} has no valid Ed25519 'x'"
            raise JwksError(msg) from exc
        keys[str(entry.get("kid") or jwk_thumbprint(key))] = key
    return keys


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
