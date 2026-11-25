"""Helpers: the golden vectors and the test key that signed them."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "ai_disclosure_vectors.json"

# The vectors' signed entries were produced with this key and id. Ed25519
# signing is deterministic, so the same bytes reproduce the same tokens. The
# key signs nothing outside these vectors.
GOLDEN_KID = "golden-vectors"
_GOLDEN_SEED = bytes(range(32))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _compact(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def golden_public_key() -> Ed25519PublicKey:
    return Ed25519PrivateKey.from_private_bytes(_GOLDEN_SEED).public_key()


def golden_jwks() -> dict[str, Any]:
    raw = golden_public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url(raw),
                "kid": GOLDEN_KID,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    }


def golden_token(claims: dict[str, Any]) -> str:
    """A compact JWS over ``claims``, signed with the vectors' test key."""
    header = {"typ": "ai-disclosure+jwt", "kid": GOLDEN_KID, "alg": "EdDSA"}
    signing_input = f"{_b64url(_compact(header))}.{_b64url(_compact(claims))}"
    signature = Ed25519PrivateKey.from_private_bytes(_GOLDEN_SEED).sign(
        signing_input.encode("ascii")
    )
    return f"{signing_input}.{_b64url(signature)}"


def signed_vector_claims(
    vector: dict[str, Any], canon: str = "text-links/2"
) -> dict[str, Any]:
    expected = vector["expected"]
    return {
        "spec": "complexio-ai-disclosure/1",
        "ai_generated": True,
        "generator": "Complexio Enterprise Automator",
        "on_behalf_of": "the company",
        "iat": 1794238200,
        "mid": vector["input"]["mid"],
        "canon": canon,
        "content_sha256": expected["content_sha256"],
    }


def signed_vector_body(
    vector: dict[str, Any], canon: str = "text-links/2"
) -> tuple[str, str]:
    """The HTML body and the token of a ``signed_as_written`` vector."""
    token = golden_token(signed_vector_claims(vector, canon))
    marker = (
        f'<div data-ai-disclosure="{token}" style="display:none" '
        'aria-hidden="true"></div>'
    )
    return vector["expected"]["content_html"] + marker, token
