"""Check the published key set before it goes live.

Usage: python scripts/check_key_set.py [PATH]

PATH defaults to ``public/.well-known/ai-disclosure-jwks.json`` in this
repository. Exits 0 when the set is sound (an empty set is sound), 1 with one
line per problem otherwise. The rules are those of KEYS.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ai_disclosure_verify.jws import JwksError, jwk_thumbprint, keys_from_jwks

DEFAULT_PATH = (
    Path(__file__).resolve().parents[2]
    / "public"
    / ".well-known"
    / "ai-disclosure-jwks.json"
)


def check_key_set(document: object) -> list[str]:
    """Return one message per problem in the key set; empty when it is sound."""
    try:
        keys = keys_from_jwks(document)
    except JwksError as exc:
        return [str(exc)]
    assert isinstance(document, dict)  # keys_from_jwks accepted it

    problems: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(document["keys"]):
        kid = entry.get("kid")
        name = f"key {index} (kid {kid!r})"
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            problems.append(f"{name}: not an Ed25519 OKP key")
            continue
        if "d" in entry:
            problems.append(f"{name}: has a private 'd' member")
        if entry.get("use") != "sig":
            problems.append(f"{name}: 'use' must be 'sig', got {entry.get('use')!r}")
        if entry.get("alg") != "EdDSA":
            problems.append(f"{name}: 'alg' must be 'EdDSA', got {entry.get('alg')!r}")
        if not isinstance(kid, str) or not kid:
            problems.append(f"{name}: missing 'kid'")
            continue
        if kid in seen:
            problems.append(f"{name}: duplicate kid")
        seen.add(kid)
        expected = jwk_thumbprint(keys[kid])
        if kid != expected:
            problems.append(f"{name}: kid is not the RFC 7638 thumbprint {expected}")
    return problems


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"{path}: cannot read: {exc.strerror or exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"{path}: not valid JSON: {exc}", file=sys.stderr)
        return 1
    problems = check_key_set(document)
    for problem in problems:
        print(f"{path}: {problem}", file=sys.stderr)
    if not problems:
        count = len(document["keys"])
        print(f"{path}: ok ({count} key{'s' if count != 1 else ''})")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
