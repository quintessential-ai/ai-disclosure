"""Where the verification keys come from: the published key set, or a local file."""

from __future__ import annotations

import importlib.metadata
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ai_disclosure_verify.jws import keys_from_jwks

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Where the published key set is served. The one place the address lives.
DEFAULT_JWKS_URL = (
    "https://ai-disclosure.complexio.com/.well-known/ai-disclosure-jwks.json"
)
FETCH_TIMEOUT_SECONDS = 10.0


def _user_agent() -> str:
    # Cloudflare refuses a library's default User-Agent (error 1010).
    try:
        return (
            f"ai-disclosure-verify/{importlib.metadata.version('ai-disclosure-verify')}"
        )
    except importlib.metadata.PackageNotFoundError:
        return "ai-disclosure-verify"


MAX_JWKS_BYTES = 1024 * 1024


class KeyLoadError(ValueError):
    """The key set could not be fetched or read."""


def load_jwks_file(path: Path) -> dict[str, Ed25519PublicKey]:
    """Read the keys from a local JWKS file."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"cannot read the key set {path}: {exc.strerror or exc}"
        raise KeyLoadError(msg) from exc
    except ValueError as exc:
        msg = f"the key set {path} is not valid JSON: {exc}"
        raise KeyLoadError(msg) from exc
    return keys_from_jwks(document)


def fetch_jwks(
    url: str = DEFAULT_JWKS_URL, timeout: float = FETCH_TIMEOUT_SECONDS
) -> dict[str, Ed25519PublicKey]:
    """Fetch the key set over HTTPS: one attempt, no retries, no caching."""
    hint = "pass --jwks PATH to use a local key set, or --offline to skip the check"
    if urllib.parse.urlsplit(url).scheme != "https":
        msg = f"the key set address {url} is not https"
        raise KeyLoadError(msg)
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        headers={"Accept": "application/json", "User-Agent": _user_agent()},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(MAX_JWKS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        msg = f"could not fetch the key set from {url}: HTTP {exc.code} ({hint})"
        raise KeyLoadError(msg) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        msg = (
            f"could not fetch the key set from {url} within {timeout:g}s: "
            f"{reason} ({hint})"
        )
        raise KeyLoadError(msg) from exc
    if len(body) > MAX_JWKS_BYTES:
        msg = f"the key set at {url} is larger than {MAX_JWKS_BYTES} bytes"
        raise KeyLoadError(msg)
    if not body.strip():
        msg = f"the key set at {url} is empty: no signing key is published yet"
        raise KeyLoadError(msg)
    try:
        document = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        msg = f"the key set at {url} is not valid JSON: {exc}"
        raise KeyLoadError(msg) from exc
    return keys_from_jwks(document)


class LazyKeys(Mapping[str, "Ed25519PublicKey"]):
    """A key set loaded on first use, so a message with no signed marker needs none."""

    def __init__(self, load: Callable[[], dict[str, Ed25519PublicKey]]) -> None:
        self._load = load
        self._keys: dict[str, Ed25519PublicKey] | None = None

    def _resolve(self) -> dict[str, Ed25519PublicKey]:
        if self._keys is None:
            self._keys = self._load()
        return self._keys

    def __getitem__(self, key: str) -> Ed25519PublicKey:
        return self._resolve()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._resolve())

    def __len__(self) -> int:
        return len(self._resolve())
