"""Fixtures."""

from __future__ import annotations

import json
from typing import Any

import pytest
from helpers import VECTORS

_PROXY_VARIABLES = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
)


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fetch tests talk to servers on this host, never through a proxy."""
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.setenv(name, "127.0.0.1,localhost")


@pytest.fixture(scope="session")
def vectors() -> dict[str, Any]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))
