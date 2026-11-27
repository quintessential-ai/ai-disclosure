"""text-links/2's URL serialisation against WHATWG's own URL test data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ai_disclosure_verify.canonical import (
    _serialise_http_url,
    normalise_url,
    serialise_url,
)

_CASES: list[dict[str, Any]] = json.loads(
    (Path(__file__).parent / "whatwg" / "urltestdata-http.json").read_text("utf-8")
)


@pytest.mark.parametrize(
    "case", _CASES, ids=[repr(case["input"])[:60] for case in _CASES]
)
def test_whatwg_url_test_data(case: dict[str, Any]) -> None:
    """Every http(s) input it handles gives WHATWG's href; it declines the rest."""
    url = normalise_url(case["input"])
    assert url.lower().startswith(("http://", "https://"))
    serialised = _serialise_http_url(url)
    if serialised is None:
        assert serialise_url(url) == url
    else:
        assert not case.get("failure"), "serialised a URL WHATWG refuses"
        assert serialised == case["href"]


def test_the_test_data_exercises_the_serialisation() -> None:
    handled = [c for c in _CASES if _serialise_http_url(normalise_url(c["input"]))]
    changed = [c for c in handled if c["href"] != normalise_url(c["input"])]
    assert len(handled) >= 100
    assert len(changed) >= 50


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.test/a^b", "https://x.test/a%5Eb"),
        ("https://x.test/p?a^b", "https://x.test/p?a^b"),
        ("https://x.test/p#a^b", "https://x.test/p#a^b"),
    ],
    ids=["path", "query", "fragment"],
)
def test_a_caret_is_percent_encoded_in_a_path_only(url: str, expected: str) -> None:
    """WHATWG percent-encodes ``^`` in a path, not in a query or fragment.

    The test data checks it only for other schemes (``wss:``, ``foo:``), so it
    is pinned here for https.
    """
    assert serialise_url(url) == expected
