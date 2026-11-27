"""Which marker is the message's own: unreadable tokens, removed containers, headers."""

from __future__ import annotations

import base64
import html
from typing import Any

import pytest
from helpers import GOLDEN_KID, golden_public_key, signed_vector_body

from ai_disclosure_verify import Carrier, Placement, SignatureStatus, Verdict
from ai_disclosure_verify.detect import ContentCheck, detect_html

KEYS = {GOLDEN_KID: golden_public_key()}


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def _block(value: str) -> str:
    return (
        f'<div data-ai-disclosure="{html.escape(value)}" style="display:none" '
        'aria-hidden="true"></div>'
    )


@pytest.fixture
def signed(vectors: dict[str, Any]) -> tuple[str, str]:
    """The HTML body (container and block) and token of the first signed vector."""
    return signed_vector_body(vectors["signed_as_written"][0])


_HEADER = _b64('{"alg":"EdDSA","typ":"ai-disclosure+jwt"}')
_EMPTY = _b64("{}")
_REPEATED = _b64('{"a":1,"a":2}')
_NAN = _b64('{"iat":NaN}')

UNDECODABLE = [
    pytest.param(f"{_HEADER}.{_EMPTY}", id="two-parts"),
    pytest.param(f"{_b64('not json')}.{_EMPTY}.", id="header-not-json"),
    pytest.param(f"{_HEADER}.{_REPEATED}.", id="repeated-member"),
    pytest.param(f"{_HEADER}.{_NAN}.", id="nan"),
    pytest.param(f"{_HEADER}.!!!.", id="not-base64url"),
]


@pytest.mark.parametrize("token", UNDECODABLE)
@pytest.mark.parametrize("before", ["", "<p>Thanks</p>"], ids=["leading", "after-text"])
def test_an_undecodable_body_token_is_marked_unverified(
    token: str, before: str
) -> None:
    """A marker attempt is present, though nothing in it can be read."""
    report = detect_html(before + _block(token), KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    (finding,) = report.findings
    assert finding.placement is Placement.UNKNOWN
    assert finding.error is not None
    assert finding.error.startswith("malformed token")


def test_an_undecodable_body_token_beside_a_verifying_original_is_unmarked(
    signed: tuple[str, str],
) -> None:
    body, _ = signed

    report = detect_html(body + _block(f"{_HEADER}.!!!."), KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_a_leading_marker_whose_container_was_removed_is_the_original(
    signed: tuple[str, str],
) -> None:
    _, token = signed

    report = detect_html(f"<html><body>{_block(token)}</body></html>", KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    (finding,) = report.findings
    assert finding.placement is Placement.ORIGINAL
    assert finding.signature is SignatureStatus.VALID
    assert finding.content is ContentCheck.NOT_FOUND


@pytest.mark.parametrize(
    ("before", "after"),
    [
        pytest.param("<p>Thanks</p>", "", id="after-text"),
        pytest.param("<blockquote>", "</blockquote>", id="in-blockquote"),
    ],
)
def test_a_marker_that_does_not_lead_without_its_container_is_quoted(
    signed: tuple[str, str], before: str, after: str
) -> None:
    _, token = signed

    report = detect_html(before + _block(token) + after, KEYS)

    assert report.verdict is Verdict.QUOTED_ONLY
    (finding,) = report.findings
    assert finding.placement is Placement.QUOTED


def test_a_leading_marker_without_its_container_yields_to_a_leading_container(
    vectors: dict[str, Any], signed: tuple[str, str]
) -> None:
    body, token = signed
    _, other = signed_vector_body(vectors["signed_as_written"][1])

    report = detect_html(_block(other) + body, KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    stray, own = report.findings
    assert stray.placement is Placement.QUOTED
    assert own.placement is Placement.ORIGINAL
    assert own.verified


def test_a_garbage_header_token_beside_a_verifying_body_is_reported(
    signed: tuple[str, str],
) -> None:
    body, _ = signed

    report = detect_html(body, KEYS, header_token="garbage")

    assert report.verdict is Verdict.VERIFIED
    header, own = report.findings
    assert header.carrier is Carrier.HEADER
    assert header.signature is SignatureStatus.INVALID
    assert header.error is not None
    assert header.error.startswith("malformed token")
    assert own.verified
    assert "rejected: malformed token" in report.describe()
    assert report.to_dict()["findings"][0]["signature"] == "invalid"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param('{"ai_generated": true, "ai_generated": false}', id="repeated"),
        pytest.param('{"ai_generated": NaN}', id="nan"),
        pytest.param('{"n": ' + "1" * 5000 + "}", id="long-integer"),
        pytest.param('{"a": ' + "[" * 50_000 + "]" * 50_000 + "}", id="deep"),
    ],
)
def test_an_unreadable_legacy_marker_is_malformed(value: str) -> None:
    report = detect_html(_block(value))

    assert report.verdict is Verdict.UNVERIFIED
    (finding,) = report.findings
    assert finding.legacy
    assert finding.error is not None
    assert finding.error.startswith("malformed legacy marker")


def test_a_quoted_legacy_marker_beside_a_verifying_original_is_unmarked(
    signed: tuple[str, str],
) -> None:
    body, _ = signed
    legacy = '{"ai_generated": true, "spec": "EU-AI-Act-Article-50"}'

    report = detect_html(f"{body}<blockquote>{_block(legacy)}</blockquote>", KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    own, quoted = report.findings
    assert own.verified
    assert quoted.legacy
    assert quoted.placement is Placement.UNKNOWN
