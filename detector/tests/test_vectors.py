"""Run the golden vectors through the verify-only detector."""

from __future__ import annotations

import json
from typing import Any

import pytest
from helpers import GOLDEN_KID, VECTORS, golden_public_key, signed_vector_body

from ai_disclosure_verify import ContentCheck, SignatureStatus, Verdict, detect_html
from ai_disclosure_verify.canonical import (
    CANONICALISATION,
    CANONICALISATION_V1,
    CONTENT_ATTR,
    canonical_as,
    digest_of_canonical,
    scan_html,
)

MID = "0" * 32


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    for section in ("canonical", "label", "signed_as_written"):
        if section in metafunc.fixturenames:
            metafunc.parametrize(
                section, [pytest.param(v, id=v["name"]) for v in data[section]]
            )


def test_vectors_name_the_supported_canonicalisation(vectors: dict[str, Any]) -> None:
    assert vectors["canonicalisation"] == CANONICALISATION


def test_canonical_vector(canonical: dict[str, Any]) -> None:
    container = f'<div {CONTENT_ATTR}="{MID}">{canonical["balanced"]}</div>'
    scan = scan_html(container)

    region_canonical = canonical_as(scan.regions[MID].canonical, CANONICALISATION)
    located = (v.located(MID) for v in scan.violations)
    first_violation = next((n for n in located if n.startswith("inside:")), None)

    assert region_canonical == canonical["canonical"]
    assert digest_of_canonical(region_canonical) == canonical["content_sha256"]
    assert first_violation == canonical["first_violation"]


def test_label_vector_reads_as_marked_but_unsigned(label: dict[str, Any]) -> None:
    expected = label["expected"]
    mid = label["input"]["mid"]
    report = detect_html(expected["html_body"])

    (finding,) = report.findings
    assert report.verdict is Verdict.UNVERIFIED
    assert finding.signature is SignatureStatus.UNSIGNED
    assert finding.content is ContentCheck.MATCH
    assert finding.claims["mid"] == mid
    assert finding.claims["content_sha256"] == expected["content_sha256"]
    canonical = canonical_as(
        scan_html(expected["html_body"]).regions[mid].canonical, CANONICALISATION
    )
    assert canonical == expected["canonical"]
    assert digest_of_canonical(canonical) == expected["content_sha256"]


def test_signed_vector_verifies_to_the_expected_verdict(
    signed_as_written: dict[str, Any],
) -> None:
    expected = signed_as_written["expected"]
    body, token = signed_vector_body(signed_as_written)
    keys = {GOLDEN_KID: golden_public_key()}

    report = detect_html(body, keys)

    (finding,) = report.findings
    assert finding.signature is SignatureStatus.VALID
    assert finding.content.value == expected["content"]
    assert report.verdict.value == expected["verdict"]
    markup = report.disallowed_markup
    assert (markup.first if markup else None) == expected["first_violation"]
    region = scan_html(body).regions[signed_as_written["input"]["mid"]]
    canonical = canonical_as(region.canonical, CANONICALISATION)
    assert canonical == expected["canonical"]
    assert token.count(".") == 2


def test_signed_vector_without_the_key_is_unverified(
    signed_as_written: dict[str, Any],
) -> None:
    body, _ = signed_vector_body(signed_as_written)

    assert detect_html(body, {}).verdict is Verdict.UNVERIFIED
    assert detect_html(body, None).verdict is Verdict.UNVERIFIED


def test_altered_content_does_not_verify(vectors: dict[str, Any]) -> None:
    vector = vectors["signed_as_written"][0]
    body, _ = signed_vector_body(vector)
    altered = body.replace("USD 1.00", "USD 9.00")
    assert altered != body

    report = detect_html(altered, {GOLDEN_KID: golden_public_key()})

    assert report.verdict is Verdict.UNVERIFIED
    assert report.findings[0].content is ContentCheck.MISMATCH


def test_a_text_links_1_token_still_verifies(vectors: dict[str, Any]) -> None:
    """A verifier reads each token under the canonicalisation it names."""
    vector = vectors["signed_as_written"][0]
    body, _ = signed_vector_body(vector, CANONICALISATION_V1)

    report = detect_html(body, {GOLDEN_KID: golden_public_key()})

    (finding,) = report.findings
    assert finding.signature is SignatureStatus.VALID
    assert finding.content.value == vector["expected"]["content"]


def test_an_unknown_canonicalisation_is_unsupported(vectors: dict[str, Any]) -> None:
    body, _ = signed_vector_body(vectors["signed_as_written"][0], "text-links/9")

    (finding,) = detect_html(body, {GOLDEN_KID: golden_public_key()}).findings

    assert finding.content is ContentCheck.UNSUPPORTED
