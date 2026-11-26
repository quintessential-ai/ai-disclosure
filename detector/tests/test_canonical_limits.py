"""The parse and walk stay bounded: html5lib's quadratic paths and nested containers."""

from __future__ import annotations

import time
import tracemalloc

import pytest

from ai_disclosure_verify import Verdict, canonical, detect_html
from ai_disclosure_verify.canonical import (
    CANONICALISATION,
    UnparseableHtmlError,
    canonical_as,
    digest_of_canonical,
    scan_html,
)


def _containers(count: int) -> str:
    return "".join(f'<div data-ai-content="{index:032x}">' for index in range(count))


def test_a_bare_ampersand_attribute_is_refused_quickly() -> None:
    # html5lib rebuilds the value at each "&": this took 24 s unbounded.
    document = '<a href="' + "&" * 2_400_000 + '">x</a>'

    started = time.perf_counter()
    with pytest.raises(UnparseableHtmlError, match="copies more than"):
        scan_html(document)

    assert time.perf_counter() - started < 2


@pytest.mark.parametrize(
    "document",
    [
        pytest.param('<a href="' + "&" * 2000 + '">x</a>', id="attribute-ampersands"),
        pytest.param('<a href="' + "\0" * 2000 + '">x</a>', id="attribute-nuls"),
        pytest.param("<a href=x" + "=" * 2000 + ">x</a>", id="unquoted-attribute"),
        pytest.param("<p>" + "&" * 2000, id="text-ampersands"),
        pytest.param("<p>" + "< " * 1000, id="text-less-thans"),
        pytest.param("<title>" + "&" * 2000, id="title"),
        pytest.param("<style>" + "<" * 2000, id="raw-text"),
        pytest.param("<!--" + "-a" * 1000 + "-->", id="comment"),
        pytest.param("<!DOCTYPE " + "&" * 2000 + ">", id="doctype"),
        pytest.param("<p a" + "-" * 2000 + ">", id="attribute-name"),
    ],
)
def test_string_building_is_charged(
    document: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_html(document)
    monkeypatch.setattr(canonical._TreeBuilder, "max_copied", 100_000)

    with pytest.raises(UnparseableHtmlError, match="copies more than"):
        scan_html(document)


def test_ordinary_mail_is_charged_about_its_length() -> None:
    document = (
        "<p>Dear <b>Sir</b>, &nbsp;please see "
        "<a href='https://x.test/a?b=1&amp;c=2'>this</a> &amp; reply.</p>"
    ) * 20_000
    builders: list[canonical._TreeBuilder] = []

    class Recording(canonical._TreeBuilder):
        def reset(self) -> None:
            super().reset()
            builders.append(self)

    canonical._parse_document(document, Recording)

    assert 0 < builders[-1].copied < 4 * len(document)


def test_foster_parenting_is_refused_before_it_turns_quadratic() -> None:
    # Each piece moved out of the table lists the foster parent's children:
    # this took 20 s unbounded.
    document = "<div>" + "<p></p>" * 40_000 + "<table>" + "<b></b>" * 40_000

    started = time.perf_counter()
    with pytest.raises(UnparseableHtmlError, match="foster-parented"):
        scan_html(document)

    assert time.perf_counter() - started < 3


def test_foster_parenting_is_charged(monkeypatch: pytest.MonkeyPatch) -> None:
    document = "<div>" + "<p></p>" * 100 + "<table>" + "x<b></b>" * 100
    scan_html(document)
    monkeypatch.setattr(canonical._TreeBuilder, "max_scans", 1_000)

    with pytest.raises(UnparseableHtmlError, match="foster-parented"):
        scan_html(document)


def test_deeply_nested_containers_are_unparseable() -> None:
    # 250 nested containers around 90,000 elements took 3.2 s and 1.9 GB.
    document = _containers(250) + "<p>x</p>" * 1_000

    report = detect_html(document)

    assert report.verdict is Verdict.UNPARSEABLE
    assert report.unparseable is not None
    assert "nested more than" in report.unparseable


def test_nested_containers_store_each_item_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(canonical, "MAX_NESTED_CONTAINERS", 300)
    elements = 5_000
    document = _containers(250) + "<p>x</p>" * elements
    scan_html(_containers(250) + "<p>x</p>")  # warm html5lib's caches

    tracemalloc.start()
    try:
        scan = scan_html(document)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # One item list for the document, not one per container (~40 MB).
    assert peak < 20_000_000
    assert len(scan.regions) == 250
    assert all(region.canonical == "x" * elements for region in scan.regions.values())


def test_nested_regions_digest_as_before() -> None:
    inner = "00000000000000000000000000000002"
    document = (
        '<div data-ai-content="00000000000000000000000000000001"><p>a</p>'
        f'<div data-ai-content="{inner}"><p>b <a href="https://x.test/c d">c</a></p>'
        "</div><p>e</p></div><p>f</p>"
    )

    scan = scan_html(document)
    alone = scan_html(
        f'<div data-ai-content="{inner}"><p>b <a href="https://x.test/c d">c</a></p>'
        "</div>"
    )

    outer = scan.regions["00000000000000000000000000000001"]
    assert outer.canonical == "ab\x1ehttps://x.test/c d\x1fce"
    assert scan.regions[inner].canonical == alone.regions[inner].canonical
    assert scan.regions[inner].canonical == "b\x1ehttps://x.test/c d\x1fc"


def test_a_region_digests_once_per_canonicalisation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mid = "0" * 32
    region = scan_html(
        f'<div data-ai-content="{mid}"><a href="https://x.test/a b">x</a></div>'
    ).regions[mid]
    calls: list[str] = []
    real = canonical._canonical

    def counting(items: list[tuple[str, str]]) -> str:
        calls.append("canonical")
        return real(items)

    monkeypatch.setattr(canonical, "_canonical", counting)

    first = region.digest(CANONICALISATION)
    second = region.digest(CANONICALISATION)

    assert (
        first
        == second
        == digest_of_canonical(canonical_as(region.canonical, CANONICALISATION))
    )
    assert calls == ["canonical"]
