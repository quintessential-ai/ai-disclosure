"""Files given to ``detect_file``: signed Office and PDF fixtures, and edge cases."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from helpers import (
    GOLDEN_KID,
    AllocationPeak,
    golden_jwks,
    golden_public_key,
    golden_token,
    signed_vector_body,
)

from ai_disclosure_verify import Carrier, ContentCheck, Verdict, cli, files
from ai_disclosure_verify.detect import MessageDecodeError, detect_file, detect_html
from ai_disclosure_verify.jws import b64url_encode, decode_compact

# Written by fixtures/generate_fixtures.py with the reference implementation.
FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEYS = {GOLDEN_KID: golden_public_key()}


@pytest.fixture
def docx() -> bytes:
    return (FIXTURES / "signed.docx").read_bytes()


@pytest.fixture
def pdf() -> bytes:
    return (FIXTURES / "signed.pdf").read_bytes()


@pytest.fixture
def jwks_file(tmp_path: Path) -> Path:
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(golden_jwks()), encoding="utf-8")
    return path


def _repack(package: bytes, parts: dict[str, bytes | None]) -> bytes:
    """``package`` with parts replaced, or dropped where the value is None."""
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(package)) as src, zipfile.ZipFile(buf, "w") as dst:
        for name in src.namelist():
            data = parts.get(name, src.read(name))
            if data is not None:
                dst.writestr(name, data, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _cli(tmp_path: Path, name: str, data: bytes, jwks_file: Path) -> int:
    path = tmp_path / name
    path.write_bytes(data)
    return cli.main([str(path), "--jwks", str(jwks_file)])


def test_a_signed_office_file_verifies(
    docx: bytes, tmp_path: Path, jwks_file: Path
) -> None:
    report = detect_file(docx, KEYS)

    (finding,) = report.findings
    assert report.verdict is Verdict.VERIFIED
    assert finding.content is ContentCheck.MATCH
    assert finding.claims["canon"] == files.OOXML_CANONICALISATION
    assert _cli(tmp_path, "report.docx", docx, jwks_file) == cli.EXIT_VERIFIED


def test_recompressing_an_office_file_keeps_it_verified(docx: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(docx)) as zf:
        names = zf.namelist()
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(docx)) as src, zipfile.ZipFile(buf, "w") as dst:
        for name in reversed(names):
            dst.writestr(name, src.read(name), zipfile.ZIP_STORED)

    assert detect_file(buf.getvalue(), KEYS).verdict is Verdict.VERIFIED


def test_a_changed_office_part_is_a_content_mismatch(
    docx: bytes, tmp_path: Path, jwks_file: Path
) -> None:
    with zipfile.ZipFile(io.BytesIO(docx)) as zf:
        document = zf.read("word/document.xml")
    edited = _repack(
        docx, {"word/document.xml": document.replace(b"USD 1.00", b"USD 9.00")}
    )

    report = detect_file(edited, KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    assert report.findings[0].content is ContentCheck.MISMATCH
    assert _cli(tmp_path, "report.docx", edited, jwks_file) == cli.EXIT_UNVERIFIED


def test_an_office_file_without_a_custom_part_has_no_marker(
    docx: bytes, tmp_path: Path, jwks_file: Path
) -> None:
    unmarked = _repack(docx, {"docProps/custom.xml": None})

    assert detect_file(unmarked, KEYS).verdict is Verdict.NONE
    assert _cli(tmp_path, "report.docx", unmarked, jwks_file) == cli.EXIT_NO_MARKER


def test_a_signed_pdf_verifies_with_its_update_unmarked(
    pdf: bytes, tmp_path: Path, jwks_file: Path
) -> None:
    report = detect_file(pdf, KEYS)

    (finding,) = report.findings
    assert finding.verified
    assert finding.claims["canon"] == files.PDF_CANONICALISATION
    assert report.unmarked_content
    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    assert (
        _cli(tmp_path, "report.pdf", pdf, jwks_file)
        == cli.EXIT_VERIFIED_WITH_UNMARKED_CONTENT
    )


def test_a_changed_first_pdf_revision_is_a_content_mismatch(
    pdf: bytes, tmp_path: Path, jwks_file: Path
) -> None:
    edited = pdf.replace(b"12 voyages", b"13 voyages", 1)
    assert edited != pdf

    report = detect_file(edited, KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    assert report.findings[0].content is ContentCheck.MISMATCH
    assert _cli(tmp_path, "report.pdf", edited, jwks_file) == cli.EXIT_UNVERIFIED


def test_a_package_over_the_part_cap_is_refused(
    docx: bytes, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, jwks_file: Path
) -> None:
    with zipfile.ZipFile(io.BytesIO(docx)) as zf:
        count = len(zf.namelist())
    monkeypatch.setattr(files, "MAX_PACKAGE_PARTS", count - 1)

    with pytest.raises(ValueError, match="more than"):
        files.ooxml_digest(docx)
    with pytest.raises(ValueError, match="more than"):
        files.ooxml_token(docx)
    with pytest.raises(MessageDecodeError, match="more than"):
        detect_file(docx, KEYS)
    assert _cli(tmp_path, "report.docx", docx, jwks_file) == cli.EXIT_ERROR


def test_directory_entries_count_toward_the_part_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        for index in range(5):
            zf.writestr(zipfile.ZipInfo(f"empty-{index}/"), b"")
    monkeypatch.setattr(files, "MAX_PACKAGE_PARTS", 5)

    with pytest.raises(ValueError, match="more than"):
        files.ooxml_digest(buf.getvalue())
    with pytest.raises(MessageDecodeError, match="more than"):
        detect_file(buf.getvalue(), KEYS)


def _with_central_field(package: bytes, name: str, offset: int, value: int) -> bytes:
    """``package`` with a 4-byte field of ``name``'s central directory entry set."""
    data = bytearray(package)
    # A central directory entry: its signature, 42 fixed bytes, then the name.
    entry = data.index(b"PK\x01\x02")
    while data[entry + 46 : entry + 46 + len(name)] != name.encode():
        entry = data.index(b"PK\x01\x02", entry + 4)
    data[entry + offset : entry + offset + 4] = value.to_bytes(4, "little")
    return bytes(data)


def _declaring(package: bytes, name: str, size: int) -> bytes:
    """``package`` with ``name``'s central directory entry declaring ``size`` bytes."""
    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        assert zf.getinfo(name).file_size != size
    return _with_central_field(package, name, 24, size)


def test_a_package_over_the_size_cap_is_refused_before_reading(docx: bytes) -> None:
    oversized = _declaring(docx, "word/document.xml", files.MAX_PACKAGE_BYTES + 1)

    with pytest.raises(ValueError, match="uncompressed"):
        files.ooxml_digest(oversized)
    with pytest.raises(MessageDecodeError, match="uncompressed"):
        detect_file(oversized, KEYS)


def test_a_part_declaring_less_than_it_holds_is_read_only_that_far(
    docx: bytes,
) -> None:
    big = 16 * 1024 * 1024
    lying = _declaring(
        _repack(docx, {"word/document.xml": bytes(big)}), "word/document.xml", 1
    )

    with AllocationPeak() as peak:
        with pytest.raises(zipfile.BadZipFile, match="CRC"):
            files.ooxml_digest(lying)

    assert peak.bytes < big // 8


def _spec_digest(package: bytes) -> str:
    """``ooxml-parts/1`` for a package without a custom-properties relationship."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        names = sorted(n for n in zf.namelist() if n != "docProps/custom.xml")
        listing = "".join(
            f"{n}\n{b64(hashlib.sha256(zf.read(n)).digest())}\n" for n in names
        )
    return b64(hashlib.sha256(listing.encode()).digest())


def test_a_large_part_is_hashed_without_holding_it() -> None:
    big = 64 * 1024 * 1024
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("word/media/video.bin", bytes(big))
    package = buf.getvalue()
    expected = _spec_digest(package)

    with AllocationPeak() as peak:
        digest = files.ooxml_digest(package)

    assert digest == expected
    assert peak.bytes < big // 16


@pytest.mark.parametrize("part", ["[Content_Types].xml", "_rels/.rels"])
def test_a_routing_part_over_its_cap_is_refused_before_reading(
    docx: bytes, part: str
) -> None:
    # Declared over the cap, the part is refused before a byte of it is read.
    oversized = _declaring(docx, part, files.MAX_XML_PART_BYTES + 1)

    with pytest.raises(ValueError, match="routing or metadata part"):
        files.ooxml_digest(oversized)
    if part == "_rels/.rels":
        with pytest.raises(MessageDecodeError, match="routing or metadata part"):
            detect_file(oversized, KEYS)
    else:
        report = detect_file(oversized, KEYS)
        assert report.findings[0].content is ContentCheck.NOT_FOUND


def test_deeply_nested_routing_reads_as_content_not_found(docx: bytes) -> None:
    depth = 5000
    content_types = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + "<x>" * depth
        + "</x>" * depth
        + "</Types>"
    )
    nested = _repack(docx, {"[Content_Types].xml": content_types.encode()})

    with pytest.raises(ValueError, match="nested"):
        files.ooxml_digest(nested)
    report = detect_file(nested, KEYS)

    assert report.findings[0].content is ContentCheck.NOT_FOUND
    assert report.verdict is Verdict.UNVERIFIED


def test_a_part_neither_stored_nor_deflated_is_refused(docx: bytes) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(docx)) as src, zipfile.ZipFile(buf, "w") as dst:
        for name in src.namelist():
            dst.writestr(name, src.read(name), zipfile.ZIP_BZIP2)

    with pytest.raises(MessageDecodeError, match="compression method"):
        detect_file(buf.getvalue(), KEYS)


def test_the_token_lookup_does_not_read_the_document_parts(docx: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(docx)) as zf:
        crc = zf.getinfo("word/document.xml").CRC
    # A corrupt document part fails only a reader that reads it.
    corrupt = _with_central_field(docx, "word/document.xml", 16, crc ^ 1)

    assert files.ooxml_token(corrupt) == files.ooxml_token(docx) is not None
    with pytest.raises(zipfile.BadZipFile, match="CRC"):
        files.ooxml_digest(corrupt)


def test_a_byte_order_mark_before_html_does_not_hide_the_marker(
    vectors: dict[str, Any], tmp_path: Path, jwks_file: Path
) -> None:
    body, _ = signed_vector_body(vectors["signed_as_written"][0])
    plain = body.encode("utf-8")

    with_bom = detect_file(b"\xef\xbb\xbf" + plain, KEYS)

    assert with_bom.verdict is not Verdict.NONE
    assert with_bom.to_dict() == detect_file(plain, KEYS).to_dict()
    assert _cli(tmp_path, "body.html", b"\xef\xbb\xbf" + plain, jwks_file) == _cli(
        tmp_path, "plain.html", plain, jwks_file
    )


_PDF = (
    b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
    b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
    b"trailer << /Root 1 0 R >>\n%%EOF\n"
)


def _assert_one_malformed_file_token(data: bytes) -> None:
    report = detect_file(data, KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    (finding,) = report.findings
    assert finding.carrier is Carrier.FILE_METADATA
    assert finding.error is not None
    assert finding.error.startswith("malformed token")


@pytest.mark.parametrize(
    "value",
    [
        b"<vt:lpwstr/>",
        b"<vt:lpwstr></vt:lpwstr>",
        b"<vt:lpwstr>  </vt:lpwstr>",
        b"<vt:lpwstr>not-a-token</vt:lpwstr>",
        b"",
    ],
    ids=["self-closing", "empty", "blank", "not-a-token", "no-value-element"],
)
def test_an_office_property_without_a_token_is_a_malformed_token(
    docx: bytes, value: bytes
) -> None:
    with zipfile.ZipFile(io.BytesIO(docx)) as zf:
        custom = zf.read("docProps/custom.xml")
    custom, replaced = re.subn(rb"<vt:lpwstr>[^<]*</vt:lpwstr>", value, custom)
    assert replaced == 1

    _assert_one_malformed_file_token(_repack(docx, {"docProps/custom.xml": custom}))


@pytest.mark.parametrize(
    "entry",
    [
        b"/AIDisclosure ()",
        b"/AIDisclosure (not-a-token)",
        b"/AIDisclosure (\xff\xfe.a.b)",
        b"<cpxai:AIDisclosure></cpxai:AIDisclosure>",
        b"/AIDisclosure (not(a)token)",
        b"/AIDisclosure (never closed",
        b"/AIDisclosure <>",
        b"/AIDisclosure <6E6F74>",
        b"/AIDisclosure <<>>",
        b"/AIDisclosure 7 0 R",
        b"<cpxai:AIDisclosure/>",
        b'<rdf:Description cpxai:AIDisclosure=""/>',
    ],
    ids=[
        "empty",
        "not-a-token",
        "not-ascii",
        "empty-xmp",
        "nested-parens",
        "unterminated",
        "empty-hex",
        "hex-not-a-token",
        "dictionary",
        "indirect-reference",
        "self-closing-xmp",
        "empty-xmp-attribute",
    ],
)
def test_a_pdf_entry_without_a_token_is_a_malformed_token(
    entry: bytes, tmp_path: Path
) -> None:
    update = b"3 0 obj << " + entry + b" >> endobj\ntrailer << /Info 3 0 R >>\n%%EOF\n"
    data = _PDF + update

    _assert_one_malformed_file_token(data)
    path = tmp_path / "marked.pdf"
    path.write_bytes(data)
    assert cli.main([str(path), "--offline"]) == cli.EXIT_UNVERIFIED


def test_a_longer_pdf_name_is_not_the_property() -> None:
    data = _PDF + b"3 0 obj << /AIDisclosureX (x) >> endobj\n"

    assert files.pdf_token(data) is None
    assert detect_file(data).verdict is Verdict.NONE


@pytest.mark.parametrize("form", ["hex", "xmp-attribute"])
def test_a_token_in_another_pdf_string_form_verifies(pdf: bytes, form: str) -> None:
    token = pdf.split(b"/AIDisclosure (")[1].split(b")")[0]
    entry = (
        b"/AIDisclosure <" + token.hex().upper().encode() + b">"
        if form == "hex"
        else b'<rdf:Description cpxai:AIDisclosure="' + token + b'"/>'
    )
    rewritten = pdf.replace(b"/AIDisclosure (" + token + b")", entry)
    assert rewritten != pdf

    verdict = detect_file(rewritten, KEYS).verdict
    assert verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


@pytest.mark.parametrize(
    ("escaped", "read"),
    [
        (rb"a\056b\056c", b"a.b.c"),
        (rb"a\56b\.c", b"a.b.c"),
        (b"a.b\\\nc.d", b"a.bc.d"),
        (rb"a\(b\)\\", b"a(b)\\"),
        (rb"\8\9\q", b"89q"),
        (rb"\777", b"\xff"),
    ],
    ids=[
        "octal",
        "short-octal-and-named",
        "line-continuation",
        "parens",
        "not-octal",
        "wraps",
    ],
)
def test_a_pdf_info_string_is_read_with_its_escapes_decoded(
    escaped: bytes, read: bytes
) -> None:
    found = files.pdf_token(_PDF + b"/AIDisclosure (" + escaped + b")")

    assert found is not None
    assert found[0] == read.decode("ascii", errors="replace")


@pytest.mark.parametrize(
    ("entry", "value"),
    [
        (b"/AIDisclosure (a(b)c)", "a(b)c"),
        (b"/AIDisclosure <612E62 2E63>", "a.b.c"),
        (b"/AIDisclosure <612>", "a "),
        (b"/AIDisclosure <<>>", ""),
        (b"<cpxai:AIDisclosure>a.b.c</cpxai:AIDisclosure>", "a.b.c"),
        (b"<cpxai:AIDisclosure/>a.b.c<", ""),
        (b"<rdf:Description cpxai:AIDisclosure='a.b.c'/>", "a.b.c"),
        (b"/AI#44isclosure (a.b.c)", "a.b.c"),
        (b"/AIDisclosure % note /AIDisclosure (x)\n(a.b.c)", "a.b.c"),
        (b"(see /AIDisclosure) Tj /AIDisclosure (a.b.c)", "a.b.c"),
        (b"/AIDisclosure 7 0 R /AIDisclosure (a.b.c)", "a.b.c"),
        (b"/AIDisclosure <a.b.c>", ""),
        (b"/AIDisclosure <612E", ""),
        (b"/AIDisclosure (a.b.c", ""),
    ],
    ids=[
        "balanced-parens",
        "hex-with-space",
        "hex-odd-digit",
        "dictionary",
        "xmp-element",
        "self-closing-xmp",
        "xmp-attribute",
        "escaped-name",
        "comment-before-value",
        "mention-skipped",
        "reference-skipped",
        "hex-not-hex",
        "unterminated-hex",
        "unterminated-literal",
    ],
)
def test_a_pdf_property_value_is_read_by_its_form(entry: bytes, value: str) -> None:
    found = files.pdf_token(_PDF + entry)

    assert found is not None
    assert found[0] == value


@pytest.mark.parametrize(
    "data",
    [
        b"/AIDisclosure#41 (a.b.c)",
        b"/AIDisclosureX (a.b.c)",
        b'<rdf:Description xcpxai:AIDisclosure="a.b.c"/>',
        b"<xcpxai:AIDisclosure>a.b.c</xcpxai:AIDisclosure>",
    ],
    ids=[
        "longer-escaped-name",
        "longer-name",
        "longer-qname-attribute",
        "longer-qname-element",
    ],
)
def test_a_longer_name_is_not_the_pdf_property(data: bytes) -> None:
    assert files.pdf_token(_PDF + data) is None


def _token_of_pdf(marked: bytes) -> bytes:
    return marked.split(b"/AIDisclosure (")[1].split(b")")[0]


def test_a_hex_token_with_whitespace_pdf_does_not_know_is_malformed(
    pdf: bytes,
) -> None:
    # bytes.fromhex skips VT; PDF whitespace does not include it.
    token = _token_of_pdf(pdf)
    digits = token.hex().encode()
    rewritten = pdf.replace(
        b"(" + token + b")", b"<" + digits[:4] + b"\x0b\x0b" + digits[4:] + b">"
    )
    assert rewritten != pdf

    _assert_one_malformed_file_token(rewritten)


def test_a_signed_token_written_as_a_bare_hex_value_does_not_verify(
    pdf: bytes,
) -> None:
    token = _token_of_pdf(pdf)
    rewritten = pdf.replace(b"(" + token + b")", b"<" + token + b">")
    assert rewritten != pdf

    _assert_one_malformed_file_token(rewritten)


def test_an_escaped_property_name_before_the_marker_is_the_one_read(
    pdf: bytes,
) -> None:
    marked = pdf.replace(
        b"/AIDisclosure (", b"/AI#44isclosure (bad) /AIDisclosure (", 1
    )
    assert marked != pdf

    _assert_one_malformed_file_token(marked)


def test_a_token_under_a_longer_xmp_qname_is_not_found(pdf: bytes) -> None:
    token = _token_of_pdf(pdf)
    rewritten = pdf.replace(
        b"/AIDisclosure (" + token + b")",
        b'/Note (<rdf:Description xcpxai:AIDisclosure="' + token + b'"/>)',
    )
    assert rewritten != pdf

    assert detect_file(rewritten, KEYS).verdict is Verdict.NONE


def _signed_pdf(original: bytes, fixture: bytes) -> bytes:
    """``original`` marked as an incremental update, with the fixture's claims."""
    found = files.pdf_token(fixture)
    assert found is not None
    revision = original[: original.rindex(b"%%EOF") + len(b"%%EOF")]
    claims = {
        **decode_compact(found[0]).payload,
        "content_sha256": files.pdf_digest(revision),
    }
    token = golden_token(claims).encode()
    return original + (
        b"3 0 obj << /AIDisclosure (" + token + b") >> endobj\n"
        b"trailer << /Info 3 0 R >>\n%%EOF\n"
    )


@pytest.mark.parametrize("page_text", [b"", b"BT (see /AIDisclosure) Tj ET"])
def test_page_text_that_mentions_the_property_hides_no_marker(
    pdf: bytes, page_text: bytes
) -> None:
    stream = b"4 0 obj << /Length 30 >> stream\n" + page_text + b"\nendstream endobj\n"
    original = _PDF.replace(b"trailer", stream + b"trailer")

    report = detect_file(_signed_pdf(original, pdf), KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


@pytest.mark.parametrize(
    "data",
    [
        b'Note: PK\x03\x04\n<div data-ai-disclosure=""></div>',
        b'Note: %PDF-1.7\n<div data-ai-disclosure="x"></div>',
    ],
    ids=["zip", "pdf"],
)
def test_a_header_led_fragment_with_a_file_signature_reads_its_html_marker(
    data: bytes,
) -> None:
    assert detect_file(data).verdict is Verdict.UNVERIFIED


def test_only_the_first_pdf_property_is_read() -> None:
    found = files.pdf_token(_PDF + b"/AIDisclosure (bad) /AIDisclosure (a.b.c)")

    assert found is not None
    assert found[0] == "bad"


@pytest.mark.parametrize(
    "prefix",
    [
        b"<p>Hi</p>\n",
        b"<!-- x -->",
        b"Content-Type: text/html\n\n",
        b"Note: x\n",
        b"Pay to account 123 now\n",
        b"\n",
        b"\xef\xbb\xbf",
    ],
    ids=[
        "html",
        "comment",
        "mime-header",
        "header-like",
        "text",
        "blank-line",
        "byte-order-mark",
    ],
)
@pytest.mark.parametrize("fixture", ["signed.pdf", "signed.docx"], ids=["pdf", "docx"])
def test_a_file_with_anything_in_front_is_read_by_how_it_starts(
    prefix: bytes, fixture: str
) -> None:
    # A file is recognised only from its first byte, so its marker is not found.
    report = detect_file(prefix + (FIXTURES / fixture).read_bytes(), KEYS)

    assert report.verdict is Verdict.NONE
    assert not report.findings


def test_bytes_after_a_signed_package_are_not_covered(
    docx: bytes, jwks_file: Path, tmp_path: Path
) -> None:
    data = docx + b"Pay to account 123 now\n"

    assert detect_file(data, KEYS).verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    assert (
        _cli(tmp_path, "input.docx", data, jwks_file)
        == cli.EXIT_VERIFIED_WITH_UNMARKED_CONTENT
    )


def _eocd(package: bytes) -> int:
    return package.rindex(b"PK\x05\x06")


def _cd_bounds(package: bytes) -> tuple[int, int]:
    end = _eocd(package)
    start = int.from_bytes(package[end + 16 : end + 20], "little")
    return start, end


def _with_gap(package: bytes, gap: bytes) -> bytes:
    """``gap`` between the first two local entries, every offset after it moved."""
    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        split = sorted(info.header_offset for info in zf.infolist())[1]
    data = bytearray(package[:split] + gap + package[split:])
    cd_start, end = _cd_bounds(bytes(data))
    cd_start += len(gap)
    position = cd_start
    while data[position : position + 4] == b"PK\x01\x02":
        offset = int.from_bytes(data[position + 42 : position + 46], "little")
        if offset >= split:
            data[position + 42 : position + 46] = (offset + len(gap)).to_bytes(
                4, "little"
            )
        lengths = [
            int.from_bytes(data[position + at : position + at + 2], "little")
            for at in (28, 30, 32)
        ]
        position += 46 + sum(lengths)
    data[end + 16 : end + 20] = cd_start.to_bytes(4, "little")
    return bytes(data)


def _with_copied_directory(package: bytes, text: bytes) -> bytes:
    """Text, then a copy of the directory and an end record that points at the copy."""
    cd_start, end = _cd_bounds(package)
    copy_at = len(package) + len(text)
    record = bytearray(package[end : end + 22])
    record[16:20] = copy_at.to_bytes(4, "little")
    return package + text + package[cd_start:end] + bytes(record)


_TEXT = b"Pay to account 1234\n"


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda p: p + _TEXT, id="appended"),
        pytest.param(
            lambda p: p[:-2] + b"\xff\xff" + _TEXT, id="inflated-comment-length"
        ),
        pytest.param(
            lambda p: p[:-2] + len(_TEXT).to_bytes(2, "little") + _TEXT,
            id="comment-length-covering-the-text",
        ),
        pytest.param(lambda p: _with_copied_directory(p, _TEXT), id="copied-directory"),
        pytest.param(lambda p: _with_gap(p, _TEXT), id="gap-between-entries"),
    ],
)
def test_bytes_outside_the_package_records_are_not_covered(
    docx: bytes,
    jwks_file: Path,
    tmp_path: Path,
    tamper: Callable[[bytes], bytes],
) -> None:
    data = tamper(docx)

    assert detect_file(data, KEYS).verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    assert (
        _cli(tmp_path, "input.docx", data, jwks_file)
        == cli.EXIT_VERIFIED_WITH_UNMARKED_CONTENT
    )


def test_a_local_entry_away_from_its_directory_offset_is_not_covered(
    docx: bytes,
) -> None:
    """The entries still run back to back, but not where the directory says."""
    extra = int.from_bytes(docx[28:30], "little")
    name = int.from_bytes(docx[26:28], "little")
    data = bytearray(docx)
    # Widen the first entry's extra field over 8 inserted bytes; leave the
    # directory's entry offsets as they were.
    data[28:30] = (extra + 8).to_bytes(2, "little")
    data[30 + name + extra : 30 + name + extra] = b"\x00" * 8
    cd_start, end = _cd_bounds(bytes(data))
    data[end + 16 : end + 20] = (cd_start + 8).to_bytes(4, "little")

    assert files.ooxml_uncovered(bytes(data)) is True


def test_a_directory_that_stops_short_of_the_end_record_is_not_covered(
    docx: bytes,
) -> None:
    end = _eocd(docx)
    data = docx[:end] + b"text" + docx[end:]

    assert files._zip_layout(data) is None
    assert files.ooxml_uncovered(data) is True


def test_a_package_comment_is_not_covered(
    docx: bytes, jwks_file: Path, tmp_path: Path
) -> None:
    # The comment is outside ooxml-parts/1's digest, so it is unsigned text.
    buffer = io.BytesIO(docx)
    with zipfile.ZipFile(buffer, "a") as zf:
        zf.comment = b"written by the editor"
    data = buffer.getvalue()

    assert detect_file(data, KEYS).verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    assert (
        _cli(tmp_path, "input.docx", data, jwks_file)
        == cli.EXIT_VERIFIED_WITH_UNMARKED_CONTENT
    )


class _Unseekable(io.RawIOBase):
    """A stream zipfile cannot seek back in, so it writes data descriptors."""

    def __init__(self) -> None:
        self.written = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        self.written += data
        return len(data)


def test_a_package_written_with_data_descriptors_is_covered(docx: bytes) -> None:
    stream = _Unseekable()
    with (
        zipfile.ZipFile(io.BytesIO(docx)) as source,
        zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as target,
    ):
        for info in source.infolist():
            target.writestr(info.filename, source.read(info))
    repacked = bytes(stream.written)
    with zipfile.ZipFile(io.BytesIO(repacked)) as check:
        assert all(info.flag_bits & 0x8 for info in check.infolist())

    assert detect_file(repacked, KEYS).verdict is Verdict.VERIFIED
    assert files.ooxml_uncovered(repacked) is False


def test_a_signed_package_alone_is_covered(docx: bytes) -> None:
    assert files.ooxml_uncovered(docx) is False
    assert detect_file(docx, KEYS).verdict is Verdict.VERIFIED


def test_a_mail_quoting_a_file_signature_has_no_marker() -> None:
    data = b"Subject: Re: %PDF-1.7 header\n\nThe file starts %PDF- and PK\x03\x04.\n"

    assert detect_file(data).verdict is Verdict.NONE


@pytest.mark.parametrize("fixture", ["signed.pdf", "signed.docx"], ids=["pdf", "docx"])
def test_a_signed_file_alone_still_verifies(fixture: str) -> None:
    verdict = detect_file((FIXTURES / fixture).read_bytes(), KEYS).verdict

    assert verdict in {Verdict.VERIFIED, Verdict.VERIFIED_WITH_UNMARKED_CONTENT}


@pytest.mark.parametrize("alg", [["EdDSA"], {"x": 1}], ids=["array", "object"])
def test_an_alg_that_is_not_a_string_is_a_rejected_token(
    alg: object, tmp_path: Path
) -> None:
    def part(value: object) -> str:
        return b64url_encode(json.dumps(value).encode())

    token = ".".join(
        [part({"alg": alg, "typ": "ai-disclosure+jwt"}), part({"spec": "x"}), ""]
    )
    html = f'<div data-ai-disclosure="{token}"></div><p>x</p>'

    (finding,) = detect_html(html).findings
    assert finding.error is not None
    assert finding.error.startswith("unsupported alg")
    path = tmp_path / "body.html"
    path.write_text(html)
    assert cli.main([str(path), "--offline"]) == cli.EXIT_UNVERIFIED


def test_text_naming_a_signature_before_a_signed_fragment_reads_the_fragment(
    vectors: dict[str, Any],
) -> None:
    body, _ = signed_vector_body(vectors["signed_as_written"][0])

    report = detect_file(f"see %PDF- spec\n{body}".encode(), KEYS)

    # Read as HTML: the marker verifies, and the text before it reads as quoted.
    assert report.verdict is Verdict.QUOTED_ONLY
    (finding,) = report.findings
    assert finding.carrier is Carrier.BODY
    assert finding.verified


def test_a_header_led_message_without_a_file_signature_has_no_marker(
    tmp_path: Path,
) -> None:
    data = b"Note: x\nNothing marked here.\n"

    assert detect_file(data).verdict is Verdict.NONE
    path = tmp_path / "note.eml"
    path.write_bytes(data)
    assert cli.main([str(path), "--offline"]) == cli.EXIT_NO_MARKER


@pytest.mark.parametrize(
    "entry",
    [b"/AIDisclosure\x00(", b"/AIDisclosure \x00 (", b"hex"],
    ids=["nul-after-name", "nul-before-value", "nul-in-hex"],
)
def test_nul_is_pdf_whitespace_around_the_property(pdf: bytes, entry: bytes) -> None:
    token = _token_of_pdf(pdf)
    if entry == b"hex":
        digits = token.hex().encode()
        rewritten = pdf.replace(
            b"(" + token + b")", b"<" + digits[:4] + b"\x00" + digits[4:] + b">"
        )
    else:
        rewritten = pdf.replace(b"/AIDisclosure (", entry)
    assert rewritten != pdf

    verdict = detect_file(rewritten, KEYS).verdict
    assert verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


_NS_AI_DISCLOSURE = b"https://complexio.com/ns/ai-disclosure/1.0/"


@pytest.mark.parametrize(
    ("prefix", "namespace", "verdict"),
    [
        (b"ai", _NS_AI_DISCLOSURE, Verdict.NONE),
        (b"cpxai", b"urn:other", Verdict.VERIFIED_WITH_UNMARKED_CONTENT),
    ],
    ids=["our-namespace-other-prefix", "our-prefix-other-namespace"],
)
def test_the_xmp_prefix_is_matched_as_written(
    pdf: bytes, prefix: bytes, namespace: bytes, verdict: Verdict
) -> None:
    token = _token_of_pdf(pdf)
    rewritten = pdf.replace(
        b"/AIDisclosure (" + token + b")",
        b'/Note (<rdf:Description xmlns:%b="%b" %b:AIDisclosure="%b"/>)'
        % (prefix, namespace, prefix, token),
    )
    assert rewritten != pdf

    assert detect_file(rewritten, KEYS).verdict is verdict


@pytest.mark.parametrize(
    "mention",
    [
        b"BT (see /AIDisclosure (x)) Tj ET\n",
        b"% see /AIDisclosure (x)\n",
        b'BT (see cpxai:AIDisclosure="x") Tj ET\n',
        b"BT (the <cpxai:AIDisclosure>x</cpxai:AIDisclosure> tag) Tj ET\n",
    ],
    ids=[
        "info-key-in-text",
        "info-key-in-comment",
        "xmp-attribute-in-text",
        "xmp-element-in-text",
    ],
)
def test_page_text_mentioning_the_property_before_a_string_fails_closed(
    pdf: bytes, mention: bytes
) -> None:
    original = _PDF.replace(
        b"trailer",
        b"4 0 obj << /Length 34 >> stream\n" + mention + b"endstream endobj\ntrailer",
    )

    _assert_one_malformed_file_token(_signed_pdf(original, pdf))


@pytest.mark.parametrize("part", ["docProps/custom.xml", "word/document.xml"])
def test_an_entry_zipfile_cannot_extract_fails_closed(docx: bytes, part: str) -> None:
    # Version needed to extract 6.4, past what zipfile reads; zipfile checks
    # every entry when it opens the package. Flags stay 0.
    package = _with_central_field(docx, part, 6, 64)

    with pytest.raises(MessageDecodeError, match="version"):
        detect_file(package, KEYS)


def test_a_corrupt_deflate_stream_fails_closed(docx: bytes) -> None:
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(docx)) as src,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst,
    ):
        for name in src.namelist():
            dst.writestr(name, src.read(name))
    data = bytearray(buf.getvalue())
    name = b"word/document.xml"
    header = data.index(b"PK\x03\x04")
    while data[header + 30 : header + 30 + len(name)] != name:
        header = data.index(b"PK\x03\x04", header + 4)
    extra = int.from_bytes(data[header + 28 : header + 30], "little")
    start = header + 30 + len(name) + extra
    # A deflate block of reserved type 3: zlib refuses it.
    data[start] = 0xFF

    report = detect_file(bytes(data), KEYS)

    assert report.findings[0].content is ContentCheck.NOT_FOUND
    assert report.verdict is Verdict.UNVERIFIED
