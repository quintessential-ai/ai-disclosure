"""Files given to ``detect_file``: signed Office and PDF fixtures, and edge cases."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest
from helpers import (
    GOLDEN_KID,
    AllocationPeak,
    golden_jwks,
    golden_public_key,
    signed_vector_body,
)

from ai_disclosure_verify import Carrier, ContentCheck, Verdict, cli, files
from ai_disclosure_verify.detect import MessageDecodeError, detect_file

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
    ],
    ids=["empty", "not-a-token", "not-ascii", "empty-xmp"],
)
def test_a_pdf_entry_without_a_token_is_a_malformed_token(entry: bytes) -> None:
    update = b"3 0 obj << " + entry + b" >> endobj\ntrailer << /Info 3 0 R >>\n%%EOF\n"

    _assert_one_malformed_file_token(_PDF + update)


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


def test_a_pdf_entry_stops_at_the_next_parenthesis() -> None:
    found = files.pdf_token(_PDF + b"/AIDisclosure (a.b /AIDisclosure (c.d.e)")

    assert found is not None
    assert found[0] == "c.d.e"


@pytest.mark.parametrize(
    ("fixture", "verdict", "content"),
    [
        ("signed.docx", Verdict.VERIFIED, ContentCheck.MATCH),
        # The line is part of the PDF revision the digest covers.
        ("signed.pdf", Verdict.UNVERIFIED, ContentCheck.MISMATCH),
    ],
    ids=["ooxml", "pdf"],
)
def test_a_header_like_line_before_a_marked_file_keeps_its_marker(
    fixture: str, verdict: Verdict, content: ContentCheck
) -> None:
    report = detect_file(b"Note: x\n" + (FIXTURES / fixture).read_bytes(), KEYS)

    assert report.verdict is verdict
    (finding,) = report.findings
    assert finding.carrier is Carrier.FILE_METADATA
    assert finding.content is content


def test_a_header_like_line_before_an_unmarked_pdf_reads_as_the_message() -> None:
    assert detect_file(b"Note: x\n" + _PDF).verdict is Verdict.NONE


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
