"""Files given to ``detect_file``: signed Office and PDF fixtures, and edge cases."""

from __future__ import annotations

import io
import json
import tracemalloc
import zipfile
from pathlib import Path

import pytest
from helpers import GOLDEN_KID, golden_jwks, golden_public_key

from ai_disclosure_verify import ContentCheck, Verdict, cli, files
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


def _declaring(package: bytes, name: str, size: int) -> bytes:
    """``package`` with ``name``'s central directory entry declaring ``size`` bytes."""
    with zipfile.ZipFile(io.BytesIO(package)) as zf:
        info = zf.getinfo(name)
    data = bytearray(package)
    # A central directory entry: its signature, 42 fixed bytes, then the name.
    entry = data.index(b"PK\x01\x02")
    while data[entry + 46 : entry + 46 + len(name)] != name.encode():
        entry = data.index(b"PK\x01\x02", entry + 4)
    assert int.from_bytes(data[entry + 24 : entry + 28], "little") == info.file_size
    data[entry + 24 : entry + 28] = size.to_bytes(4, "little")
    return bytes(data)


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

    tracemalloc.start()
    try:
        with pytest.raises(zipfile.BadZipFile, match="CRC"):
            files.ooxml_digest(lying)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < big // 8


def test_a_part_neither_stored_nor_deflated_is_refused(docx: bytes) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(docx)) as src, zipfile.ZipFile(buf, "w") as dst:
        for name in src.namelist():
            dst.writestr(name, src.read(name), zipfile.ZIP_BZIP2)

    with pytest.raises(MessageDecodeError, match="compression method"):
        detect_file(buf.getvalue(), KEYS)


def test_the_token_lookup_reads_only_the_relationships_and_custom_part(
    docx: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    read: list[str] = []
    real = files._read_part

    def spy(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
        read.append(info.filename)
        return real(zf, info)

    monkeypatch.setattr(files, "_read_part", spy)

    assert files.ooxml_token(docx) is not None
    assert read == ["_rels/.rels", "docProps/custom.xml"]
