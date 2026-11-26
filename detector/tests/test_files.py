"""Files given to ``detect_file``: signed Office and PDF fixtures, and edge cases."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from helpers import GOLDEN_KID, golden_jwks, golden_public_key

from ai_disclosure_verify import ContentCheck, Verdict, cli, files
from ai_disclosure_verify.detect import detect_file

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
