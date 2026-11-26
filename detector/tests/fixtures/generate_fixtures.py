"""Regenerate the signed Office and PDF fixtures with the reference implementation.

Run it where the reference implementation, the ``compliance.ai_disclosure``
package, is importable:

    python generate_fixtures.py

It writes ``signed.docx`` and ``signed.pdf`` next to itself, each marked with
a token the reference issuer signs with the golden vectors' test key
(``tests/helpers.py``), and checks each with the reference detector. The
checker's tests then read the same bytes, so the two implementations are held
to each other. Ed25519 signing is deterministic and the claims are fixed, so
the tokens reproduce exactly; the zip's deflated bytes may differ with the
zlib version, which no digest covers.
"""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from compliance.ai_disclosure import (
    FILE_PROPERTY,
    OOXML_CANONICALISATION,
    PDF_CANONICALISATION,
    DisclosureSigner,
    Verdict,
    issue_digest_marker,
    keys_from_jwks,
    ooxml_digest,
    pdf_digest,
)
from compliance.ai_disclosure.detect import detect_file
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
SIGNER = DisclosureSigner(
    Ed25519PrivateKey.from_private_bytes(bytes(range(32))), "golden-vectors"
)
ISSUED_AT = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)
GENERATOR = "Complexio Stevie"
ON_BEHALF_OF = "the company"

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/'
    'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    "{custom}</Types>"
)
_CUSTOM_OVERRIDE = (
    '<Override PartName="/docProps/custom.xml" ContentType="application/'
    'vnd.openxmlformats-officedocument.custom-properties+xml"/>'
)
_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/officeDocument" Target="word/document.xml"/>'
    "{custom}</Relationships>"
)
_CUSTOM_REL = (
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/custom-properties" Target="docProps/custom.xml"/>'
)
_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>Quarterly freight summary: 12 voyages, USD 1.00 each."
    "</w:t></w:r></w:p></w:body></w:document>"
)
_CUSTOM = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
    'custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/'
    '2006/docPropsVTypes">'
    '<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" '
    'name="AIGenerated"><vt:bool>true</vt:bool></property>'
    '<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="3" '
    f'name="{FILE_PROPERTY}"><vt:lpwstr>{{token}}</vt:lpwstr></property>'
    "</Properties>"
)


def _docx(token: str | None) -> bytes:
    parts = {
        "[Content_Types].xml": _CONTENT_TYPES.format(
            custom=_CUSTOM_OVERRIDE if token else ""
        ),
        "_rels/.rels": _RELS.format(custom=_CUSTOM_REL if token else ""),
        "word/document.xml": _DOCUMENT,
    }
    if token:
        parts["docProps/custom.xml"] = _CUSTOM.format(token=token)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in parts.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, text.encode("utf-8"))
    return buf.getvalue()


def _pdf_objects(
    objects: list[bytes], first: int, offset: int
) -> tuple[bytes, list[int]]:
    body, offsets = b"", []
    for number, obj in enumerate(objects, start=first):
        offsets.append(offset + len(body))
        body += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    return body, offsets


def _pdf_original() -> bytes:
    text = b"BT /F1 12 Tf 72 720 Td (Quarterly freight summary: 12 voyages.) Tj ET"
    header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    body, offsets = _pdf_objects(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
            b" /Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(text)} >>\nstream\n".encode() + text + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ],
        1,
        len(header),
    )
    xref_at = len(header) + len(body)
    xref = b"xref\n0 6\n0000000000 65535 f \n" + b"".join(
        f"{offset:010d} 00000 n \n".encode() for offset in offsets
    )
    trailer = f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
    return header + body + xref + trailer.encode()


def _pdf_update(original: bytes, token: str) -> bytes:
    """The marker as an incremental update: a new Info dictionary."""
    prev = original.rindex(b"startxref\n") + len(b"startxref\n")
    prev_xref = int(original[prev:].split(b"\n", 1)[0])
    info = (
        f"<< /AIGenerated (true) /AISystem ({GENERATOR}) /{FILE_PROPERTY} ({token}) >>"
    ).encode()
    body, (offset,) = _pdf_objects([info], 6, len(original))
    xref_at = len(original) + len(body)
    tail = (
        f"xref\n0 1\n0000000000 65535 f \n6 1\n{offset:010d} 00000 n \n"
        f"trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev {prev_xref} >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    )
    return original + body + tail.encode()


def _marker(digest: str, canon: str, mid: str) -> str:
    return issue_digest_marker(
        digest,
        canon,
        on_behalf_of=ON_BEHALF_OF,
        generator=GENERATOR,
        signer=SIGNER,
        now=ISSUED_AT,
        mid=mid,
    ).token


def main() -> None:
    keys = keys_from_jwks({"keys": [SIGNER.public_jwk()]})
    docx = _docx(_marker(ooxml_digest(_docx(None)), OOXML_CANONICALISATION, "1" * 32))
    assert detect_file(docx, keys).verdict is Verdict.VERIFIED
    original = _pdf_original()
    pdf = _pdf_update(
        original, _marker(pdf_digest(original), PDF_CANONICALISATION, "2" * 32)
    )
    assert detect_file(pdf, keys).verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT
    (HERE / "signed.docx").write_bytes(docx)
    (HERE / "signed.pdf").write_bytes(pdf)


if __name__ == "__main__":
    main()
