# Generated from the reference implementation. Do not edit by hand:
# changes are made there and regenerated.
"""Content digests and token lookup for markers carried in Office (OOXML) and PDF files.

A file's marker sits in the file's own metadata, which writing the marker
changes. So each digest covers the content that writing the marker leaves
alone: OOXML content and normalized package routing, and a PDF's bytes up
to the revision the marker is appended after.
"""

from __future__ import annotations

import hashlib
import io
import lzma
import re
import zipfile
import zlib
from posixpath import normpath
from xml.etree import ElementTree

from defusedxml.ElementTree import fromstring

from ai_disclosure_verify.jws import b64url_encode

OOXML_CANONICALISATION = "ooxml-parts/1"
PDF_CANONICALISATION = "pdf-revision/1"

# The custom document property (OOXML), Info dictionary key and XMP property (PDF) holding the token.
FILE_PROPERTY = "AIDisclosure"

_CUSTOM_PART = "docProps/custom.xml"
_ROOT_RELS = "_rels/.rels"
_CONTENT_TYPES = "[Content_Types].xml"
_NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
_NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_REL_CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties"
_EOF = b"%%EOF"
_TOKEN = rb"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
_PDF_TOKEN = re.compile(
    rb"/" + FILE_PROPERTY.encode() + rb"\s*\((" + _TOKEN + rb")\)"
    rb"|<cpxai:" + FILE_PROPERTY.encode() + rb">(" + _TOKEN + rb")<"
)


def is_ooxml(data: bytes) -> bool:
    """True for a zip container, the OOXML packaging."""
    return data.startswith(b"PK\x03\x04")


def is_pdf(data: bytes) -> bool:
    """True when ``data`` starts with the PDF header."""
    return data.startswith(b"%PDF-")


def _package_parts(zf: zipfile.ZipFile) -> dict[str, bytes]:
    names = [info.filename for info in zf.infolist() if not info.is_dir()]
    if len(names) != len(set(names)):
        msg = "duplicate Office package part"
        raise ValueError(msg)
    try:
        return {name: zf.read(name) for name in names}
    except (
        RuntimeError,
        NotImplementedError,
        OSError,
        EOFError,
        zlib.error,
        lzma.LZMAError,
    ) as exc:
        msg = f"cannot read Office package parts: {exc}"
        raise ValueError(msg) from exc


def _custom_properties_part(parts: dict[str, bytes]) -> str:
    if _ROOT_RELS not in parts:
        return _CUSTOM_PART
    rels = fromstring(parts[_ROOT_RELS])
    custom = [
        rel
        for rel in rels.iterfind(f"{{{_NS_REL}}}Relationship")
        if rel.get("Type") == _REL_CUSTOM
    ]
    if not custom:
        return _CUSTOM_PART
    if len(custom) != 1 or custom[0].get("TargetMode", "Internal") != "Internal":
        msg = "ambiguous or external custom-properties relationship"
        raise ValueError(msg)
    target = normpath(custom[0].get("Target", "")).lstrip("/")
    if target in {"", ".", _ROOT_RELS, _CONTENT_TYPES} or target.startswith("../"):
        msg = "invalid custom-properties target"
        raise ValueError(msg)
    return target


def _normalized_routing(data: bytes, tag: str, attribute: str, value: str) -> bytes:
    root = fromstring(data)
    for child in list(root):
        if child.tag == tag and child.get(attribute) == value:
            root.remove(child)
    return ElementTree.canonicalize(
        ElementTree.tostring(root, encoding="unicode"),
        strip_text=True,
        rewrite_prefixes=True,
    ).encode("utf-8")


def ooxml_digest(data: bytes) -> str:
    """``ooxml-parts/1``: SHA-256 over part names and hashes, with normalized package routing.

    Only the selected custom-properties part and directory entries are omitted.
    Routing XML uses C14N 2.0 with stripped text and rewritten prefixes, after
    removing the custom-properties relationship and its content-type override.
    Each sorted part contributes ``<name>\\n<base64url SHA-256>\\n``.
    Duplicate parts, unsafe XML and ambiguous metadata relationships are rejected.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        parts = _package_parts(zf)
    custom = _custom_properties_part(parts)
    if (
        custom in parts
        and fromstring(parts[custom]).tag != f"{{{_NS_CUSTOM}}}Properties"
    ):
        msg = "custom-properties part is not metadata"
        raise ValueError(msg)
    parts.pop(custom, None)
    if _ROOT_RELS in parts:
        parts[_ROOT_RELS] = _normalized_routing(
            parts[_ROOT_RELS], f"{{{_NS_REL}}}Relationship", "Type", _REL_CUSTOM
        )
    if _CONTENT_TYPES in parts:
        parts[_CONTENT_TYPES] = _normalized_routing(
            parts[_CONTENT_TYPES], f"{{{_NS_CT}}}Override", "PartName", f"/{custom}"
        )
    listing = "".join(
        f"{name}\n{b64url_encode(hashlib.sha256(parts[name]).digest())}\n"
        for name in sorted(parts)
    )
    return b64url_encode(hashlib.sha256(listing.encode("utf-8")).digest())


def pdf_digest(revision: bytes) -> str:
    """``pdf-revision/1``: SHA-256 of a PDF up to and including its last ``%%EOF``.

    The marker is appended as an incremental update, so these bytes are the
    file as it was before marking. Raises ``ValueError`` when there is no
    ``%%EOF``.
    """
    end = revision.rfind(_EOF)
    if end < 0:
        msg = "PDF has no %%EOF"
        raise ValueError(msg)
    return b64url_encode(hashlib.sha256(revision[: end + len(_EOF)]).digest())


def ooxml_token(data: bytes) -> str | None:
    """The token in the package's ``AIDisclosure`` custom property, if any."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        parts = _package_parts(zf)
    part = _custom_properties_part(parts)
    if part not in parts:
        return None
    props = fromstring(parts[part])
    if props.tag != f"{{{_NS_CUSTOM}}}Properties":
        msg = "custom-properties part is not metadata"
        raise ValueError(msg)
    for prop in props.iterfind(f"{{{_NS_CUSTOM}}}property"):
        if prop.get("name") == FILE_PROPERTY and len(prop) and prop[0].text:
            return prop[0].text.strip()
    return None


def pdf_token(data: bytes) -> tuple[str, bytes] | None:
    """The token in a PDF's Info dictionary or XMP, with the revision it was appended after.

    Read from the raw bytes, so a token inside a compressed object stream
    (a file re-saved by another tool) is not found.
    """
    match = _PDF_TOKEN.search(data)
    if match is None:
        return None
    token = match.group(1) or match.group(2)
    end = data.rfind(_EOF, 0, match.start())
    return token.decode("ascii"), data[: end + len(_EOF)] if end >= 0 else b""
