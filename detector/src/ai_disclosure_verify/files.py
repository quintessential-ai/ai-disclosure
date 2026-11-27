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
import re
import zipfile
import zlib
from posixpath import normpath
from typing import TYPE_CHECKING
from xml.etree import ElementTree

from defusedxml.ElementTree import fromstring

from ai_disclosure_verify.jws import b64url_encode

if TYPE_CHECKING:
    from collections.abc import Iterator

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
# Caps on an Office package, checked on the sizes it declares before any part
# is read. Parts are hashed as they are inflated, so the size cap bounds the
# time a digest takes, not memory.
MAX_PACKAGE_PARTS = 10_000
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
# The routing and custom-properties parts are parsed whole.
MAX_XML_PART_BYTES = 4 * 1024 * 1024
# OPC packages use only these; zipfile does not bound every other method's output.
_PACKAGE_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_READ_CHUNK = 64 * 1024
_EOF = b"%%EOF"
# Zip records (APPNOTE 4.3): the end of central directory record, 22 bytes
# whose last two give the length of the comment after it; the Zip64 end record
# and its 20-byte locator; and a data descriptor's optional signature.
_EOCD = b"PK\x05\x06"
_EOCD_SIZE = 22
_ZIP64_END = b"PK\x06\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_LOCATOR_SIZE = 20
_DATA_DESCRIPTOR = b"PK\x07\x08"
# The one extra field a package may carry (APPNOTE 4.5.3), and the most its
# data can hold: two sizes, an offset and a disk number.
_ZIP64_EXTRA_ID = 0x0001
_ZIP64_EXTRA_MAX = 28
# A part name holds no control character (ECMA-376 Part 2, 9.1.1), C1
# included: a part name is an IRI, whose characters start at U+00A0. A line
# feed in one would let two ``ooxml-parts/1`` listings read the same.
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _pdf_name_pattern(name: str) -> bytes:
    """A PDF name's characters, each as written or ``#xx``-escaped (ISO 32000-1, 7.3.5)."""
    return b"".join(
        b"(?:" + re.escape(char.encode()) + f"|#(?i:{ord(char):02x}))".encode()
        for char in name
    )


# PDF whitespace (ISO 32000-1, 7.2.2): unlike ``\s``, it includes NUL and not VT.
_PDF_WHITESPACE = rb"[\x00\t\n\f\r ]"
# Where the property can be: the Info key as a whole name once its escapes are
# decoded, or the complete XMP QName as an element or an attribute. The XMP
# prefix is matched as written, not resolved to its namespace.
_PDF_PROPERTY = re.compile(
    rb"/" + _pdf_name_pattern(FILE_PROPERTY) + rb"(?=[\x00\t\n\f\r ()<>\[\]{}/%]|$)"
    rb"|<cpxai:" + FILE_PROPERTY.encode() + rb"(?=[\s/>])"
    rb"|(?<=\s)cpxai:" + FILE_PROPERTY.encode() + rb"\s*=\s*([\"'])"
)
# Whitespace and comments between a key and its value.
_PDF_SKIP = re.compile(rb"(?:" + _PDF_WHITESPACE + rb"|%[^\r\n]*)*")
_HEX_DIGITS = re.compile(rb"[0-9A-Fa-f]*")
# A literal string's parts: plain bytes, an escape, or a parenthesis.
_PDF_LITERAL_PART = re.compile(rb"[^()\\]+|\\.|[()\\]", re.DOTALL)
# A PDF literal string escape: a named character, up to three octal digits,
# or a backslash before a line break, which continues the string.
_PDF_ESCAPE = re.compile(rb"\\([0-7]{1,3}|\r\n|.)", re.DOTALL)
_PDF_NAMED_ESCAPES = {
    b"n": b"\n",
    b"r": b"\r",
    b"t": b"\t",
    b"b": b"\b",
    b"f": b"\f",
    b"\r\n": b"",
    b"\r": b"",
    b"\n": b"",
}


def is_ooxml(data: bytes) -> bool:
    """True for a zip container, the OOXML packaging."""
    return data.startswith(b"PK\x03\x04")


def ooxml_uncovered(data: bytes) -> bool:
    """Whether a package holds any byte its marker does not cover.

    The rule is the specification's, at the end of ``ooxml-parts/1``. Any
    package zipfile cannot open counts as uncovered.
    """
    try:
        layout = _zip_layout(data)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = sorted(zf.infolist(), key=lambda info: info.header_offset)
    except (zipfile.BadZipFile, ValueError, NotImplementedError, OSError):
        return True
    if layout is None:
        return True
    cd_start = layout
    # The directory's own fields: what zipfile read from each record.
    if any(
        info.comment
        or not _only_zip64(info.extra)
        or (info.is_dir() and (info.compress_size or info.file_size))
        for info in infos
    ):
        return True
    position = 0
    for index, info in enumerate(infos):
        following = (
            infos[index + 1].header_offset if index + 1 < len(infos) else cd_start
        )
        entry_end = _local_entry_end(data, info, position, following)
        if info.header_offset != position or entry_end is None:
            return True
        position = entry_end
    return position != cd_start


def _zip_layout(data: bytes) -> int | None:
    """Where the central directory starts, or None when it and the end records do not fit."""
    end = data.rfind(_EOCD, max(0, len(data) - _EOCD_SIZE - 0xFFFF))
    if (
        end < 0
        or len(data) != end + _EOCD_SIZE
        or data[end + _EOCD_SIZE - 2 : end + _EOCD_SIZE] != b"\x00\x00"
    ):
        # No end record, anything after it, or a comment declared, whether
        # its bytes are present or not.
        return None
    cd_size = int.from_bytes(data[end + 12 : end + 16], "little")
    cd_start = int.from_bytes(data[end + 16 : end + 20], "little")
    cd_end = end
    locator = end - _ZIP64_LOCATOR_SIZE
    if locator >= 0 and data[locator : locator + 4] == _ZIP64_LOCATOR:
        record = int.from_bytes(data[locator + 8 : locator + 16], "little")
        if data[record : record + 4] != _ZIP64_END:
            return None
        record_size = int.from_bytes(data[record + 4 : record + 12], "little")
        if record + 12 + record_size != locator:
            return None
        cd_size = int.from_bytes(data[record + 40 : record + 48], "little")
        cd_start = int.from_bytes(data[record + 48 : record + 56], "little")
        cd_end = record
    # zipfile's own offset reckoning already shifts every entry when this
    # fails; the check states the rule for readers that do not.
    if cd_start + cd_size != cd_end:
        return None
    return cd_start


def _local_entry_end(
    data: bytes, info: zipfile.ZipInfo, start: int, following: int
) -> int | None:
    """Where the local entry at ``start`` ends, or None when it is not one the marker covers."""
    if data[start : start + 4] != b"PK\x03\x04":
        return None
    name_length = int.from_bytes(data[start + 26 : start + 28], "little")
    extra_length = int.from_bytes(data[start + 28 : start + 30], "little")
    extra_start = start + 30 + name_length
    if not _only_zip64(data[extra_start : extra_start + extra_length]):
        return None
    end = extra_start + extra_length + info.compress_size
    if not info.flag_bits & 0x8:
        return end
    # A data descriptor: CRC and sizes, 4- or 8-byte, with or without its
    # signature. The one that reaches the next record is the one written.
    for size in (12, 16, 20, 24):
        has_signature = size in (16, 24)
        if has_signature and data[end : end + 4] != _DATA_DESCRIPTOR:
            continue
        if end + size == following:
            return end + size
    return None


def _only_zip64(extra: bytes) -> bool:
    """Whether an extra-field block is empty or one well-formed Zip64 field."""
    if not extra:
        return True
    if len(extra) < 4:
        return False
    field_id = int.from_bytes(extra[0:2], "little")
    size = int.from_bytes(extra[2:4], "little")
    return (
        field_id == _ZIP64_EXTRA_ID
        and size <= _ZIP64_EXTRA_MAX
        and len(extra) == 4 + size
    )


def is_pdf(data: bytes) -> bool:
    """True when ``data`` starts with the PDF header."""
    return data.startswith(b"%PDF-")


def _package_infos(zf: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    """The package's parts by name, refused on what they declare before any is read."""
    entries = zf.infolist()
    # Directory entries count too: each costs as much to hold as a part.
    if len(entries) > MAX_PACKAGE_PARTS:
        msg = f"Office package has more than {MAX_PACKAGE_PARTS} entries"
        raise ValueError(msg)
    # ``orig_filename``: zipfile cuts ``filename`` at a NUL.
    if any(_CONTROL_CHARACTER.search(info.orig_filename) for info in entries):
        msg = "Office package entry name holds a control character"
        raise ValueError(msg)
    infos = [info for info in entries if not info.is_dir()]
    by_name = {info.filename: info for info in infos}
    if len(by_name) != len(infos):
        msg = "duplicate Office package part"
        raise ValueError(msg)
    if sum(info.file_size for info in infos) > MAX_PACKAGE_BYTES:
        msg = f"Office package is over {MAX_PACKAGE_BYTES} bytes uncompressed"
        raise ValueError(msg)
    for info in infos:
        if info.compress_type not in _PACKAGE_COMPRESSION:
            msg = (
                f"cannot read Office package parts: {info.filename} "
                f"uses compression method {info.compress_type}"
            )
            raise ValueError(msg)
        if info.flag_bits & 0x1:
            msg = f"cannot read Office package parts: {info.filename} is encrypted"
            raise ValueError(msg)
    return by_name


def _read_chunks(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> Iterator[bytes]:
    # A sized read inflates at most that much per step and stops at the
    # declared size; an unsized one inflates the whole stream first.
    try:
        with zf.open(info) as part:
            while chunk := part.read(_READ_CHUNK):
                yield chunk
    except (RuntimeError, NotImplementedError, OSError, EOFError, zlib.error) as exc:
        msg = f"cannot read Office package parts: {exc}"
        raise ValueError(msg) from exc


def _read_part(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """A routing or metadata part, whole; refused over ``MAX_XML_PART_BYTES``."""
    if info.file_size > MAX_XML_PART_BYTES:
        msg = (
            f"Office routing or metadata part {info.filename} is over "
            f"{MAX_XML_PART_BYTES} bytes"
        )
        raise ValueError(msg)
    return b"".join(_read_chunks(zf, info))


def _part_sha256(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    digest = hashlib.sha256()
    for chunk in _read_chunks(zf, info):
        digest.update(chunk)
    return digest.digest()


def _custom_properties_part(rels: bytes | None) -> str:
    if rels is None:
        return _CUSTOM_PART
    custom = [
        rel
        for rel in fromstring(rels).iterfind(f"{{{_NS_REL}}}Relationship")
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
    try:
        written = ElementTree.tostring(root, encoding="unicode")
    except RecursionError as exc:
        # The serialiser recurses once per level of nesting.
        msg = "Office routing XML is nested too deeply"
        raise ValueError(msg) from exc
    return ElementTree.canonicalize(
        written, strip_text=True, rewrite_prefixes=True
    ).encode("utf-8")


def ooxml_digest(data: bytes) -> str:
    """``ooxml-parts/1``: SHA-256 over part names and hashes, with normalized package routing.

    Follows the specification's steps. Raises ``ValueError``, or the error
    zipfile or the XML parser raises, for a package step 1 refuses. Parts
    other than the routing and custom-properties ones are hashed as they are
    inflated.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = _package_infos(zf)
        rels = _read_part(zf, infos[_ROOT_RELS]) if _ROOT_RELS in infos else None
        custom = _custom_properties_part(rels)
        if (
            custom in infos
            and fromstring(_read_part(zf, infos[custom])).tag
            != f"{{{_NS_CUSTOM}}}Properties"
        ):
            msg = "custom-properties part is not metadata"
            raise ValueError(msg)
        hashes: dict[str, bytes] = {}
        for name, info in infos.items():
            if name == custom:
                continue
            if name == _ROOT_RELS and rels is not None:
                routing = _normalized_routing(
                    rels, f"{{{_NS_REL}}}Relationship", "Type", _REL_CUSTOM
                )
            elif name == _CONTENT_TYPES:
                routing = _normalized_routing(
                    _read_part(zf, info),
                    f"{{{_NS_CT}}}Override",
                    "PartName",
                    f"/{custom}",
                )
            else:
                hashes[name] = _part_sha256(zf, info)
                continue
            hashes[name] = hashlib.sha256(routing).digest()
    listing = "".join(
        f"{name}\n{b64url_encode(hashes[name])}\n" for name in sorted(hashes)
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
    """The token in the package's ``AIDisclosure`` custom property, if any.

    Reads only the package relationships and the custom-properties part. A
    property without a value gives ``""``: it is still an attempt at a marker.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = _package_infos(zf)
        rels = _read_part(zf, infos[_ROOT_RELS]) if _ROOT_RELS in infos else None
        part = _custom_properties_part(rels)
        if part not in infos:
            return None
        props = fromstring(_read_part(zf, infos[part]))
    if props.tag != f"{{{_NS_CUSTOM}}}Properties":
        msg = "custom-properties part is not metadata"
        raise ValueError(msg)
    for prop in props.iterfind(f"{{{_NS_CUSTOM}}}property"):
        if prop.get("name") == FILE_PROPERTY:
            return (prop[0].text or "").strip() if len(prop) else ""
    return None


def pdf_token(data: bytes) -> tuple[str, bytes] | None:
    """The token in a PDF's Info dictionary or XMP, with the revision it was appended after.

    Found as the specification's ``pdf-revision/1`` sets out, in the raw
    bytes, so a token inside a compressed object stream is not found. A
    property that is present always gives a token, ``""`` when it holds no
    string: it is still an attempt at a marker.
    """
    position = 0
    first: re.Match[bytes] | None = None
    while (match := _PDF_PROPERTY.search(data, position)) is not None:
        first = first or match
        value, position = _pdf_property_value(data, match)
        if value is not None:
            return _pdf_found(data, value, match.start())
    if first is None:
        return None
    return _pdf_found(data, b"", first.start())


def _pdf_found(data: bytes, value: bytes, start: int) -> tuple[str, bytes]:
    end = data.rfind(_EOF, 0, start)
    # A byte outside ASCII cannot be in a token; replaced, it reads as malformed.
    return (
        value.decode("ascii", errors="replace"),
        data[: end + len(_EOF)] if end >= 0 else b"",
    )


def _pdf_property_value(
    data: bytes, match: re.Match[bytes]
) -> tuple[bytes | None, int]:
    """The property's value, or None when this occurrence holds no string, and where to search on.

    An unterminated string is a value, ``b""``: searching past it would let
    each later occurrence rescan the rest of the file.
    """
    quote_mark = match.group(1)
    if quote_mark is not None:
        close = data.find(quote_mark, match.end())
        return (data[match.end() : close] if close >= 0 else b""), len(data)
    if match.group().startswith(b"<"):
        tag_end = data.find(b">", match.end())
        if tag_end < 0 or data[tag_end - 1 : tag_end] == b"/":
            return b"", len(data)
        text_end = data.find(b"<", tag_end + 1)
        return (data[tag_end + 1 : text_end] if text_end >= 0 else b""), len(data)
    skipped = _PDF_SKIP.match(data, match.end())
    position = skipped.end() if skipped else match.end()
    if data[position : position + 1] == b"(":
        # Escapes are decoded (ISO 32000-1, 7.3.4.2): a writer may escape any byte.
        body = _pdf_literal_body(data, position)
        return (_pdf_literal(body) if body is not None else b""), len(data)
    if data[position : position + 2] != b"<<" and data[position : position + 1] == b"<":
        return _pdf_hex(data, position), len(data)
    # Not a string, so not the property; searching on after the skipped
    # comments ignores names inside them.
    return None, position


def _pdf_literal_body(data: bytes, start: int) -> bytes | None:
    """A literal string's body, balanced parentheses kept, or None when it never closes."""
    depth = 0
    for part in _PDF_LITERAL_PART.finditer(data, start):
        if part.group() == b"(":
            depth += 1
        elif part.group() == b")":
            depth -= 1
            if depth == 0:
                return data[start + 1 : part.start()]
    return None


def _pdf_hex(data: bytes, start: int) -> bytes:
    """A hexadecimal string's bytes (ISO 32000-1, 7.3.4.3), or ``b""`` when it is not hex."""
    end = data.find(b">", start)
    if end < 0:
        return b""
    digits = re.sub(_PDF_WHITESPACE, b"", data[start + 1 : end])
    # bytes.fromhex would skip other whitespace, such as VT, that PDF does not.
    if not _HEX_DIGITS.fullmatch(digits):
        return b""
    # A final odd digit stands for that digit followed by 0.
    return bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("ascii"))


def _pdf_literal(raw: bytes) -> bytes:
    """The bytes a PDF literal string's body stands for (ISO 32000-1, 7.3.4.2)."""

    def unescape(match: re.Match[bytes]) -> bytes:
        escaped = match.group(1)
        if escaped[0] in b"01234567":
            return bytes([int(escaped, 8) & 0xFF])
        return _PDF_NAMED_ESCAPES.get(escaped, escaped)

    return _PDF_ESCAPE.sub(unescape, raw)
