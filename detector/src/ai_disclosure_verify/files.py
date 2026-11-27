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
    from collections.abc import Callable

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
# Every Zip record field is compared with the central record zipfile reads,
# pinned to one value, or locates no byte; ``ooxml-parts/1`` states the rules.
# Zip records (APPNOTE 4.3): the end of central directory record, 22 bytes
# whose last two give the length of the comment after it; the Zip64 end record
# and its 20-byte locator; and a data descriptor's optional signature.
_EOCD = b"PK\x05\x06"
_EOCD_SIZE = 22
_ZIP64_END = b"PK\x06\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_LOCATOR_SIZE = 20
# The Zip64 end record's size field with no extensible data after the fixed fields.
_ZIP64_END_SIZE = 44
_DATA_DESCRIPTOR = b"PK\x07\x08"
# The one extra field a package may carry (APPNOTE 4.5.3), and the values in
# a record's 32-bit and 16-bit fields that send a reader to it.
_ZIP64_EXTRA_ID = 0x0001
_ZIP64_MARK = 0xFFFFFFFF
_ZIP64_DISK_MARK = 0xFFFF
# A part name holds no control character (ECMA-376 Part 2, 9.1.1), C1
# included: a part name is an IRI, whose characters start at U+00A0. A line
# feed in one would let two ``ooxml-parts/1`` listings read the same.
# XML's whitespace (XML 1.0, production 3): routing text is stripped of
# these and no other character.
_XML_WHITESPACE = " \t\r\n"
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


def ooxml_uncovered(data: bytes, *, streams_complete: bool | None = None) -> bool:
    """Whether a package holds any byte its marker does not cover.

    The rule is the specification's, at the end of ``ooxml-parts/1``. Any
    package zipfile cannot open counts as uncovered. ``streams_complete`` is
    what ``ooxml_digest_and_streams`` found, when the caller has it; without
    it, every part is read again to find out.
    """
    try:
        layout = _zip_layout(data)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, NotImplementedError, OSError):
        return True
    if layout is None:
        return True
    cd_start = layout
    central = _central_names(data, cd_start, len(infos))
    # The digest leaves out directory entries, so their names are unsigned.
    if central is None or any(info.comment or info.is_dir() for info in infos):
        return True
    names = [name for name, _disk in central]
    entries = sorted(zip(infos, names, strict=True), key=lambda e: e[0].header_offset)
    position = 0
    for index, (info, name) in enumerate(entries):
        following = (
            entries[index + 1][0].header_offset
            if index + 1 < len(entries)
            else cd_start
        )
        entry_end = _local_entry_end(data, info, name, position, following)
        if info.header_offset != position or entry_end is None:
            return True
        position = entry_end
    if position != cd_start:
        return True
    if streams_complete is None:
        streams_complete = _streams_complete(data)
    return not streams_complete


def _streams_complete(data: bytes) -> bool:
    """Whether every part's data is exactly one stream of its declared sizes; False when one cannot be read."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return all(
                _entry_data(data, zf, info, lambda _chunk: None)
                for info in _package_infos(data, zf).values()
            )
    except (zipfile.BadZipFile, ValueError, NotImplementedError, OSError):
        return False


def _end_record(data: bytes) -> int:
    """Where the end of central directory record zipfile opens the package by starts, or -1."""
    return data.rfind(_EOCD, max(0, len(data) - _EOCD_SIZE - 0xFFFF))


def _zip_layout(data: bytes) -> int | None:
    """Where the central directory starts, or None when it and the end records do not fit."""
    end = _end_record(data)
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
        # The record's size counts what follows its size field; anything
        # past the fixed fields is extensible data, unread.
        record_size = int.from_bytes(data[record + 4 : record + 12], "little")
        if record_size != _ZIP64_END_SIZE or record + 12 + record_size != locator:
            return None
        zip64_size = int.from_bytes(data[record + 40 : record + 48], "little")
        zip64_start = int.from_bytes(data[record + 48 : record + 56], "little")
        # The end record's own value stands unless it holds the mark that
        # defers to the Zip64 one.
        if cd_size not in (_ZIP64_MARK, zip64_size) or cd_start not in (
            _ZIP64_MARK,
            zip64_start,
        ):
            return None
        cd_size, cd_start, cd_end = zip64_size, zip64_start, record
    # zipfile's own offset reckoning already shifts every entry when this
    # fails; the check states the rule for readers that do not.
    if cd_start + cd_size != cd_end:
        return None
    return cd_start


def _central_names(
    data: bytes, cd_start: int, count: int
) -> list[tuple[bytes, int]] | None:
    """Each central record's name bytes and the disk its entry starts on, in directory order.

    The disk is the Zip64 field's value when the record defers it there.
    None when a record's extra field is anything but the Zip64 values its
    size, offset and disk fields call for.
    """
    names: list[tuple[bytes, int]] = []
    position = cd_start
    for _ in range(count):
        if data[position : position + 4] != b"PK\x01\x02":
            return None
        compressed = int.from_bytes(data[position + 20 : position + 24], "little")
        uncompressed = int.from_bytes(data[position + 24 : position + 28], "little")
        name_length = int.from_bytes(data[position + 28 : position + 30], "little")
        extra_length = int.from_bytes(data[position + 30 : position + 32], "little")
        comment_length = int.from_bytes(data[position + 32 : position + 34], "little")
        disk = int.from_bytes(data[position + 34 : position + 36], "little")
        offset = int.from_bytes(data[position + 42 : position + 46], "little")
        extra_start = position + 46 + name_length
        # APPNOTE 4.5.3: a value for each field that holds its maximum, in this order.
        widths = [
            8 for field in (uncompressed, compressed, offset) if field == _ZIP64_MARK
        ]
        if disk == _ZIP64_DISK_MARK:
            widths.append(4)
        values = _zip64_values(data[extra_start : extra_start + extra_length], widths)
        if values is None:
            return None
        if disk == _ZIP64_DISK_MARK:
            disk = values[-1]
        names.append((data[position + 46 : extra_start], disk))
        position = extra_start + extra_length + comment_length
    return names


def _entry_disks(data: bytes, cd_start: int) -> list[int | None]:
    """The disk each central record's entry starts on; None where it defers to a Zip64 field that does not hold it.

    Read whatever else the record's extra field holds, so a disk other than
    0 is found even behind an extra field the coverage check rejects.
    """
    disks: list[int | None] = []
    position = cd_start
    while data[position : position + 4] == b"PK\x01\x02":
        lengths = [
            int.from_bytes(data[position + at : position + at + 2], "little")
            for at in (28, 30, 32)
        ]
        disk: int | None = int.from_bytes(data[position + 34 : position + 36], "little")
        if disk == _ZIP64_DISK_MARK:
            central = _central_names(data, position, 1)
            disk = central[0][1] if central else None
        disks.append(disk)
        position += 46 + sum(lengths)
    return disks


def _local_entry_end(
    data: bytes, info: zipfile.ZipInfo, name: bytes, start: int, following: int
) -> int | None:
    """Where the local entry at ``start`` ends, or None when it is not one the marker covers.

    ``name`` is the entry's name as its central record holds it.
    """
    if data[start : start + 4] != b"PK\x03\x04":
        return None
    name_length = int.from_bytes(data[start + 26 : start + 28], "little")
    extra_length = int.from_bytes(data[start + 28 : start + 30], "little")
    extra_start = start + 30 + name_length
    if data[start + 30 : extra_start] != name or not _local_fields_agree(
        data, start, data[extra_start : extra_start + extra_length], info
    ):
        return None
    end = extra_start + extra_length + info.compress_size
    if not info.flag_bits & 0x8:
        return end
    # A data descriptor: CRC and sizes, with or without its signature. The
    # sizes are 8-byte when the entry has a Zip64 field, the only extra field
    # it may have, and 4-byte otherwise (APPNOTE 4.3.9.2). The one that
    # reaches the next record, holding what the directory declares, is the
    # one written.
    declared = (info.CRC, info.compress_size, info.file_size)
    width = 8 if extra_length else 4
    for has_signature in (False, True):
        if has_signature and data[end : end + 4] != _DATA_DESCRIPTOR:
            continue
        fields = end + 4 if has_signature else end
        size = fields - end + 4 + 2 * width
        held = (
            int.from_bytes(data[fields : fields + 4], "little"),
            int.from_bytes(data[fields + 4 : fields + 4 + width], "little"),
            int.from_bytes(data[fields + 4 + width : fields + 4 + 2 * width], "little"),
        )
        if end + size == following and held == declared:
            return end + size
    return None


def _local_fields_agree(
    data: bytes, start: int, extra: bytes, info: zipfile.ZipInfo
) -> bool:
    """Whether the local header's flags, method, CRC-32, sizes and extra field are what the central directory declares.

    zipfile reads only the directory's, so a local value that differs is an
    unread byte. Behind a data descriptor (flag bit 3) each may also be zero,
    as writers leave them. The flags and compression method say how the
    entry's bytes are read, so they must be the directory's too.
    """
    flags = int.from_bytes(data[start + 6 : start + 8], "little")
    method = int.from_bytes(data[start + 8 : start + 10], "little")
    if (flags, method) != (info.flag_bits, info.compress_type):
        return False
    crc = int.from_bytes(data[start + 14 : start + 18], "little")
    compressed = int.from_bytes(data[start + 18 : start + 22], "little")
    uncompressed = int.from_bytes(data[start + 22 : start + 26], "little")
    zip64 = _ZIP64_MARK in (compressed, uncompressed)
    # A local Zip64 field holds both sizes, uncompressed first (APPNOTE 4.5.3).
    if zip64 and compressed != uncompressed:
        return False
    values = _zip64_values(extra, [8, 8] if zip64 else [])
    if values is None:
        return False
    if zip64:
        uncompressed, compressed = values
    held = (crc, compressed, uncompressed)
    declared = (info.CRC, info.compress_size, info.file_size)
    if info.flag_bits & 0x8:
        return all(
            value in (0, want) for value, want in zip(held, declared, strict=True)
        )
    return held == declared


def _zip64_values(extra: bytes, widths: list[int]) -> list[int] | None:
    """The values in ``extra`` when it is one Zip64 field of exactly ``widths``, or empty when ``widths`` is; else None."""
    if not widths:
        return [] if not extra else None
    size = sum(widths)
    if (
        len(extra) != 4 + size
        or int.from_bytes(extra[0:2], "little") != _ZIP64_EXTRA_ID
        or int.from_bytes(extra[2:4], "little") != size
    ):
        return None
    values: list[int] = []
    at = 4
    for width in widths:
        values.append(int.from_bytes(extra[at : at + width], "little"))
        at += width
    return values


def is_pdf(data: bytes) -> bool:
    """True when ``data`` starts with the PDF header."""
    return data.startswith(b"%PDF-")


def _package_infos(data: bytes, zf: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    """The package's parts by name, refused on what they declare before any is read."""
    entries = zf.infolist()
    # Directory entries count too: each costs as much to hold as a part.
    if len(entries) > MAX_PACKAGE_PARTS:
        msg = f"Office package has more than {MAX_PACKAGE_PARTS} entries"
        raise ValueError(msg)
    _check_end_records(data, len(entries))
    # zipfile reads no entry's disk. A disk deferred to a Zip64 field that
    # cannot be read is left to ``ooxml_uncovered``.
    if any(disk not in (0, None) for disk in _entry_disks(data, zf.start_dir)):
        msg = "Office package entry starts on a disk other than 0"
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


def _check_end_records(data: bytes, count: int) -> None:
    """Refuse a package whose end records name a disk other than 0 or count other than its ``count`` central records.

    zipfile reads the directory by its size and reads none of these fields.
    The records are the ones it opens the package by; ``count`` is within
    ``MAX_PACKAGE_PARTS``, so no field needs its Zip64 mark.
    """
    end = _end_record(data)

    def field(at: int, width: int) -> int:
        return int.from_bytes(data[at : at + width], "little")

    # Each record's disk, the directory's disk, and its two entry counts.
    held = [
        (field(end + 4, 2), field(end + 6, 2), field(end + 8, 2), field(end + 10, 2))
    ]
    # The locator names the disk holding the Zip64 end record, and how many disks there are.
    locator_disks = (0, 1)
    locator = end - _ZIP64_LOCATOR_SIZE
    if locator >= 0 and data[locator : locator + 4] == _ZIP64_LOCATOR:
        locator_disks = (field(locator + 4, 4), field(locator + 16, 4))
        record = field(locator + 8, 8)
        if data[record : record + 4] == _ZIP64_END:
            held.append(
                (
                    field(record + 16, 4),
                    field(record + 20, 4),
                    field(record + 24, 8),
                    field(record + 32, 8),
                )
            )
    if locator_disks != (0, 1) or any(
        fields != (0, 0, count, count) for fields in held
    ):
        msg = (
            "Office package end record names another disk or does not count "
            "its central directory records"
        )
        raise ValueError(msg)


def _entry_data(
    data: bytes,
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    sink: Callable[[bytes], object],
) -> bool:
    """Pass an entry's data, as zipfile extracts it, to ``sink``; whether it is exactly one stream of its declared sizes.

    zipfile stops at the end of a deflate stream and at the declared
    uncompressed size, leaving any byte after either unread; reading the
    entry from ``data`` shows them. Raises ``zipfile.BadZipFile`` when the
    data read fails its CRC-32, as zipfile does, and ValueError when it does
    not inflate.
    """
    try:
        # Opening checks the local header as zipfile does; nothing is read through it.
        with zf.open(info):
            pass
    except (RuntimeError, NotImplementedError, OSError) as exc:
        msg = f"cannot read Office package parts: {exc}"
        raise ValueError(msg) from exc
    name_length = int.from_bytes(
        data[info.header_offset + 26 : info.header_offset + 28], "little"
    )
    extra_length = int.from_bytes(
        data[info.header_offset + 28 : info.header_offset + 30], "little"
    )
    start = info.header_offset + 30 + name_length + extra_length
    raw = memoryview(data)[start : start + info.compress_size]
    if len(raw) != info.compress_size:
        msg = f"cannot read Office package parts: {info.filename} is truncated"
        raise ValueError(msg)
    crc = 0

    def emit(chunk: bytes | memoryview) -> None:
        nonlocal crc
        crc = zlib.crc32(chunk, crc)
        sink(bytes(chunk))

    if info.compress_type == zipfile.ZIP_STORED:
        for at in range(0, min(len(raw), info.file_size), _READ_CHUNK):
            emit(raw[at : min(at + _READ_CHUNK, info.file_size)])
        complete = info.compress_size == info.file_size
    else:
        complete = _inflate(raw, info.file_size, emit)
    if crc != info.CRC:
        msg = f"Bad CRC-32 for file {info.filename!r}"
        raise zipfile.BadZipFile(msg)
    return complete


def _inflate(raw: memoryview, size: int, emit: Callable[[bytes], None]) -> bool:
    """Inflate ``raw``, emitting its first ``size`` bytes; whether it is one deflate stream that fills ``raw`` and inflates to exactly ``size``."""
    stream = zlib.decompressobj(-zlib.MAX_WBITS)
    position = 0
    produced = 0
    try:
        # Each step inflates at most a chunk, so a small stream cannot
        # inflate into one large one, and stops once past ``size``.
        while produced <= size and not stream.eof:
            piece = stream.unconsumed_tail
            if not piece:
                piece = raw[position : position + _READ_CHUNK]
                position += len(piece)
            out = stream.decompress(piece, _READ_CHUNK)
            if not out and not piece:
                break
            emit(out[: size - produced])
            produced += len(out)
    except zlib.error as exc:
        msg = f"cannot read Office package parts: {exc}"
        raise ValueError(msg) from exc
    return (
        stream.eof
        and not stream.unused_data
        and position == len(raw)
        and produced == size
    )


def _read_part(
    data: bytes, zf: zipfile.ZipFile, info: zipfile.ZipInfo
) -> tuple[bytes, bool]:
    """A routing or metadata part, whole, and whether its data is one complete stream; refused over ``MAX_XML_PART_BYTES``."""
    if info.file_size > MAX_XML_PART_BYTES:
        msg = (
            f"Office routing or metadata part {info.filename} is over "
            f"{MAX_XML_PART_BYTES} bytes"
        )
        raise ValueError(msg)
    chunks: list[bytes] = []
    complete = _entry_data(data, zf, info, chunks.append)
    return b"".join(chunks), complete


def _part_sha256(
    data: bytes, zf: zipfile.ZipFile, info: zipfile.ZipInfo
) -> tuple[bytes, bool]:
    digest = hashlib.sha256()
    complete = _entry_data(data, zf, info, digest.update)
    return digest.digest(), complete


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
    # C14N's own ``strip_text`` strips Unicode whitespace on some Pythons and
    # XML whitespace on others, so the same file would digest two ways.
    for element in root.iter():
        if element.text is not None:
            element.text = element.text.strip(_XML_WHITESPACE)
        if element.tail is not None:
            element.tail = element.tail.strip(_XML_WHITESPACE)
    try:
        written = ElementTree.tostring(root, encoding="unicode")
    except RecursionError as exc:
        # The serialiser recurses once per level of nesting.
        msg = "Office routing XML is nested too deeply"
        raise ValueError(msg) from exc
    return ElementTree.canonicalize(written, rewrite_prefixes=True).encode("utf-8")


def ooxml_digest(data: bytes) -> str:
    """``ooxml-parts/1``: SHA-256 over part names and hashes, with normalized package routing.

    Follows the specification's steps. Raises ``ValueError``, or the error
    zipfile or the XML parser raises, for a package step 1 refuses. Parts
    other than the routing and custom-properties ones are hashed as they are
    inflated.
    """
    return ooxml_digest_and_streams(data)[0]


def ooxml_digest_and_streams(data: bytes) -> tuple[str, bool]:
    """``ooxml_digest``, and whether every part's data is exactly one stream of its declared sizes.

    Both come from one read of each part; ``ooxml_uncovered`` takes the
    second, so a checker inflates each part once.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = _package_infos(data, zf)
        complete = True
        rels = None
        if _ROOT_RELS in infos:
            rels, whole = _read_part(data, zf, infos[_ROOT_RELS])
            complete &= whole
        custom = _custom_properties_part(rels)
        if custom in infos:
            properties, whole = _read_part(data, zf, infos[custom])
            complete &= whole
            if fromstring(properties).tag != f"{{{_NS_CUSTOM}}}Properties":
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
                types, whole = _read_part(data, zf, info)
                complete &= whole
                routing = _normalized_routing(
                    types, f"{{{_NS_CT}}}Override", "PartName", f"/{custom}"
                )
            else:
                hashes[name], whole = _part_sha256(data, zf, info)
                complete &= whole
                continue
            hashes[name] = hashlib.sha256(routing).digest()
    listing = "".join(
        f"{name}\n{b64url_encode(hashes[name])}\n" for name in sorted(hashes)
    )
    return b64url_encode(hashlib.sha256(listing.encode("utf-8")).digest()), complete


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
        infos = _package_infos(data, zf)
        rels = (
            _read_part(data, zf, infos[_ROOT_RELS])[0] if _ROOT_RELS in infos else None
        )
        part = _custom_properties_part(rels)
        if part not in infos:
            return None
        props = fromstring(_read_part(data, zf, infos[part])[0])
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
