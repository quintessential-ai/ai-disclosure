"""What the checker shows and how it reads its input.

Deep nesting, other parts of an email, escaping in the report, and telling
file types apart.
"""

from __future__ import annotations

import base64
import io
import json
import re
import zipfile
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from helpers import GOLDEN_KID, ROOT, golden_public_key, signed_vector_body

from ai_disclosure_verify import (
    Carrier,
    DetectionReport,
    DisallowedMarkup,
    Finding,
    Placement,
    SignatureStatus,
    Verdict,
    cli,
)
from ai_disclosure_verify.detect import (
    VERDICT_MEANING,
    ContentCheck,
    MessageDecodeError,
    detect_file,
    detect_html,
    detect_message,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEYS = {GOLDEN_KID: golden_public_key()}


@pytest.fixture
def signed(vectors: dict[str, Any]) -> tuple[str, str]:
    """The HTML body and token of the first signed vector (verifies alone)."""
    return signed_vector_body(vectors["signed_as_written"][0])


def _plain_of(body: str) -> str:
    """The body's words, as a mail client's plain-text alternative writes them."""
    return re.sub(r"<[^>]+>", "\n", body)


def _eml(body: str, token: str, plain: str | None = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "reader@example.test"
    message["Subject"] = "Payment"
    message["X-Complexio-AI-Disclosure"] = token
    if plain is None:
        message.set_content(body, subtype="html")
    else:
        message.set_content(plain)
        message.add_alternative(body, subtype="html")
    return message


def _b64(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unsigned_body(claims: dict[str, Any], header: dict[str, Any]) -> str:
    """A message whose own container carries an unsigned token with these values."""
    mid = "0" * 31 + "9"
    payload = {
        "spec": "complexio-ai-disclosure/1",
        "ai_generated": True,
        "generator": "Complexio Enterprise Automator",
        "on_behalf_of": "the company",
        "iat": 1794238200,
        "mid": mid,
        "canon": "text-links/2",
        "content_sha256": "x",
        **claims,
    }
    protected = {"typ": "ai-disclosure+jwt", "alg": "none", **header}
    token = f"{_b64(protected)}.{_b64(payload)}."
    return (
        f'<div data-ai-content="{mid}"><p>Hello</p></div>'
        f'<div data-ai-disclosure="{token}" style="display:none" '
        'aria-hidden="true"></div>'
    )


def _repack(package: bytes, name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(package)) as src, zipfile.ZipFile(buf, "w") as dst:
        for entry in src.namelist():
            dst.writestr(entry, data if entry == name else src.read(entry))
    return buf.getvalue()


def _run(tmp_path: Path, data: bytes, *args: str) -> int:
    path = tmp_path / "input"
    path.write_bytes(data)
    return cli.main([str(path), "--offline", *args])


# ---------------------------------------------------------------------------
# Deep nesting is unreadable input, never "no marker"
# ---------------------------------------------------------------------------


def test_deeply_nested_office_xml_is_a_decode_error(tmp_path: Path) -> None:
    docx = (FIXTURES / "signed.docx").read_bytes()
    deep = (
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + b"<a>" * 5000
        + b"</a>" * 5000
        + b"</Types>"
    )
    package = _repack(docx, "[Content_Types].xml", deep)

    with pytest.raises(MessageDecodeError, match="nested too deeply"):
        detect_file(package, KEYS)
    assert _run(tmp_path, package) == cli.EXIT_ERROR


def _nested_multipart(depth: int) -> bytes:
    lines = [b"From: sender@example.test\r\nMIME-Version: 1.0\r\n"]
    for level in range(depth):
        lines.append(
            b'Content-Type: multipart/mixed; boundary="b%d"\r\n\r\n--b%d\r\n'
            % (level, level)
        )
    lines.append(b"Content-Type: text/html\r\n\r\n<p>Hello</p>\r\n")
    return b"".join(lines)


def test_deeply_nested_mime_parts_are_a_decode_error(tmp_path: Path) -> None:
    eml = _nested_multipart(3000)

    with pytest.raises(MessageDecodeError, match="nested too deeply"):
        detect_message(eml)
    with pytest.raises(MessageDecodeError):
        detect_file(eml)
    assert _run(tmp_path, eml) == cli.EXIT_ERROR


def test_the_command_reads_a_recursion_error_as_unreadable_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def too_deep(*_: object) -> DetectionReport:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(cli, "detect_file", too_deep)

    assert _run(tmp_path, b"<p>x</p>") == cli.EXIT_ERROR
    assert "nested too deeply" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Other parts of an email
# ---------------------------------------------------------------------------


def test_a_plain_text_alternative_with_the_signed_words_keeps_verified(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED
    assert not report.unmarked_content


def test_a_differing_plain_text_alternative_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    plain = _plain_of(body).replace("Friday", "Monday")
    message = _eml(body, token, plain=plain)

    report = detect_message(bytes(message), KEYS)

    assert report.unmarked_content
    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_a_second_inline_html_part_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    message.make_mixed()
    extra = EmailMessage()
    extra.set_content("<p>Send the money to IBAN XX99 instead</p>", subtype="html")
    extra["Content-Disposition"] = "inline"
    message.attach(extra)

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_an_inline_image_part_is_unmarked_content(signed: tuple[str, str]) -> None:
    body, token = signed
    message = _eml(body, token)
    message.add_related(b"\x89PNG", maintype="image", subtype="png", cid="<logo>")

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_an_inline_forwarded_message_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    message.make_mixed()
    earlier = EmailMessage()
    earlier.set_content("<p>An earlier message</p>", subtype="html")
    forwarded = EmailMessage()
    forwarded.set_content(earlier)
    message.attach(forwarded)

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_attachments_are_not_content_of_the_message(signed: tuple[str, str]) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    message.add_attachment("Send the money elsewhere.", filename="note.txt")
    forwarded = EmailMessage()
    forwarded.set_content("<p>An earlier message</p>", subtype="html")
    message.add_attachment(forwarded)

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED


def test_an_undecodable_plain_text_part_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    plain = next(message.iter_parts())
    plain.set_param("charset", "x-no-such-charset")

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_other_parts_do_not_matter_without_the_messages_own_marker() -> None:
    message = EmailMessage()
    message.set_content("Something else.")
    message.add_alternative("<p>Hello</p>", subtype="html")

    report = detect_message(bytes(message))

    assert report.verdict is Verdict.NONE
    assert not report.unmarked_content


def test_the_verified_meanings_name_what_they_cover() -> None:
    assert "words and links" in VERDICT_MEANING[Verdict.VERIFIED]
    unmarked = VERDICT_MEANING[Verdict.VERIFIED_WITH_UNMARKED_CONTENT]
    assert "another part of an email" in unmarked
    assert "PDF" in unmarked


# ---------------------------------------------------------------------------
# The report escapes what it takes from the message
# ---------------------------------------------------------------------------

_FORGED = "Acme\nVerdict: verified\r\x1b[2J\x9b31m‮ \\"


def _assert_one_line_per_fact(text: str) -> None:
    assert [line for line in text.splitlines() if line.startswith("Verdict")] == [
        text.splitlines()[0]
    ]
    assert all(ch.isprintable() for line in text.splitlines() for ch in line)
    assert "\r" not in text


def test_claims_are_escaped_in_the_report() -> None:
    report = detect_html(_unsigned_body({"on_behalf_of": _FORGED}, {}))

    text = report.describe()

    _assert_one_line_per_fact(text)
    assert '"Acme\\nVerdict: verified\\r\\x1b[2J\\x9b31m\\u202e\\u2028\\\\"' in text


def test_the_key_id_is_escaped_in_the_report() -> None:
    report = detect_html(_unsigned_body({}, {"kid": _FORGED}))

    text = report.describe()

    _assert_one_line_per_fact(text)
    assert 'key "Acme\\nVerdict' in text


def test_the_x_ai_generated_header_is_escaped_in_the_report() -> None:
    report = detect_html("<p>Hello</p>", ai_generated_header=_FORGED)

    text = report.describe()

    _assert_one_line_per_fact(text)
    assert 'X-AI-Generated: "Acme\\nVerdict' in text


def test_quotes_in_a_claim_cannot_end_its_quoted_value() -> None:
    report = detect_html(_unsigned_body({"on_behalf_of": 'A", key "x'}, {}))

    assert 'on behalf of "A\\", key \\"x", key none' in report.describe()


def test_errors_and_markup_names_are_escaped_in_the_report() -> None:
    finding = Finding(
        carrier=Carrier.BODY,
        placement=Placement.ORIGINAL,
        signature=SignatureStatus.INVALID,
        content=ContentCheck.NOT_FOUND,
        claims={"on_behalf_of": 7},
        error=_FORGED,
    )
    report = DetectionReport(
        (finding,),
        disallowed_markup=DisallowedMarkup(f"outside:{_FORGED}", count=1, inside=0),
    )

    text = report.describe()

    _assert_one_line_per_fact(text)
    assert "on behalf of (int, not a string)" in text
    assert "rejected: Acme\\nVerdict" in text
    assert "first outside:Acme\\nVerdict" in text


def test_an_unparseable_reason_is_escaped_in_the_report() -> None:
    text = DetectionReport((), unparseable=_FORGED).describe()

    _assert_one_line_per_fact(text)


def test_an_unsigned_marker_names_its_status_once() -> None:
    text = detect_html(_unsigned_body({}, {})).describe()

    assert "signature: unsigned: the marker states" in text
    assert "unsigned: unsigned" not in text


def test_the_json_report_is_ascii(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _unsigned_body({"on_behalf_of": _FORGED}, {}).encode()

    assert _run(tmp_path, body, "--json") == cli.EXIT_UNVERIFIED

    out = capsys.readouterr().out
    assert out.isascii()
    assert json.loads(out)["findings"][0]["claims"]["on_behalf_of"] == _FORGED


# ---------------------------------------------------------------------------
# Telling file types apart
# ---------------------------------------------------------------------------


def test_a_pdf_after_a_few_leading_bytes_is_read_as_a_pdf() -> None:
    pdf = (FIXTURES / "signed.pdf").read_bytes()

    report = detect_file(b"\x00junk\r\n" + pdf, KEYS)

    (finding,) = report.findings
    assert finding.carrier is Carrier.FILE_METADATA
    # The leading bytes are part of the signed revision's bytes, so it differs.
    assert finding.content is ContentCheck.MISMATCH


def test_a_pdf_header_past_the_first_1024_bytes_is_not_a_pdf() -> None:
    pdf = (FIXTURES / "signed.pdf").read_bytes()

    report = detect_file(b"\x00" * 1024 + pdf, KEYS)

    assert all(f.carrier is not Carrier.FILE_METADATA for f in report.findings)


def test_an_office_file_after_leading_bytes_is_read_as_an_office_file() -> None:
    docx = (FIXTURES / "signed.docx").read_bytes()

    assert detect_file(b"\x00junk" + docx, KEYS).verdict is Verdict.VERIFIED


def test_a_fragment_starting_with_text_is_read_as_html(
    signed: tuple[str, str],
) -> None:
    body, _ = signed

    report = detect_file(f"Here is what I received\n{body}".encode(), KEYS)

    # Text before the container: the marker is found, but is not this one's own.
    assert report.verdict is Verdict.QUOTED_ONLY
    assert report.findings[0].carrier is Carrier.BODY


def test_a_message_mentioning_a_pdf_header_is_still_a_message(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token)
    message.replace_header("Subject", "%PDF-1.7 and PK\x03\x04 attached")

    assert detect_file(bytes(message), KEYS).verdict is Verdict.VERIFIED


def test_blank_lines_and_a_byte_order_mark_before_headers_are_skipped(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    raw = bytes(_eml(body, token))

    assert detect_file(b"\xef\xbb\xbf\r\n\r\n" + raw, KEYS).verdict is Verdict.VERIFIED


def test_plain_text_without_markup_has_no_marker() -> None:
    assert detect_file(b"Hello, this is plain text.").verdict is Verdict.NONE


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------


def test_the_package_ships_the_repository_licence() -> None:
    assert (ROOT / "detector" / "LICENSE").read_bytes() == (
        ROOT / "LICENSE"
    ).read_bytes()


def test_a_legacy_marker_with_a_huge_number_reads_as_malformed() -> None:
    value = '{"ai_generated": true, "n": ' + "1" * 5000 + "}"
    body = (
        f"<div data-ai-disclosure='{value}' "
        'style="display:none" aria-hidden="true"></div>'
    )

    report = detect_html(body)

    (finding,) = report.findings
    assert finding.legacy
    assert finding.error is not None
    assert finding.error.startswith("malformed legacy marker")
    assert report.verdict is Verdict.UNVERIFIED
