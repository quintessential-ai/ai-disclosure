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
from helpers import (
    GOLDEN_KID,
    golden_public_key,
    golden_token,
    signed_vector_body,
    signed_vector_claims,
)

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
from ai_disclosure_verify.canonical import (
    CANONICALISATION,
    MAX_DOCUMENT_BYTES,
    canonical_as,
    digest_of_canonical,
    scan_html,
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


def test_deeply_nested_office_xml_keeps_the_marker(tmp_path: Path) -> None:
    """Routing XML too deep to serialise: the marker is found, its content is not."""
    docx = (FIXTURES / "signed.docx").read_bytes()
    deep = (
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + b"<a>" * 5000
        + b"</a>" * 5000
        + b"</Types>"
    )
    package = _repack(docx, "[Content_Types].xml", deep)

    report = detect_file(package, KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    (finding,) = report.findings
    assert finding.signature is SignatureStatus.VALID
    assert finding.content is ContentCheck.NOT_FOUND
    assert _run(tmp_path, package) == cli.EXIT_UNVERIFIED


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


def test_a_differing_plain_text_alternative_is_not_checked(
    signed: tuple[str, str],
) -> None:
    """The documented caveat: mail clients show the HTML, not this part."""
    body, token = signed
    plain = _plain_of(body).replace("Friday", "Monday")
    assert plain != _plain_of(body)
    message = _eml(body, token, plain=plain)

    report = detect_message(bytes(message), KEYS)

    assert not report.unmarked_content
    assert report.verdict is Verdict.VERIFIED


def test_a_plain_text_alternative_beside_a_related_html_part_is_not_checked(
    signed: tuple[str, str],
) -> None:
    """Outlook's shape: the HTML sits in multipart/related inside the alternative."""
    body, token = signed
    message = _eml(body, token, plain="Something else entirely.")
    _, html = message.iter_parts()
    html.make_related()

    report = detect_message(bytes(message), KEYS)

    assert html.get_content_type() == "multipart/related"
    assert report.verdict is Verdict.VERIFIED


def test_a_plain_text_part_outside_the_alternative_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    message.make_mixed()
    extra = EmailMessage()
    extra.set_content("Send the money to IBAN XX99 instead.")
    extra["Content-Disposition"] = "inline"
    message.attach(extra)

    report = detect_message(bytes(message), KEYS)

    assert report.unmarked_content
    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_a_plain_text_part_beside_the_html_in_related_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    """Only a direct child of the alternative is the plain-text alternative."""
    body, token = signed
    message = _eml(body, token)
    message.add_related("Send the money to IBAN XX99 instead.")

    report = detect_message(bytes(message), KEYS)

    assert message.get_content_type() == "multipart/related"
    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_a_plain_text_alternative_to_another_part_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    """Only the alternative that holds the HTML body is passed over."""
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    message.make_mixed()
    extra = EmailMessage()
    extra.set_content("Send the money to IBAN XX99 instead.")
    extra.make_alternative()
    message.attach(extra)

    report = detect_message(bytes(message), KEYS)

    assert extra.get_content_type() == "multipart/alternative"
    assert report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT


def test_a_second_html_alternative_is_unmarked_content(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    message.add_alternative(
        "<p>Send the money to IBAN XX99 instead</p>", subtype="html"
    )

    report = detect_message(bytes(message), KEYS)

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


def test_an_undecodable_plain_text_alternative_is_not_read(
    signed: tuple[str, str],
) -> None:
    body, token = signed
    message = _eml(body, token, plain=_plain_of(body))
    plain = next(message.iter_parts())
    plain.set_param("charset", "x-no-such-charset")

    report = detect_message(bytes(message), KEYS)

    assert report.verdict is Verdict.VERIFIED


def test_other_parts_do_not_matter_without_the_messages_own_marker() -> None:
    message = EmailMessage()
    message.set_content("Something else.")
    message.add_alternative("<p>Hello</p>", subtype="html")

    report = detect_message(bytes(message))

    assert report.verdict is Verdict.NONE
    assert not report.unmarked_content


def test_the_verified_meanings_name_what_they_cover() -> None:
    assert "words and links" in VERDICT_MEANING[Verdict.VERIFIED]
    assert (
        "a plain-text alternative to the HTML body is not checked"
        in VERDICT_MEANING[Verdict.VERIFIED]
    )
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


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_disclosure_header_is_a_marker_attempt(value: str) -> None:
    raw = (
        "From: sender@example.test\r\n"
        f"X-Complexio-AI-Disclosure:{value}\r\n"
        "Content-Type: text/html\r\n\r\n<p>Payment is due.</p>\r\n"
    ).encode()

    report = detect_message(raw, KEYS)

    assert report.verdict is Verdict.UNVERIFIED
    (finding,) = report.findings
    assert finding.carrier is Carrier.HEADER
    assert finding.error is not None


# ---------------------------------------------------------------------------
# Telling file types apart
# ---------------------------------------------------------------------------


def test_a_fragment_starting_with_text_is_read_as_html(
    signed: tuple[str, str],
) -> None:
    body, _ = signed

    report = detect_file(f"Here is what I received\n{body}".encode(), KEYS)

    # Text before the container: the marker is found, but is not this one's own.
    assert report.verdict is Verdict.QUOTED_ONLY
    assert report.findings[0].carrier is Carrier.BODY


@pytest.mark.parametrize(
    "first_lines",
    ["Note: what I received\n", "Payment: due\n\n", "From me, unedited\n"],
    ids=["header-like", "header-like-then-blank", "mbox-like"],
)
def test_a_fragment_starting_with_a_header_like_line_is_read_as_html(
    signed: tuple[str, str], first_lines: str
) -> None:
    body, _ = signed
    data = f"{first_lines}{body}".encode()

    report = detect_file(data, KEYS)

    assert report.to_dict() == detect_html(data.decode(), KEYS).to_dict()
    assert report.verdict is Verdict.QUOTED_ONLY


def test_an_unreadable_fragment_holding_a_marker_is_not_no_marker() -> None:
    padding = "<p>x</p>" * (MAX_DOCUMENT_BYTES // 8)
    data = f'Note: long\n<div data-ai-disclosure="x"></div>{padding}'.encode()

    assert detect_file(data, KEYS).verdict is Verdict.UNPARSEABLE


def test_a_message_with_an_html_body_is_not_read_again(
    signed: tuple[str, str],
) -> None:
    body, _ = signed
    message = EmailMessage()
    message["Subject"] = "Forwarded"
    message.set_content("<p>See the attachment.</p>", subtype="html")
    message.add_attachment(body, subtype="html", filename="earlier.html")

    assert detect_file(bytes(message), KEYS).verdict is Verdict.NONE


def test_a_message_with_markup_but_no_marker_has_no_marker() -> None:
    data = b"Subject: hello\r\n\r\nPlease read <b>this</b>.\r\n"

    assert detect_file(data, KEYS).verdict is Verdict.NONE


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


def test_a_legacy_marker_nested_past_the_json_cap_reads_as_malformed() -> None:
    value = '{"ai_generated": true, "n": ' + "[" * 50_000 + "]" * 50_000 + "}"
    body = (
        f"<div data-ai-disclosure='{value}' "
        'style="display:none" aria-hidden="true"></div>'
    )

    (finding,) = detect_html(body).findings

    assert finding.legacy
    assert finding.error == "malformed legacy marker: JSON nested more than 32 deep"


@pytest.mark.parametrize(
    "charset",
    ['"ut\x00f"', "idna"],
    ids=["nul-in-name", "codec-that-cannot-decode"],
)
def test_a_charset_the_codecs_refuse_fails_closed(charset: str) -> None:
    raw = (
        "Subject: x\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset={charset}\r\n\r\n<p>{'a' * 70}</p>\r\n"
    ).encode()

    with pytest.raises(MessageDecodeError, match="cannot decode"):
        detect_message(raw)


def test_the_command_escapes_the_unparseable_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A reason can quote the input; it must not reach the terminal raw.
    report = DetectionReport((), unparseable="bad \x1b[31mtag")
    monkeypatch.setattr(cli, "detect_file", lambda *_: report)

    assert _run(tmp_path, b"<p>x</p>") == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\\x1b[31mtag" in err


def test_the_command_escapes_input_quoted_in_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    eml = (
        b"Subject: x\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: text/html; charset="x\x1b[31mred"\r\n\r\n<p>x</p>\r\n'
    )

    assert _run(tmp_path, eml) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\\x1b[31mred" in err


def test_a_lone_surrogate_is_hashed_as_the_replacement_character() -> None:
    assert digest_of_canonical("a\ud800b") == digest_of_canonical("a�b")
    # A surrogate pair is the character it encodes, as in JavaScript.
    assert digest_of_canonical("😀") == digest_of_canonical("\U0001f600")
    # A URL holding one is kept as written (text-links/2) and hashed the same way.
    assert digest_of_canonical("https://x.test/\ud800") == digest_of_canonical(
        "https://x.test/�"
    )


def test_content_with_a_lone_surrogate_verifies() -> None:
    mid = "0" * 31 + "7"
    content = f'<div data-ai-content="{mid}"><p>Rates \ud800 up</p></div>'
    canonical = canonical_as(
        scan_html(content).regions[mid].canonical, CANONICALISATION
    )
    vector = {
        "input": {"mid": mid},
        "expected": {"content_sha256": digest_of_canonical(canonical)},
    }
    token = golden_token(signed_vector_claims(vector))
    marker = (
        f'<div data-ai-disclosure="{token}" style="display:none" '
        'aria-hidden="true"></div>'
    )

    assert detect_html(content + marker, KEYS).verdict is Verdict.VERIFIED


@pytest.mark.parametrize(
    ("header", "error"),
    [
        ({"crit": ["b64"]}, "unsupported header members ['crit']"),
        ({"b64": False, "jku": "https://x.test"}, "unsupported header members"),
        ({"kid": 7}, "header kid is not a string"),
        ({"alg": "HS256"}, "unsupported alg 'HS256'"),
        ({"alg": "Ed25519"}, "unsupported alg 'Ed25519'"),
        ({"kid": "k"}, "an unsigned token names a kid"),
    ],
    ids=[
        "crit",
        "b64-and-jku",
        "kid-not-a-string",
        "hs256",
        "ed25519-as-alg",
        "unsigned-with-a-kid",
    ],
)
def test_a_header_outside_the_profile_rejects_the_token(
    header: dict[str, Any], error: str
) -> None:
    (finding,) = detect_html(_unsigned_body({}, header)).findings

    assert finding.error is not None
    assert finding.error.startswith(error)
