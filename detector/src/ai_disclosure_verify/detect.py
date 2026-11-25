# Generated from the reference implementation. Do not edit by hand:
# changes are made there and regenerated.
"""Reference detector: find, verify and place disclosure markers in a received message.

Reads the ``X-Complexio-AI-Disclosure`` header and every in-body
``data-ai-disclosure`` block, checks each token's claims and signature,
recomputes the content digest, and says which marker is the message's own
(``original``) and which arrived inside a quoted reply trail (``quoted``).

A signature vouches for the text of one content container, not for the
message around it: a signed fragment can be copied into any message. So a
marker counts as the message's own only when its container opens the
message, and the report says whether the message carries anything outside
its container beyond the document's empty scaffolding. Placement, coverage
and markup outside the allowlist are read from html5lib's HTML5 parse tree
(``canonical.scan_html``).
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field, replace
from email import message_from_bytes, policy
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree

from defusedxml.common import DefusedXmlException

from ai_disclosure_verify.canonical import (
    MESSAGE_CANONICALISATIONS,
    ContentRegion,
    DocumentScan,
    UnparseableHtmlError,
    canonical_as,
    digest_of_canonical,
    scan_html,
)
from ai_disclosure_verify.files import (
    OOXML_CANONICALISATION,
    PDF_CANONICALISATION,
    is_ooxml,
    is_pdf,
    ooxml_digest,
    ooxml_token,
    pdf_digest,
    pdf_token,
)
from ai_disclosure_verify.jws import (
    MalformedTokenError,
    SignatureStatus,
    check_signature,
    decode_compact,
)
from ai_disclosure_verify.constants import (
    AI_GENERATED_HEADER,
    DISCLOSURE_HEADER,
    SPEC,
    TOKEN_TYPE,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_MID = re.compile(r"[0-9a-f]{32}")


class MessageDecodeError(ValueError):
    """The message or file could not be decoded far enough to look for markers."""


class Carrier(StrEnum):
    """Where a marker was found."""

    HEADER = "header"
    BODY = "body"
    # An Office file's custom property, or a PDF's Info dictionary or XMP.
    FILE_METADATA = "file_metadata"


class Placement(StrEnum):
    """Whether a marker labels this message or a copy quoted in it."""

    ORIGINAL = "original"
    QUOTED = "quoted"
    # A pre-signing marker has no content container to place it by.
    UNKNOWN = "unknown"


class ContentCheck(StrEnum):
    """Outcome of recomputing the content digest."""

    MATCH = "match"
    MISMATCH = "mismatch"
    NOT_FOUND = "content_not_found"
    # The header's content is in the body, but not where the message's own
    # content sits: quoted, nested, or after other text.
    NOT_LEADING = "content_not_leading"
    UNSUPPORTED = "unsupported_canonicalisation"


class Verdict(StrEnum):
    """The message-level answer."""

    # The message's own marker verifies, its container holds only allowlisted
    # markup, and outside it there is nothing but empty scaffolding and the
    # marker block.
    VERIFIED = "verified"
    # The message's own marker verifies, but the message carries markup
    # outside the allowlist (in its container or around it), or anything
    # outside its container: a quoted trail, styling, any element at all.
    VERIFIED_WITH_UNMARKED_CONTENT = "verified_with_unmarked_content"
    # The message carries its own marker that does not verify, or any
    # X-AI-Generated header (whatever its value), or an earlier unsigned
    # (legacy JSON) marker anywhere, a quoted trail included: a legacy marker
    # cannot be placed. So a reply that merely quotes a pre-signing message
    # reads as this. Do not treat it as "this message was labelled" for mail
    # you did not label yourself.
    UNVERIFIED = "ai_marked_unverified"
    QUOTED_ONLY = "quoted_only"
    NONE = "no_marker"
    # The HTML body is too large or too deep, or the parser failed on it.
    UNPARSEABLE = "unparseable"


SIGNATURE_MEANING: dict[SignatureStatus, str] = {
    SignatureStatus.VALID: "signed by a key in the supplied key set",
    SignatureStatus.INVALID: "signature does not verify: the marker was forged or altered",
    SignatureStatus.UNSIGNED: (
        "unsigned: the marker states AI generation but proves nothing about its origin"
    ),
    SignatureStatus.UNKNOWN_KEY: "signed with a key that is not in the supplied key set",
    SignatureStatus.NOT_CHECKED: "signature not checked: no key set was supplied",
}

CONTENT_MEANING: dict[ContentCheck, str] = {
    ContentCheck.MATCH: "content unchanged since signing",
    ContentCheck.MISMATCH: (
        "content changed after signing: edited by a person before or after "
        "sending, or altered in transit"
    ),
    ContentCheck.NOT_FOUND: (
        "the signed content was not found in the message: removed in transit"
    ),
    ContentCheck.NOT_LEADING: (
        "the signed content does not open the message (quoted, nested or after "
        "other text), so the marker is not this message's own"
    ),
    ContentCheck.UNSUPPORTED: (
        "the marker uses a content rule this detector does not support"
    ),
}

VERDICT_MEANING: dict[Verdict, str] = {
    Verdict.VERIFIED: (
        "AI-generated by Complexio's system: the message's own marker is genuine "
        "and the message holds nothing else"
    ),
    Verdict.VERIFIED_WITH_UNMARKED_CONTENT: (
        "the signed text is intact, but styling or markup in or around it, "
        "which could change how it is shown, is not vouched for, nor is the "
        "rest of the message (such as a quoted reply); see disallowed_markup, "
        "and do not attribute any of it to the marker"
    ),
    Verdict.UNVERIFIED: (
        "marked as AI-generated, but the message's own marker does not verify; "
        "see the findings (for example, content changed after signing)"
    ),
    Verdict.QUOTED_ONLY: (
        "only quoted copies of marked messages; this message itself is not marked"
    ),
    Verdict.NONE: "no AI disclosure marker found",
    Verdict.UNPARSEABLE: (
        "the HTML body could not be read safely (too large, nested too deep, "
        "or the parser failed); nothing in it is verified"
    ),
}


@dataclass(frozen=True)
class Finding:
    """One marker and what checking it showed."""

    carrier: Carrier
    placement: Placement
    signature: SignatureStatus
    content: ContentCheck
    claims: dict[str, Any] = field(default_factory=dict)
    kid: str | None = None
    legacy: bool = False
    error: str | None = None

    @property
    def verified(self) -> bool:
        """Claims well-formed, signature valid against the key set, digest matching."""
        return (
            self.error is None
            and self.signature is SignatureStatus.VALID
            and self.content is ContentCheck.MATCH
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form for the CLI."""
        return {
            "carrier": self.carrier.value,
            "placement": self.placement.value,
            "signature": self.signature.value,
            "content": self.content.value,
            "signature_meaning": SIGNATURE_MEANING[self.signature],
            "content_meaning": CONTENT_MEANING[self.content],
            "verified": self.verified,
            "kid": self.kid,
            "legacy": self.legacy,
            "error": self.error,
            "claims": self.claims,
        }


@dataclass(frozen=True)
class DisallowedMarkup:
    """Markup outside the allowlist in a message.

    ``first`` names the first violation inside the original container, else
    the first in the message, as ``inside:NAME`` or ``outside:NAME``; see
    ``canonical.Violation`` for the names.
    """

    first: str
    count: int
    inside: int

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form for the CLI."""
        return {"first": self.first, "count": self.count, "inside": self.inside}


@dataclass(frozen=True)
class DetectionReport:
    """Every marker found in one message, plus the ``X-AI-Generated`` flag.

    ``unmarked_content`` is set when the message's own marker was found and the
    message has text, links, images or any other element outside its content
    container, beyond the document's scaffolding and the marker block.
    ``disallowed_markup`` describes markup outside the allowlist, placed
    against the original container. ``unparseable`` says why the HTML could
    not be read; the findings are then empty.
    """

    findings: tuple[Finding, ...]
    ai_generated_header: str | None = None
    unmarked_content: bool = False
    disallowed_markup: DisallowedMarkup | None = None
    unparseable: str | None = None

    @property
    def verdict(self) -> Verdict:
        """The message-level answer; see ``Verdict``."""
        if self.unparseable is not None:
            return Verdict.UNPARSEABLE
        originals = [f for f in self.findings if f.placement is Placement.ORIGINAL]
        if any(f.verified for f in originals):
            if self.disallowed_markup is not None or self.unmarked_content:
                return Verdict.VERIFIED_WITH_UNMARKED_CONTENT
            return Verdict.VERIFIED
        unplaced = any(f.placement is Placement.UNKNOWN for f in self.findings)
        if originals or unplaced or self.ai_generated_header is not None:
            return Verdict.UNVERIFIED
        if self.findings:
            return Verdict.QUOTED_ONLY
        return Verdict.NONE

    def describe(self) -> str:
        """A plain-language account of the report, one fact per line."""
        lines = [
            f"Verdict: {self.verdict.value}",
            f"  {VERDICT_MEANING[self.verdict]}",
            f"Content outside the marker: {'yes' if self.unmarked_content else 'no'}",
        ]
        if self.unparseable is not None:
            lines.append(f"Unparseable: {self.unparseable}")
        markup = self.disallowed_markup
        if markup is not None:
            lines.append(
                f"Markup outside the allowlist: {markup.count} "
                f"({markup.inside} inside the marker's content), first {markup.first}"
            )
        if self.ai_generated_header is not None:
            lines.append(f"X-AI-Generated: {self.ai_generated_header}")
        for number, finding in enumerate(self.findings, start=1):
            lines.append(
                f"Marker {number} ({finding.carrier.value}, {finding.placement.value})"
                f": on behalf of {finding.claims.get('on_behalf_of', '?')}"
                f", key {finding.kid or 'none'}"
            )
            lines.append(
                f"  signature: {finding.signature.value}: "
                f"{SIGNATURE_MEANING[finding.signature]}"
            )
            lines.append(
                f"  content: {finding.content.value}: {CONTENT_MEANING[finding.content]}"
            )
            if finding.legacy:
                lines.append("  earlier, unsigned marker format")
            if finding.error:
                lines.append(f"  rejected: {finding.error}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form for the CLI."""
        return {
            "verdict": self.verdict.value,
            "meaning": VERDICT_MEANING[self.verdict],
            "x_ai_generated": self.ai_generated_header,
            "unmarked_content": self.unmarked_content,
            "disallowed_markup": (
                self.disallowed_markup.to_dict() if self.disallowed_markup else None
            ),
            "unparseable": self.unparseable,
            "findings": [f.to_dict() for f in self.findings],
        }


def detect_html(
    document: str,
    keys: Mapping[str, Ed25519PublicKey] | None = None,
    *,
    header_token: str | None = None,
    ai_generated_header: str | None = None,
) -> DetectionReport:
    """Detect markers in an HTML body, plus a header token when the caller has one.

    The original is the body marker whose content container leads the
    document (no text before it, not inside a ``blockquote`` or another
    container). With a header token it must also share the header's ``mid``;
    a header whose content does not lead the document is ``NOT_LEADING``.
    A document ``scan_html`` cannot read gives an empty, ``unparseable`` report.
    """
    try:
        scan = scan_html(document)
    except UnparseableHtmlError as exc:
        return DetectionReport((), ai_generated_header, unparseable=str(exc))
    findings: list[Finding] = []
    header_mid: str | None = None
    if header_token:
        header = _check_token(
            header_token, scan, keys, Carrier.HEADER, Placement.ORIGINAL
        )
        header_mid = _mid_of(header)
        region = scan.regions.get(header_mid or "")
        if region is not None and not region.leads:
            header = replace(header, content=ContentCheck.NOT_LEADING)
        findings.append(header)
    original_region: ContentRegion | None = None
    for marker in scan.markers:
        finding = _check_token(marker.value, scan, keys, Carrier.BODY, Placement.QUOTED)
        if finding.legacy:
            findings.append(replace(finding, placement=Placement.UNKNOWN))
            continue
        region = scan.regions.get(_mid_of(finding) or "")
        is_original = (
            original_region is None
            and region is not None
            and region.leads
            and (header_mid is None or _mid_of(finding) == header_mid)
        )
        if is_original:
            original_region = region
            finding = replace(finding, placement=Placement.ORIGINAL)
        findings.append(finding)
    if original_region is None and header_mid is not None:
        candidate = scan.regions.get(header_mid)
        original_region = candidate if candidate and candidate.leads else None
    return DetectionReport(
        tuple(findings),
        ai_generated_header,
        unmarked_content=(
            original_region is not None and scan.has_content_outside(original_region)
        ),
        disallowed_markup=_disallowed_markup(
            scan, original_region.mid if original_region else None
        ),
    )


def _disallowed_markup(scan: DocumentScan, mid: str | None) -> DisallowedMarkup | None:
    if not scan.violations:
        return None
    located = [violation.located(mid) for violation in scan.violations]
    inside = [name for name in located if name.startswith("inside:")]
    return DisallowedMarkup(
        first=(inside or located)[0], count=len(located), inside=len(inside)
    )


def detect_message(
    raw: bytes, keys: Mapping[str, Ed25519PublicKey] | None = None
) -> DetectionReport:
    """Detect markers in an RFC 5322 message (an ``.eml`` file).

    Raises:
        MessageDecodeError: The HTML part declares a charset Python cannot decode.

    """
    message = message_from_bytes(raw, policy=policy.default)
    body = message.get_body(preferencelist=("html",))
    try:
        document = body.get_content() if body is not None else ""
    except LookupError as exc:
        msg = f"cannot decode the HTML part: {exc}"
        raise MessageDecodeError(msg) from exc
    header_token = message.get(DISCLOSURE_HEADER)
    flag = message.get(AI_GENERATED_HEADER)
    return detect_html(
        document,
        keys,
        header_token=str(header_token).strip() if header_token else None,
        ai_generated_header=str(flag).strip() if flag is not None else None,
    )


def detect_file(
    data: bytes, keys: Mapping[str, Ed25519PublicKey] | None = None
) -> DetectionReport:
    """Detect markers in an Office (OOXML) file, a PDF, a bare HTML document or an RFC 5322 message."""
    if is_ooxml(data):
        try:
            token = ooxml_token(data)
        except (
            zipfile.BadZipFile,
            ElementTree.ParseError,
            DefusedXmlException,
            ValueError,
        ) as exc:
            msg = f"cannot read the Office package: {exc}"
            raise MessageDecodeError(msg) from exc
        return _detect_document(
            token, keys, OOXML_CANONICALISATION, lambda: ooxml_digest(data)
        )
    if is_pdf(data):
        found = pdf_token(data)
        report = _detect_document(
            found[0] if found else None,
            keys,
            PDF_CANONICALISATION,
            lambda: pdf_digest(found[1] if found else b""),
        )
        return replace(report, unmarked_content=found is not None)
    head = data.lstrip()[:1]
    if head == b"<":
        return detect_html(data.decode("utf-8", errors="replace"), keys)
    return detect_message(data, keys)


def _detect_document(
    token: str | None,
    keys: Mapping[str, Ed25519PublicKey] | None,
    canon: str,
    digest: Callable[[], str],
) -> DetectionReport:
    """Check the file marker against its canonical content or original PDF revision."""
    if token is None:
        return DetectionReport(())
    finding = _check_token(token, None, keys, Carrier.FILE_METADATA, Placement.ORIGINAL)
    if not finding.claims:
        return DetectionReport((finding,))
    if finding.claims.get("canon") != canon:
        content = ContentCheck.UNSUPPORTED
    else:
        try:
            matches = digest() == finding.claims.get("content_sha256")
        except (
            ValueError,
            zipfile.BadZipFile,
            ElementTree.ParseError,
            DefusedXmlException,
        ):
            content = ContentCheck.NOT_FOUND
        else:
            content = ContentCheck.MATCH if matches else ContentCheck.MISMATCH
    return DetectionReport((replace(finding, content=content),))


def _mid_of(finding: Finding) -> str | None:
    mid = finding.claims.get("mid")
    return mid if isinstance(mid, str) else None


def _check_token(
    value: str,
    scan: DocumentScan | None,
    keys: Mapping[str, Ed25519PublicKey] | None,
    carrier: Carrier,
    placement: Placement,
) -> Finding:
    if value.lstrip().startswith("{"):
        return _legacy_finding(value, carrier, placement)
    try:
        token = decode_compact(value)
    except MalformedTokenError as exc:
        return Finding(
            carrier=carrier,
            placement=placement,
            signature=SignatureStatus.INVALID,
            content=ContentCheck.NOT_FOUND,
            error=f"malformed token: {exc}",
        )
    claims = token.payload
    kid = token.header.get("kid")
    return Finding(
        carrier=carrier,
        placement=placement,
        signature=check_signature(token, keys),
        content=_check_content(claims, scan)
        if scan is not None
        else ContentCheck.NOT_FOUND,
        claims=claims,
        kid=str(kid) if kid is not None else None,
        error=_claims_error(token.header, claims),
    )


def _claims_error(header: Mapping[str, Any], claims: Mapping[str, Any]) -> str | None:
    """Why the token is not a version-1 disclosure marker, or None when it is."""
    if header.get("typ") != TOKEN_TYPE:
        return f"unsupported typ {header.get('typ')!r}"
    if claims.get("spec") != SPEC:
        return f"unsupported spec {claims.get('spec')!r}"
    if claims.get("ai_generated") is not True:
        return "ai_generated is not true"
    for name in ("generator", "on_behalf_of", "canon", "content_sha256"):
        if not isinstance(claims.get(name), str) or not claims[name]:
            return f"claim {name} missing or not a string"
    if not isinstance(claims.get("mid"), str) or not _MID.fullmatch(claims["mid"]):
        return "claim mid is not 32 lowercase hex characters"
    iat = claims.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return "claim iat missing or not an integer"
    return None


def _check_content(claims: Mapping[str, Any], scan: DocumentScan) -> ContentCheck:
    canon = claims.get("canon")
    if not isinstance(canon, str) or canon not in MESSAGE_CANONICALISATIONS:
        return ContentCheck.UNSUPPORTED
    region = scan.regions.get(str(claims.get("mid", "")))
    if region is None:
        return ContentCheck.NOT_FOUND
    canonical = canonical_as(region.canonical, str(canon))
    if digest_of_canonical(canonical) == claims.get("content_sha256"):
        return ContentCheck.MATCH
    return ContentCheck.MISMATCH


def _legacy_finding(value: str, carrier: Carrier, placement: Placement) -> Finding:
    """The pre-signing JSON marker: still a disclosure, never verifiable."""
    try:
        claims = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        claims, error = {}, f"malformed legacy marker: {exc}"
    else:
        error = None if isinstance(claims, dict) else "malformed legacy marker"
        claims = claims if isinstance(claims, dict) else {}
    return Finding(
        carrier=carrier,
        placement=placement,
        signature=SignatureStatus.UNSIGNED,
        content=ContentCheck.NOT_FOUND,
        claims=claims,
        legacy=True,
        error=error,
    )
