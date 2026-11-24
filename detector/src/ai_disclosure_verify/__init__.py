"""Verify the AI-disclosure marker in an email.

Detection and verification only: nothing here issues or signs a marker. The
format is specified in ``SPEC.md``; the command is ``ai-disclosure-verify``.
"""

from ai_disclosure_verify.canonical import (
    CONTENT_ATTR,
    MARKER_ATTR,
    UnparseableHtmlError,
)
from ai_disclosure_verify.constants import (
    AI_GENERATED_HEADER,
    DISCLOSURE_HEADER,
    SPEC,
    TOKEN_TYPE,
)
from ai_disclosure_verify.detect import (
    Carrier,
    ContentCheck,
    DetectionReport,
    DisallowedMarkup,
    Finding,
    MessageDecodeError,
    Placement,
    Verdict,
    detect_file,
    detect_html,
    detect_message,
)
from ai_disclosure_verify.jws import JwksError, SignatureStatus, keys_from_jwks

__all__ = [
    "AI_GENERATED_HEADER",
    "CONTENT_ATTR",
    "DISCLOSURE_HEADER",
    "MARKER_ATTR",
    "SPEC",
    "TOKEN_TYPE",
    "Carrier",
    "ContentCheck",
    "DetectionReport",
    "DisallowedMarkup",
    "Finding",
    "JwksError",
    "MessageDecodeError",
    "Placement",
    "SignatureStatus",
    "UnparseableHtmlError",
    "Verdict",
    "detect_file",
    "detect_html",
    "detect_message",
    "keys_from_jwks",
]
