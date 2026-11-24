# Generated from the reference implementation. Do not edit by hand:
# changes are made there and regenerated.
"""Constants of the disclosure marker format that a verifier needs."""

from __future__ import annotations

SPEC = "complexio-ai-disclosure/1"

TOKEN_TYPE = "ai-disclosure+jwt"

# Boolean flag for filters and gateways; unsigned, so informative only.
AI_GENERATED_HEADER = "X-AI-Generated"

# The compact JWS, the same token the in-body marker carries.
DISCLOSURE_HEADER = "X-Complexio-AI-Disclosure"
