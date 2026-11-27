"""The ``ai-disclosure-verify`` command.

``ai-disclosure-verify FILE [--jwks JWKS | --offline] [--timeout SECONDS] [--json]``
reads an ``.eml`` message, an HTML body, an Office file or a PDF and reports,
in plain language or as JSON, every marker it carries and what its verdict
means.

Exit status: 0 when the message's own marker verifies and covers all its
text, 4 when it verifies but the message carries markup outside the allowlist,
or anything outside its content, that it does not vouch for (always so for a
PDF), 1 when no marker is present, 2 when the input or key set cannot be read
(nested too deeply included) or the HTML is unparseable, 3 when a marker is
present but not verified (unsigned, bad or unknown signature, altered or
displaced content, or only quoted copies).

Without ``--jwks`` the key set is fetched from ``keys.DEFAULT_JWKS_URL``,
only if a signed marker needs it; ``--timeout`` sets how long to wait for it.
``--offline`` loads no key set, so signed markers read as not checked.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ai_disclosure_verify.detect import Verdict, detect_file
from ai_disclosure_verify.keys import (
    DEFAULT_JWKS_URL,
    FETCH_TIMEOUT_SECONDS,
    MAX_FETCH_TIMEOUT_SECONDS,
    LazyKeys,
    fetch_jwks,
    load_jwks_file,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXIT_VERIFIED = 0
EXIT_NO_MARKER = 1
EXIT_ERROR = 2
EXIT_UNVERIFIED = 3
EXIT_VERIFIED_WITH_UNMARKED_CONTENT = 4


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the exit status."""
    parser = argparse.ArgumentParser(
        prog="ai-disclosure-verify",
        description="Detect and verify the AI-disclosure marker in a message.",
        epilog=(
            "Exit status: 0 verified; 1 no marker; 2 unreadable input or key set, "
            "or unparseable HTML; 3 marked but not verified or only quoted "
            "copies; 4 verified with unmarked content or markup."
        ),
    )
    parser.add_argument(
        "file", type=Path, help=".eml message, HTML body, Office file or PDF"
    )
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument(
        "--jwks",
        type=Path,
        help=f"read the key set from this file instead of fetching {DEFAULT_JWKS_URL}",
    )
    keys.add_argument(
        "--offline",
        action="store_true",
        help="load no key set: signed markers read as not checked",
    )
    parser.add_argument(
        "--timeout",
        type=_timeout,
        default=FETCH_TIMEOUT_SECONDS,
        help=(
            "seconds to wait for the key set, at most "
            f"{MAX_FETCH_TIMEOUT_SECONDS:g} (default: %(default)s)"
        ),
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    try:
        return _verify(args.file, args.jwks, args.timeout, args.offline, args.json)
    except (OSError, ValueError, LookupError) as exc:
        # Exit 1 means "read the message, found no marker"; a failure to read
        # must not look like that.
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_ERROR
    except RecursionError:
        sys.stderr.write("error: the input is nested too deeply to read\n")
        return EXIT_ERROR


def _timeout(text: str) -> float:
    try:
        seconds = float(text)
    except ValueError:
        seconds = math.nan
    if not 0 < seconds <= MAX_FETCH_TIMEOUT_SECONDS:
        msg = f"must be more than 0 and at most {MAX_FETCH_TIMEOUT_SECONDS:g}"
        msg += f", not {text}"
        raise argparse.ArgumentTypeError(msg)
    return seconds


def _verify(
    file: Path, jwks_file: Path | None, timeout: float, offline: bool, as_json: bool
) -> int:
    data = file.read_bytes()
    keys: Mapping[str, Ed25519PublicKey] | None
    if jwks_file is not None:
        keys = load_jwks_file(jwks_file)
    elif offline:
        keys = None
    else:
        keys = LazyKeys(lambda: fetch_jwks(timeout=timeout))
    report = detect_file(data, keys)
    if as_json:
        # ASCII only: a control character or bidirectional override in a
        # claim reaches the terminal escaped.
        output = json.dumps(report.to_dict(), indent=2, ensure_ascii=True)
    else:
        output = report.describe()
    sys.stdout.write(output + "\n")
    if report.verdict is Verdict.VERIFIED:
        return EXIT_VERIFIED
    if report.verdict is Verdict.VERIFIED_WITH_UNMARKED_CONTENT:
        return EXIT_VERIFIED_WITH_UNMARKED_CONTENT
    if report.verdict is Verdict.NONE:
        return EXIT_NO_MARKER
    if report.verdict is Verdict.UNPARSEABLE:
        sys.stderr.write(f"error: {report.unparseable}\n")
        return EXIT_ERROR
    return EXIT_UNVERIFIED
