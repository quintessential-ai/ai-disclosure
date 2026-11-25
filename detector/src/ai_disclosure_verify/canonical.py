# Generated from the reference implementation. Do not edit by hand:
# changes are made there and regenerated.
"""Canonical content and the markup allowlist (``text-links/2``).

The digest binds a marker to what a recipient reads and what the message
links to or loads, not to the markup carrying it: mail servers and clients
rewrite HTML, re-wrap lines and swap spaces for ``&nbsp;``. Text keeps its
characters but loses its whitespace; each link and image URL keeps its
characters and enters the stream where its element starts.

What may carry that content is a fixed allowlist of elements, attributes and
URL schemes. Anything else (CSS, comments, foreign content, forms, embedded
documents, content the parser moved out of a table) is a violation. The
detector reports violations rather than predicting how a client would render
them, so "verified" means the content container holds only allowlisted
markup, whose text and links are what was signed. The issuer signs content as
written: it only closes what each part leaves open, so a
violation in the content reads as such, never as "verified".

Both sides read html5lib's HTML5 parse of a whole document, and the issuer
digests the exact string it sends. The rule is specified in
``SPEC.md``; keep the two in step.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qsl
from xml.etree import ElementTree

import html5lib
from html5lib._tokenizer import HTMLTokenizer

from ai_disclosure_verify.jws import b64url_encode

if TYPE_CHECKING:
    from collections.abc import Mapping
    from xml.etree.ElementTree import Element

# The canonicalisation the issuer signs messages under. A detector also
# accepts text-links/1, which keeps each URL as written; text-links/2 writes
# each http and https URL in its WHATWG serialisation (``serialise_url``).
CANONICALISATION = "text-links/2"
CANONICALISATION_V1 = "text-links/1"
MESSAGE_CANONICALISATIONS = frozenset({CANONICALISATION_V1, CANONICALISATION})

CONTENT_ATTR = "data-ai-content"
MARKER_ATTR = "data-ai-disclosure"
MARKER_STYLE = "display:none"

type ContentFormat = Literal["html", "text"]

URL_OPEN = "\x1e"
ATTRIBUTE_TEXT_OPEN = "\x1d"
ITEM_CLOSE = "\x1f"

# Larger documents, deeper nesting or more attributes on one tag are refused
# before or during parsing: html5lib's cost grows with the square of the
# nesting depth and of the attributes on one tag.
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 256
MAX_ATTRIBUTES = 64
# Bounds html5lib's parse time: each element costs up to a scan of the open
# elements, so a document of nothing but tags runs to tens of seconds at the
# byte cap. Mail with a large table stays well under it.
MAX_ELEMENTS = 200_000

# Not ``s``, ``del``, ``ins``, ``sub`` or ``sup``: each changes what the text
# says ("We <s>approve</s>", "10<sup>6</sup>") without changing the digest.
ALLOWED_ELEMENTS = frozenset(
    {
        *("p", "br", "div", "span", "a", "b", "strong", "i", "em", "u"),
        *("small", "blockquote", "pre", "code", "hr"),
        *("h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li"),
        *("table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "img"),
    }
)
# The parser's document scaffolding; ``title`` and ``meta`` only inside ``head``.
SCAFFOLDING = frozenset({"html", "head", "body"})
HEAD_ELEMENTS = frozenset({"title", "meta"})

# ``dir`` is not global: on a span it isolates digit groups, and reverses
# their order ("2000 3000" shows as "3000 2000") without adding a glyph.
GLOBAL_ATTRIBUTES = frozenset({"lang"})
ELEMENT_ATTRIBUTES: dict[str, frozenset[str]] = {
    "html": frozenset({"dir"}),
    "body": frozenset({"dir"}),
    "a": frozenset({"href", "title"}),
    "img": frozenset({"src", "alt"}),
    "table": frozenset({"border", "cellpadding", "cellspacing", "width"}),
    "td": frozenset({"colspan", "rowspan", "align", "valign", "width"}),
    "th": frozenset({"colspan", "rowspan", "align", "valign", "width"}),
    # A charset declaration only: Exchange adds one to every HTML body.
    "meta": frozenset({"charset", "http-equiv", "content"}),
}
# Outlook's Safe Links attributes: dropped, never a violation.
IGNORED_ATTRIBUTES: dict[str, frozenset[str]] = {
    "a": frozenset({"originalsrc", "shash"}),
}
URL_SCHEMES: dict[tuple[str, str], frozenset[str]] = {
    ("a", "href"): frozenset({"http", "https", "mailto", "tel"}),
    ("img", "src"): frozenset({"https"}),
}
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):")

# Elements whose content a browser never renders as text. Matched by local
# name in any namespace. Each is also a violation; this only decides what
# counts as text before or outside a container.
NON_RENDERED = frozenset(
    {"script", "style", "template", "title", "iframe", "noembed", "noframes"}
)

# Spelled out rather than ``\s`` so every implementation removes the same
# set: Python's and JavaScript's ``\s`` differ (U+001C-U+001F, U+FEFF).
_TEXT_WHITESPACE = re.compile(
    r"[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200d\u2028\u2029\u202f\u205f\u2060\u3000\ufeff]"
)
_ASCII_WHITESPACE = frozenset("\t\n\f\r ")
_CONTROLS = re.compile(r"[\x00-\x1f\x7f]")
# WHATWG URL preprocessing: trim C0 controls and spaces, drop tab and newline.
_URL_EDGES = "".join(chr(c) for c in range(0x21))
_URL_TAB_OR_NEWLINE = re.compile(r"[\t\n\r]")

# Microsoft Defender Safe Links rewrites links on delivery into this host,
# carrying the original target in the ``url`` query parameter. Only a host
# that a WHATWG parser would also read as exactly this is unwrapped.
_SAFELINKS_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.safelinks\.protection\.outlook\.com"
)

_DOCUMENT_ROOT = "DOCUMENT_ROOT"
_DOCTYPE = "<!DOCTYPE>"
_COMMENT: Any = ElementTree.Comment


class UnparseableHtmlError(ValueError):
    """The document is too large or too deep, or the HTML parser failed on it."""


_EtreeBuilder: Any = html5lib.getTreeBuilder("etree", fullTree=True)


class _TreeBuilder(_EtreeBuilder):
    """html5lib's etree builder, recording foster parenting, capping depth and size.

    Every foster-parenting insertion goes through
    ``getTableMisnestedNodePosition``; the table it moves content in front of
    is recorded, so the walk can place the violation.
    """

    max_depth = MAX_DEPTH
    max_elements = MAX_ELEMENTS
    max_bytes = MAX_DOCUMENT_BYTES

    def reset(self) -> None:
        super().reset()
        self.fostered: list[Element] = []
        self.inserted = 0

    def insertElementNormal(self, token: Any) -> Any:
        self._check_depth()
        return super().insertElementNormal(token)

    def insertElementTable(self, token: Any) -> Any:
        self._check_depth()
        return super().insertElementTable(token)

    def getTableMisnestedNodePosition(self) -> Any:
        parent, insert_before = super().getTableMisnestedNodePosition()
        anchor = insert_before if insert_before is not None else parent
        self.fostered.append(anchor._element)
        return parent, insert_before

    def _check_depth(self) -> None:
        if len(self.openElements) >= self.max_depth:
            msg = f"elements nested more than {self.max_depth} deep"
            raise UnparseableHtmlError(msg)
        self.inserted += 1
        if self.inserted > self.max_elements:
            msg = f"more than {self.max_elements} elements"
            raise UnparseableHtmlError(msg)


class _Tokenizer(HTMLTokenizer):
    """html5lib's tokenizer, capping the attributes on one tag.

    html5lib checks each new attribute against every earlier one on the tag,
    so the cost of one tag grows with the square of its attribute count.
    """

    def beforeAttributeNameState(self) -> bool:
        result = super().beforeAttributeNameState()
        self._check_attributes()
        return result

    def afterAttributeNameState(self) -> bool:
        result = super().afterAttributeNameState()
        self._check_attributes()
        return result

    def _check_attributes(self) -> None:
        token = self.currentToken
        data = token.get("data") if token is not None else None
        if isinstance(data, list) and len(data) > MAX_ATTRIBUTES:
            msg = f"a tag carries more than {MAX_ATTRIBUTES} attributes"
            raise UnparseableHtmlError(msg)


class _Parser(html5lib.HTMLParser):
    def reset(self) -> None:
        # ``_parse`` creates the tokenizer and calls ``reset`` straight after,
        # before reading any input: the one point to swap in the capped one.
        self.tokenizer.__class__ = _Tokenizer
        super().reset()


def _parse_document(
    document: str, builder: type[_TreeBuilder]
) -> tuple[Element, list[Element]]:
    """Parse ``document`` within the caps.

    Raises:
        UnparseableHtmlError: Larger, more deeply nested or with more
            elements than the builder allows, over ``MAX_ATTRIBUTES`` on one
            tag, or html5lib failed on it.

    """
    max_bytes = builder.max_bytes
    if len(document) > max_bytes or (
        len(document) * 4 > max_bytes
        and len(document.encode("utf-8", errors="surrogatepass")) > max_bytes
    ):
        msg = f"the HTML is larger than {max_bytes} bytes"
        raise UnparseableHtmlError(msg)
    parser = _Parser(tree=builder, namespaceHTMLElements=False)
    try:
        root = parser.parse(document)
    except UnparseableHtmlError:
        raise
    except Exception as exc:
        # html5lib asserts on some inputs; any failure reads as unparseable.
        msg = f"the HTML parser failed: {type(exc).__name__}"
        raise UnparseableHtmlError(msg) from exc
    return root, parser.tree.fostered


def attribute_allowed(tag: str, name: str, value: str) -> bool:
    """True when the allowlist lets ``tag`` carry ``name="value"`` (HTML namespace)."""
    if name not in GLOBAL_ATTRIBUTES and name not in ELEMENT_ATTRIBUTES.get(tag, ()):
        return False
    schemes = URL_SCHEMES.get((tag, name))
    if schemes is not None:
        return _scheme_allowed(value, schemes)
    if tag == "meta" and name == "http-equiv":
        return value.strip().lower() == "content-type"
    # On the root or the body, a direction applies to the whole message.
    if tag in ("html", "body") and name == "dir":
        return value.strip().lower() == "ltr"
    return True


def _scheme_allowed(value: str, schemes: frozenset[str]) -> bool:
    """The URL, and a Safe Links target it wraps, has a scheme in ``schemes``."""
    url = _preprocess_url(value)
    match = _SCHEME.match(url)
    if match is None or match.group(1).lower() not in schemes:
        return False
    target = _safelinks_target(url)
    if target is None:
        return True
    match = _SCHEME.match(_preprocess_url(target))
    return match is not None and match.group(1).lower() in schemes


def _attribute_items(tag: str, attributes: Mapping[str, str]) -> list[tuple[str, str]]:
    """The URL and attribute-text items ``tag`` contributes, in stream order."""
    names = _ITEM_ATTRIBUTES.get(tag)
    if names is None:
        return []
    url_name, text_name = names
    found: list[tuple[str, str]] = []
    url = normalise_url(attributes.get(url_name) or "")
    if url:
        found.append(("url", url))
    text = attributes.get(text_name)
    if text is not None and _finish_text([text]):
        found.append(("attribute", text))
    return found


# The URL attribute, then the attribute text, an element contributes.
_ITEM_ATTRIBUTES: dict[str, tuple[str, str]] = {
    "a": ("href", "title"),
    "img": ("src", "alt"),
}


def digest_of_canonical(canonical: str) -> str:
    """Digest of content already in canonical form."""
    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def normalise_url(value: str) -> str:
    """A URL attribute value as it enters the stream (without the delimiters).

    A URL is trimmed of C0 controls and spaces and loses tabs and newlines,
    as WHATWG URL parsing does; a strictly valid Safe Links wrapper is
    replaced by its target. Remaining controls are percent-encoded. No case
    folding.
    """
    url = _preprocess_url(value)
    target = _safelinks_target(url)
    if target is not None:
        url = _preprocess_url(target)
    return _CONTROLS.sub(lambda m: f"%{ord(m.group()):02X}", url)


# ---------------------------------------------------------------------------
# text-links/2: URL serialisation
# ---------------------------------------------------------------------------

_URL_ITEM = re.compile(
    f"{URL_OPEN}([^{ATTRIBUTE_TEXT_OPEN}{URL_OPEN}{ITEM_CLOSE}]*){ITEM_CLOSE}"
)


def canonical_as(canonical: str, canon: str) -> str:
    """The text-links/1 form ``canonical`` rewritten as ``canon`` reads it.

    The two differ only in URL items, which the stream delimits
    unambiguously, so text-links/2 rewrites each one through ``serialise_url``.
    """
    if canon == CANONICALISATION_V1:
        return canonical
    if canon != CANONICALISATION:
        msg = f"unsupported canonicalisation {canon!r}"
        raise ValueError(msg)
    return _URL_ITEM.sub(
        lambda m: f"{URL_OPEN}{serialise_url(m.group(1))}{ITEM_CLOSE}", canonical
    )


# WHATWG percent-encode sets, minus the C0 control set (code points below
# U+0020 or above U+007E), which ``_percent_encode`` always applies.
_FRAGMENT_SET = frozenset(' "<>`')
_QUERY_SET = frozenset(' "#<>')
_SPECIAL_QUERY_SET = _QUERY_SET | {"'"}
_PATH_SET = _QUERY_SET | frozenset("?^`{}")
_USERINFO_SET = _PATH_SET | frozenset("/:;=@[\\]^|")

_DEFAULT_PORTS = {"http": 80, "https": 443}
_SPECIAL_AUTHORITY = re.compile(
    r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(.*)\Z", re.DOTALL
)
_HOST_LABEL = re.compile(r"[a-z0-9-]+\Z")
_NUMERIC_LABEL = re.compile(r"[0-9]+\Z|0[xX][0-9A-Fa-f]*\Z")
_SINGLE_DOT = frozenset({".", "%2e"})
_DOUBLE_DOT = frozenset({"..", ".%2e", "%2e.", "%2e%2e"})


def serialise_url(url: str) -> str:
    """The URL item ``url`` as text-links/2 writes it.

    An http or https URL is written as the WHATWG URL Standard serialises
    it, for the URLs this handles: scheme and ASCII host in lower case, the
    default or an empty port dropped, dot segments removed from the path, and
    userinfo, path, query and fragment percent-encoded with WHATWG's sets
    (UTF-8; an existing ``%XX`` is kept, so nothing is encoded twice). Any
    other URL is kept as written: another scheme, a backslash anywhere, a
    host that is empty, percent-encoded, non-ASCII, punycode (``xn--``), an
    IP address or ends in a number, or holds anything but ASCII letters,
    digits, hyphens and dots, and anything WHATWG would refuse to parse.
    """
    return _serialise_http_url(url) or url


def _serialise_http_url(url: str) -> str | None:
    """WHATWG's serialisation of an http(s) URL this handles, else None."""
    match = _SPECIAL_AUTHORITY.match(url)
    if match is None or "\\" in url:
        return None
    scheme = match.group(1).lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    authority, rest = match.group(2), match.group(3)
    userinfo, at, host_port = authority.rpartition("@")
    host, colon, port_text = host_port.partition(":")
    # ASCII before lower case: str.lower maps some non-ASCII letters to ASCII
    # ones (KELVIN SIGN to "k"), and a non-ASCII host is kept as written.
    if not host or not host.isascii():
        return None
    host = host.lower()
    if not _host_handled(host):
        return None
    port = ""
    if colon and port_text:
        if not port_text.isascii() or not port_text.isdigit():
            return None
        # WHATWG allows any number of leading zeros; past them, more than five
        # digits is out of range, and int() refuses a very long digit string.
        digits = port_text.lstrip("0") or "0"
        if len(digits) > 5 or int(digits) > 65535:
            return None
        if int(digits) != _DEFAULT_PORTS[scheme]:
            port = f":{int(digits)}"
    rest, hash_sign, fragment = rest.partition("#")
    path, question, query = rest.partition("?")
    try:
        credentials = ""
        if at:
            user, _, password = userinfo.partition(":")
            user = _percent_encode(user, _USERINFO_SET)
            password = _percent_encode(password, _USERINFO_SET)
            if user or password:
                credentials = f"{user}:{password}@" if password else f"{user}@"
        serialised = (
            f"{scheme}://{credentials}{host}{port}{_serialise_path(path)}"
            + (f"?{_percent_encode(query, _SPECIAL_QUERY_SET)}" if question else "")
            + (f"#{_percent_encode(fragment, _FRAGMENT_SET)}" if hash_sign else "")
        )
    except UnicodeEncodeError:  # a lone surrogate has no UTF-8 form
        return None
    return serialised


def _host_handled(host: str) -> bool:
    """A lower-case ASCII domain WHATWG keeps as it is, else False."""
    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels = labels[:-1]
    if _NUMERIC_LABEL.match(labels[-1]):
        return False  # an IPv4 address, or one WHATWG refuses
    return all(
        _HOST_LABEL.match(label) and not label.startswith("xn--") for label in labels
    )


def _serialise_path(path: str) -> str:
    """WHATWG's path of a special URL: dot segments resolved, percent-encoded."""
    segments = path[1:].split("/") if path else [""]
    out: list[str] = []
    for index, raw in enumerate(segments):
        segment = _percent_encode(raw, _PATH_SET)
        last = index == len(segments) - 1
        if segment.lower() in _DOUBLE_DOT:
            if out:
                out.pop()
            if last:
                out.append("")
        elif segment.lower() in _SINGLE_DOT:
            if last:
                out.append("")
        else:
            out.append(segment)
    return "/" + "/".join(out)


def _percent_encode(text: str, extra: frozenset[str]) -> str:
    """``text`` with the C0 control set and ``extra`` percent-encoded as UTF-8."""
    return "".join(
        "".join(f"%{byte:02X}" for byte in char.encode("utf-8"))
        if not " " < char < "\x7f" or char in extra
        else char
        for char in text
    )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


@dataclass
class ContentRegion:
    """A ``data-ai-content`` container found in a document."""

    mid: str
    text_before: bool
    in_blockquote: bool
    nested: bool
    items: list[tuple[str, str]] = field(default_factory=list)

    @property
    def leads(self) -> bool:
        """True when the region opens the document: nothing before it, not quoted, not nested."""
        return not (self.text_before or self.in_blockquote or self.nested)

    @property
    def canonical(self) -> str:
        """The region's content in canonical form."""
        return _canonical(self.items)


@dataclass(frozen=True)
class BodyMarker:
    """A ``data-ai-disclosure`` attribute value found in a document."""

    value: str
    order: int


@dataclass(frozen=True)
class Violation:
    """Markup outside the allowlist, and the content containers it sits in.

    ``name`` is an element (``style``), an element's attribute
    (``p[style]``), or one of ``#comment``, ``#foster-parented``,
    ``#text-in-head`` and ``#content-not-in-body``.
    """

    name: str
    containers: tuple[str, ...]

    def located(self, mid: str | None) -> str:
        """``inside:NAME`` when it sits in the container for ``mid``, else ``outside:NAME``."""
        where = "inside" if mid is not None and mid in self.containers else "outside"
        return f"{where}:{self.name}"


@dataclass
class DocumentScan:
    """What a parsed document carries: regions, markers, items, violations, elements."""

    regions: dict[str, ContentRegion]
    markers: list[BodyMarker]
    items: list[tuple[str, str]]
    violations: list[Violation]
    # Content elements, and text, URL and attribute-text items that are not
    # blank, by the mid of the outermost container they sit in (None: in
    # none). Scaffolding and the marker block are not counted. Counting,
    # rather than comparing canonical lengths, keeps a combining mark after a
    # container from composing into its last character unseen.
    elements: dict[str | None, int]
    content_items: dict[str | None, int]

    def has_content_outside(self, region: ContentRegion) -> bool:
        """True when the document has text, URLs or elements the region does not hold.

        Any element counts, even one with no text or URL: an empty list item
        numbers itself, a run of line breaks pushes the content off screen.
        """
        return any(
            count
            for counts in (self.elements, self.content_items)
            for mid, count in counts.items()
            if mid != region.mid
        )


def scan_html(document: str) -> DocumentScan:
    """Parse ``document`` as HTML5 and walk the whole tree once.

    Raises:
        UnparseableHtmlError: The document is over one of the caps
            (``MAX_DOCUMENT_BYTES``, ``MAX_DEPTH``, ``MAX_ATTRIBUTES``,
            ``MAX_ELEMENTS``), or the parser or the walk failed on it.

    """
    root, fostered = _parse_document(document, _TreeBuilder)
    return _scan(root, fostered)


def _scan(root: Element, fostered: list[Element]) -> DocumentScan:
    walker = _Walker(fostered)
    try:
        walker.walk(root)
    except UnparseableHtmlError:
        raise
    except Exception as exc:
        # Any failure of the walk reads as unparseable, never as a verdict.
        msg = f"the HTML walk failed: {type(exc).__name__}"
        raise UnparseableHtmlError(msg) from exc
    return DocumentScan(
        regions=walker.regions,
        markers=walker.markers,
        items=walker.items,
        violations=walker.violations,
        elements=walker.elements,
        content_items=walker.content_items,
    )


def _canonical(items: list[tuple[str, str]]) -> str:
    """Text runs NFC-normalised and stripped of whitespace; other items delimited."""
    parts: list[str] = []
    run: list[str] = []
    for kind, value in items:
        if kind == "text":
            run.append(value)
            continue
        parts.append(_finish_text(run))
        run = []
        if kind == "url":
            parts.append(f"{URL_OPEN}{value}{ITEM_CLOSE}")
        else:
            parts.append(f"{ATTRIBUTE_TEXT_OPEN}{_finish_text([value])}{ITEM_CLOSE}")
    parts.append(_finish_text(run))
    return "".join(parts)


def _finish_text(run: list[str]) -> str:
    text = _CONTROLS.sub("", "".join(run))
    return _TEXT_WHITESPACE.sub("", unicodedata.normalize("NFC", text))


def _preprocess_url(value: str) -> str:
    return _URL_TAB_OR_NEWLINE.sub("", value.strip(_URL_EDGES))


def _safelinks_target(url: str) -> str | None:
    """The ``url`` parameter of a strictly valid Safe Links URL, else None."""
    if url[:8].lower() != "https://":
        return None
    rest = url[8:]
    host_end = min((i for i in map(rest.find, "/?#") if i >= 0), default=len(rest))
    host = rest[:host_end]
    # The pattern admits no backslash, "@", ":", "%" or non-ASCII character,
    # so userinfo, ports, percent-encoding and IDNA tricks all fail it.
    if not host.isascii() or not _SAFELINKS_HOST.fullmatch(host.lower()):
        return None
    query = rest[host_end:].partition("#")[0].partition("?")[2]
    for name, value in parse_qsl(query, keep_blank_values=True):
        if name == "url":
            return value
    return None


def _is_blank(text: str) -> bool:
    return all(char in _ASCII_WHITESPACE for char in text)


@dataclass(frozen=True)
class _Context:
    """Where a node sits: its depth, its parent's tag, and what encloses it."""

    depth: int = 0
    parent: str = ""
    in_head: bool = False
    rendered: bool = True


class _Walker:
    """Pre-order walk of a parsed document: items, regions, markers and violations."""

    def __init__(self, fostered: list[Element]) -> None:
        self.regions: dict[str, ContentRegion] = {}
        self.markers: list[BodyMarker] = []
        self.items: list[tuple[str, str]] = []
        self.violations: list[Violation] = []
        self.elements: dict[str | None, int] = {}
        self.content_items: dict[str | None, int] = {}
        self._fostered: dict[int, int] = {}
        for anchor in fostered:
            self._fostered[id(anchor)] = self._fostered.get(id(anchor), 0) + 1
        self._open: list[tuple[ContentRegion, Element]] = []
        self._blockquotes: list[Element] = []
        self._seen_content = False

    def walk(self, root: Element) -> None:
        """Walk ``root``; iterative, so a deeply nested message cannot exhaust the stack."""
        stack: list[tuple[str, Element, _Context]] = [("node", root, _Context())]
        while stack:
            step, element, context = stack.pop()
            if step == "tail":
                if element.tail:
                    self._text(element.tail, context)
            elif step == "leave":
                self._leave(element)
            elif element.tag is _COMMENT:
                self._violation("#comment")
            elif isinstance(element.tag, str) and element.tag != _DOCTYPE:
                self._visit(element, context, stack)
        if self._fostered:
            # Every anchor is in the tree, so the walk visits it; an unvisited
            # one means the tree is not what the parser was assumed to build.
            msg = "content moved out of a table could not be placed"
            raise UnparseableHtmlError(msg)

    def _visit(
        self,
        element: Element,
        context: _Context,
        stack: list[tuple[str, Element, _Context]],
    ) -> None:
        if context.depth > MAX_DEPTH:
            msg = f"elements nested more than {MAX_DEPTH} deep"
            raise UnparseableHtmlError(msg)
        tag = element.tag
        local = tag.rpartition("}")[2]
        html_element = not tag.startswith("{")
        self._enter(element, local, context, html_element=html_element)
        if self._check(element, local, context, html_element=html_element):
            outermost = self._open[0][0].mid if self._open else None
            self.elements[outermost] = self.elements.get(outermost, 0) + 1
        for _ in range(self._fostered.pop(id(element), 0)):
            self._violation("#foster-parented")
        if html_element and context.rendered:
            self._emit_attributes(element, local)
        stack.append(("leave", element, context))
        inner = _Context(
            depth=context.depth + 1,
            parent=local if html_element else tag,
            in_head=context.in_head or (html_element and local == "head"),
            rendered=context.rendered and local not in NON_RENDERED,
        )
        if element.text:
            self._text(element.text, inner)
        for child in reversed(list(element)):
            stack.append(("tail", child, inner))
            stack.append(("node", child, inner))

    def _emit_attributes(self, element: Element, local: str) -> None:
        for kind, value in _attribute_items(local, element.attrib):
            self._emit(kind, value)

    def _check(
        self, element: Element, local: str, context: _Context, *, html_element: bool
    ) -> bool:
        """Record the element's violations; True when it counts as content.

        Only the scaffolding, ``title`` and ``meta`` in ``head``, and the
        marker block as issued are not content.
        """
        if not html_element:
            self._violation(local)
            return True
        if local == _DOCUMENT_ROOT:
            return False
        content = local not in SCAFFOLDING
        if local in HEAD_ELEMENTS:
            content = context.parent != "head"
            if content:
                self._violation(local)
        elif content and (local not in ALLOWED_ELEMENTS or context.in_head):
            self._violation(local)
        attributes = element.attrib
        if MARKER_ATTR in attributes:
            if self._is_marker_block(element, attributes):
                return False
            self._violation(f"{local}[{MARKER_ATTR}]")
            return True
        container = CONTENT_ATTR in attributes
        # A container is valid only as the region it opened, and not nested
        # in another: a duplicate mid or a nested one is a violation.
        opened = len(self._open) == 1 and self._open[0][1] is element
        if container and not opened:
            self._violation(f"{local}[{CONTENT_ATTR}]")
        ignored = IGNORED_ATTRIBUTES.get(local, frozenset())
        for name, value in attributes.items():
            if name == CONTENT_ATTR or name in ignored:
                continue
            if container or not attribute_allowed(local, name, value):
                self._violation(f"{local}[{name}]")
        return content

    def _is_marker_block(self, element: Element, attributes: dict[str, str]) -> bool:
        """The hidden block exactly as issued: outside any container and empty."""
        return (
            element.tag == "div"
            and attributes.keys() == {MARKER_ATTR, "style", "aria-hidden"}
            and attributes["style"] == MARKER_STYLE
            and attributes["aria-hidden"] == "true"
            and not self._open
            and not element.text
            and len(element) == 0
        )

    def _enter(
        self, element: Element, local: str, context: _Context, *, html_element: bool
    ) -> None:
        marker = element.get(MARKER_ATTR)
        if marker:
            self.markers.append(BodyMarker(value=marker, order=len(self.markers)))
        if not html_element:
            return
        if local == "blockquote":
            self._blockquotes.append(element)
        mid = element.get(CONTENT_ATTR)
        if local == "div" and mid and mid not in self.regions:
            # Anything wrapping the container (``<s>``, ``<div dir="rtl">``)
            # changes how it is shown without changing its text.
            if context.parent != "body":
                self._violation("#content-not-in-body")
            region = ContentRegion(
                mid=mid,
                text_before=self._seen_content,
                in_blockquote=bool(self._blockquotes),
                nested=bool(self._open),
            )
            self.regions[mid] = region
            self._open.append((region, element))

    def _leave(self, element: Element) -> None:
        if self._blockquotes and self._blockquotes[-1] is element:
            self._blockquotes.pop()
        if self._open and self._open[-1][1] is element:
            self._open.pop()

    def _violation(self, name: str) -> None:
        containers = tuple(region.mid for region, _ in self._open)
        self.violations.append(Violation(name=name, containers=containers))

    def _text(self, text: str, context: _Context) -> None:
        # Text under an element other than head or title is reported with
        # that element.
        if (
            context.in_head
            and context.parent in ("head", "title")
            and not _is_blank(text)
        ):
            self._violation("#text-in-head")
        if context.rendered:
            self._emit("text", text)

    def _emit(self, kind: str, value: str) -> None:
        self.items.append((kind, value))
        for region, _ in self._open:
            region.items.append((kind, value))
        if kind != "text" or _TEXT_WHITESPACE.sub("", _CONTROLS.sub("", value)):
            self._seen_content = True
            outermost = self._open[0][0].mid if self._open else None
            self.content_items[outermost] = self.content_items.get(outermost, 0) + 1
