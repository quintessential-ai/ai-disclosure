# Complexio AI disclosure marker, version 1

This specification describes how Complexio marks email written by its AI
system, Complexio Enterprise Automator, and files written by Complexio
Stevie, so that the marking is
machine-readable and anyone who receives the email can detect and verify it.
It is published so recipients, mail gateways and tooling can check the marker
without Complexio's software. A reference verifier and command-line
detector are described at the end.

Spec identifier: `complexio-ai-disclosure/1`.

## What is marked

An outbound email whose body the AI system wrote. The marker states that the
content is AI-generated, names the system, and names the entity on whose
behalf it was sent.

A human may review or edit the AI's text before the system sends it (for
example, an operator approving or amending a proposed email). Such a message
is still marked and signed as AI-generated: the system issues the marker over
the final text when it sends it, so the marker verifies.

A human may also take an AI-written draft and send it themselves after
editing it, for example in Outlook. The draft's header and hidden block go
out unchanged, but the text no longer matches the signed digest. A verifier
then reports the content as changed after signing, and the message as
marked but not verified. That is the expected result for an edited draft, not
a fault: the marker shows the message started as AI-generated content and that
someone changed it afterwards.

Each message also carries a visible footer saying the same in words. Once the
page that publishes this specification has its fixed address, the footer ends
with the line "How to check this label:" followed by that address as a visible
link. The footer is inside the content container, so the link is covered by
the digest: a changed link reads as content changed after signing. This
specification covers only the machine-readable marker.

Office (`.docx`, `.xlsx`, `.pptx`) and PDF files written by Complexio Stevie
carry the same token in their metadata; see [Files](#files).

## Carriers

One marker is issued per message. It travels in up to three places, all
bound together by the marker id (`mid`).

| Carrier | Form | Present on |
| --- | --- | --- |
| `X-Complexio-AI-Disclosure` header | The marker token (see [Token](#token)) | Messages Complexio creates directly (new messages and new drafts) |
| `X-AI-Generated` header | `true` | Same as above |
| Hidden body block | `<div data-ai-disclosure="TOKEN" style="display:none" aria-hidden="true"></div>` | Every HTML message, including replies |
| Content container | `<div data-ai-content="MID">…the AI-written content and the visible footer…</div>` | Every HTML message, including replies |

`X-AI-Generated` is unsigned. It is a convenience for filters and carries no
proof; verifiers should rely on the token.

The token in the header and the token in the hidden block are identical. The
content container opens the message and holds the AI-written text and the
visible disclosure footer; the hidden block follows it. In a reply, the
quoted conversation comes after the hidden block.

Before wrapping, the issuer balances the AI-written HTML and the footer
separately and joins them, so nothing left open in the AI's HTML (a comment,
`<style>` or `<textarea>`, a hidden element) can swallow or hide the footer.
It removes nothing: content is signed and sent as written, and only a
verifier applies the [markup allowlist](#markup-allowlist). The issuer parses
each part as a whole document and writes the tree back:

- the children of `body`, after the `style` and `link` elements of `head`
  and any comments around the document scaffolding (Outlook's conditional
  comments sit there), in document order. The attributes of `html` and
  `body`, and `title`, `meta`, `base` and `script` in `head`, are not
  carried;
- every element closed, and every comment and raw-text element (`style`,
  `script`, `textarea`, `title`, `xmp`) ended, so no part can move the end
  of the next part or of the container;
- `plaintext`, which cannot be closed, as `pre`, and a `script` whose text
  contains `<!--` without its text, since that text can stop its end tag
  from closing it;
- inside `noscript`, every `</noscript` in a comment or raw text written as
  `<\/noscript`: the issuer parses with scripting off, but a reader with
  scripting on takes `noscript` as raw text ending at the first `</noscript`.
  A `noscript` holding a foreign `noscript` (in `svg` or `math`), whose end
  tag would end it early, is sent as written.

Content the parser moved out of a table is written where the parser put it,
in front of the table. The footer is `<p><small><em>…</em></small></p>`, with
no styling. The issuer computes the digest from the wrapped container, read
as a verifier reads it, so the digest covers exactly what is sent.

The issuer's depth and element caps are 64 below a verifier's, its size cap
64 KiB below, and its copying and foster-parenting budgets half a
verifier's, so what it signs, with the hidden block and a sender's `html`
and `body` around it, always parses for a verifier. Content over the
issuer's caps in [Parsing](#parsing), content the parser fails on, and
content that, wrapped in the container and parsed again, does not write back
to exactly the bytes being sent (html5lib builds a few such trees, such as an
HTML `p` left inside `svg`, which breaks out when parsed again and can leave
an element open around the footer) is sent as written,
with an unsigned marker. The container then holds only the footer, and the
content follows the hidden block, so the footer shows above the content and
nothing the content leaves open can swallow the footer or the marker. Its
`html` and `body` start tags are written as text (`&lt;body …`), since a
parser merges their attributes, `hidden` or `style` among them, onto the
page's own `html` and `body`.

Because content is signed as written, AI-written markup outside the
allowlist (an inline style, a class, a head style sheet) sits inside the
signed container, and such a message reads at best
`verified_with_unmarked_content`. Only a message whose content is all
allowlisted markup reads `verified`.

The footer can still be hidden, and the issuer cannot prevent it without
rewriting the content:

- a style sheet in the content, or in the quoted conversation a reply draft
  puts after it, can restyle or hide the footer;
- renderers built on parse5 lose the footer and the hidden block on a few
  nestings of `template` inside `svg` that html5lib and browsers read
  correctly.

The issuer logs each message whose content carries a style sheet (`style` or
`link`), as `ai_disclosure_content_style_sheet` with the count, so how often
this can happen is measured.

## Token

The token is a compact JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515))
with a JSON payload. Each of its three parts is unpadded base64url in its one
canonical spelling: the unused low bits of the last character are zero. The
header and the payload are UTF-8 JSON objects
([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) with no member name
repeated in any object, no `NaN` or `Infinity`, and no array or object
nested more than 32 deep. A token that is not is malformed, and is never
verified.

### Protected header

| Member | Value |
| --- | --- |
| `alg` | `EdDSA` (Ed25519, [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037)), or `none` for an unsigned marker |
| `typ` | `ai-disclosure+jwt` |
| `kid` | Key id of the signing key; absent when `alg` is `none` |

A token whose header has any other member is invalid, whatever its
signature: `crit` and `b64` among them, and `jku`, `jwk`, `x5u` or `x5c`,
which could name a key outside the published set. So is a token whose `kid`
is not a string.

### Payload

| Claim | Type | Meaning |
| --- | --- | --- |
| `spec` | string | `complexio-ai-disclosure/1` |
| `ai_generated` | boolean | Always `true` |
| `generator` | string | The AI system: `Complexio Enterprise Automator`, or `Complexio Stevie` for files |
| `on_behalf_of` | string | The entity the message is sent on behalf of (the deploying organisation) |
| `iat` | integer | Issue time, seconds since the Unix epoch (UTC) |
| `mid` | string | Marker id: 32 lowercase hex characters, random per message |
| `canon` | string | Canonicalisation used for `content_sha256`: `text-links/2` for messages (a verifier also accepts `text-links/1`), `ooxml-parts/1` or `pdf-revision/1` for files |
| `content_sha256` | string | Unpadded base64url SHA-256 of the canonical content (below) |

Example payload:

```json
{
  "ai_generated": true,
  "canon": "text-links/2",
  "content_sha256": "HqtrRXPLKxZ03i6kBAueIa4X0NLwjEX93dU6OW9gkJU",
  "generator": "Complexio Enterprise Automator",
  "iat": 1794238106,
  "mid": "20b56aa04ec84500bf52f6e0c683d1f2",
  "on_behalf_of": "Example Shipping Ltd",
  "spec": "complexio-ai-disclosure/1"
}
```

### Unsigned markers

When a deployment has no signing key, the marker is still issued, with
`alg: none`, no `kid` and an empty signature part (`HEADER.PAYLOAD.`). It
states the same facts but proves nothing about its origin. A verifier reports
it as unsigned and never as verified. A token with `alg: none` and a
non-empty signature is invalid.

## Markup allowlist

The marker vouches for content held in a fixed set of elements, attributes
and URL schemes. Anything else in a message is a *violation*. A verifier
does not predict how a mail client would render such markup; it reports it.

**Elements** (HTML namespace): `p`, `br`, `div`, `span`, `a`, `b`, `strong`,
`i`, `em`, `u`, `small`, `blockquote`, `pre`, `code`,
`h1`–`h6`, `hr`, `ul`, `ol` (no `start` or `type`: a list counter can
spell words), `li`, `table`, `thead`, `tbody`, `tfoot`, `tr`,
`td`, `th`, `caption`, `img`. Not `s`, `del`, `ins`, `sub` or `sup`: each
changes what the text says (`We <s>approve</s>` reads as a refusal,
`10<sup>6</sup>` as a million) without changing the digest.

**Document scaffolding:** `html`, `head` and `body` as the parser builds
them. `title` and `meta` only as children of `head`. Any text in `head` or
in its `title`, other than ASCII whitespace, is a violation, and so is any
other element in `head`.

**Attributes.** Any attribute not listed is a violation, including `style`,
`class`, `id`, `hidden`, `srcset`, `srcdoc`, `background`, event handlers
(`on…`), `data-…` and `aria-…`:

| Element | Attributes |
| --- | --- |
| any | `lang` |
| `html`, `body` | `dir`, only with the value `ltr` (ASCII case-insensitive). Nowhere else: on a `span`, `dir` isolates digit groups and shows them in reverse order ("2000 3000" as "3000 2000") without adding a character |
| `a` | `href`, `title` |
| `img` | `src`, `alt` (no size: a zero size hides a signed image) |
| `table` | `border`, `cellpadding`, `cellspacing`, `width` |
| `td`, `th` | `colspan`, `rowspan`, `align`, `valign`, `width` |
| `meta` | `charset`, `content`, and `http-equiv` only with the value `content-type` (ASCII case-insensitive, trimmed) |

`originalsrc` and `shash` on `a` are ignored: never a violation, and not part
of the digest. They are taken from the attributes Outlook's Safe Links adds
to links; that is not confirmed on a received sample.

**URL schemes.** After the preprocessing in [URL items](#url-items) (trim
C0 controls and spaces; remove tab, LF and CR), a URL's scheme is the text
before the first `:`, when that text is an ASCII letter followed by ASCII
letters, digits, `+`, `-` or `.`. It is compared ASCII case-insensitively.
`a href` must be `http`, `https`, `mailto` or `tel`; `img src` must be
`https` (not `cid`: a Content-ID names an attachment, it does not bind its
bytes). A URL without a scheme (empty, relative, `//host`) is a
violation. When the URL is a strictly valid Safe Links URL, the target it
carries must pass the same check.

**Our own structure**, exactly:

- the content container is a `div` whose only attribute is
  `data-ai-content`, a child of `body` and not inside another container.
  Any other element carrying `data-ai-content`, a second container for the
  same `mid`, or a container with another element between it and `body` is
  a violation;
- the hidden block is a `div` with exactly three attributes:
  `data-ai-disclosure`, `style` with the exact string `display:none` (not
  parsed as CSS), and `aria-hidden="true"`. It is outside every container and
  has no content, and its `data-ai-disclosure` holds a compact JWS of at
  most 8,192 characters: three base64url parts, the first two decoding to
  JSON objects. Any other element carrying `data-ai-disclosure`, or a block
  in any other shape, a block holding any other value included, is a
  violation. A browser hides the block, but a program reading the markup
  sees its value, so only the block holding the original body marker (step
  6 of [Verifying a message](#verifying-a-message)) is the message's own,
  and not even that one when the header token verifies and the block's own
  token does not: copying a genuine header's `mid` into a block proves
  nothing. Every other block in this shape is content outside the original
  container (step 7).

**Also violations:** every comment, including Outlook's conditional
comments (`<!--[if mso]>…<![endif]-->` and `<!--[if !mso]><!-->…<!--<![endif]-->`),
and so CDATA sections and processing instructions, which an HTML parser reads
as comments; every element in the SVG or MathML namespace; and every text
node or element the parser moves out of a `table`, `tbody`, `thead`, `tfoot`
or `tr` (foster parenting). The reference implementation records each
foster-parenting step as the parser takes it and reports it at the table the
content was moved in front of.

A violation is *inside* when it sits within the original's content
container (the container's own extra attributes included), and *outside*
otherwise.

## Canonical content (`text-links/2`)

The digest covers what a recipient reads and what the message links to or
loads: the text, the target of every link and image, and the text of link
titles and image descriptions. It does not cover markup, so it survives the
rewriting mail servers and clients apply to HTML.

`text-links/2` and `text-links/1` differ only in how a URL item is written
(step 4 of [URL items](#url-items)). `text-links/1` keeps each URL as written,
so a link whose spaces a mail server re-encodes as `%20` no longer matches;
`text-links/2` writes http and https URLs in their WHATWG serialisation, which
such re-encoding does not change. Issuers sign `text-links/2`. A verifier
accepts both and reads each marker under the canonicalisation it names.

### Parsing

The document is parsed with the HTML5 parsing algorithm (WHATWG HTML, tree
construction, scripting disabled); the reference implementation uses
html5lib. All of what follows reads the resulting tree, never the markup as
written: a misplaced `<head>`, a stray closing tag or an unclosed element
counts where the parser put it.

Parsers differ from each other and from browsers on markup outside the
allowlist (foreign content, `template`, `select`, `isindex`). That markup is
a violation whichever way it parses, so the guarantee does not rest on
matching a browser: a `verified` marker means the content container holds
only allowlisted markup, and its text and links are what was signed.

A document is *unparseable* when the parser fails on it or it exceeds a cap:

- a UTF-8 encoding longer than 5 MiB (5,242,880 bytes);
- elements nested more than 256 deep, counting `html` and `body`;
- more than 64 attributes on one tag;
- more than 200,000 elements, counting each one the parser creates;
- content containers nested more than 4 deep, counting each `div` that
  opens a new `mid` inside another.

The caps bound parse time: html5lib's cost grows with the square of the
nesting depth and of the attributes on one tag, and each nested container
is digested on its own.

The reference implementation also refuses a document on which html5lib's
cost would grow with the square of the input. html5lib builds each text
node, attribute value, comment and name by appending to a string, and
places each piece of foster-parented content by scanning the foster
parent's children. The reference stops when, summed over the parse, the
length of the token being built at each tokenizer step and of the text
each insertion extends passes 2^31 characters, or the children scanned
placing foster-parented content pass 2^24. Mail stays far below both. They
bound this parser's cost, not the document, so another parser need not
apply them.

### Walk

Walk the tree in tree order (pre-order: an element, then its children in
order). Comments and the doctype contribute nothing.

- The content of a **non-rendered** element contributes nothing. These are,
  by local name in any namespace: `script`, `style`, `template`, `title`,
  `iframe`, `noembed`, `noframes`. Each is also a violation; the rule only
  decides what counts as text before or outside a container.
- A **text node** contributes its data, with character references decoded,
  as a text item.
- An HTML `a` element contributes, when it is visited and before its
  children, a URL item for its `href`, then an attribute-text item for its
  `title`. An HTML `img` element contributes a URL item for its `src`, then
  an attribute-text item for its `alt`. Where an attribute is repeated in the
  markup, the parser keeps the first value. No other attribute contributes.

### URL items

A URL value is normalised before it enters the stream:

1. trim leading and trailing code points U+0000–U+0020, and remove every
   U+0009, U+000A and U+000D, as WHATWG URL parsing does. Inner spaces are
   kept;
2. if it is a strictly valid Safe Links URL (below), replace it with the
   target it carries and apply step 1 to the target;
3. percent-encode each remaining U+0000–U+001F and U+007F as `%XX`
   (uppercase hex);
4. under `text-links/2` only, replace an http or https URL with its
   serialisation as given in [URL serialisation](#url-serialisation-text-links2).
   Under `text-links/1`, and for any URL that section keeps as written,
   nothing else changes: no case folding, no percent-decoding, no resolving
   against a base URL, no Unicode normalisation.

An empty value contributes nothing.

A **strictly valid Safe Links URL**:

- begins with `https://`, compared case-insensitively;
- its host is the text after `https://` up to the first `/`, `?` or `#`;
- that host consists of ASCII characters only (tested before lowercasing)
  and, lowercased, fully matches
  `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.safelinks\.protection\.outlook\.com`.

That pattern admits no `\`, `@`, `:`, `%` or non-ASCII character, so a
backslash, userinfo, a port, a percent-encoded host or an IDNA host all fail
it, and so does any host a WHATWG parser would read differently. The target
is the value of the first query parameter named exactly `url` in the query
(after the first `?`, before any `#`), decoded as
`application/x-www-form-urlencoded`. A wrapper that is not strictly valid
is not unwrapped: it stays the URL, and is then written as the
canonicalisation writes any URL.

### URL serialisation (`text-links/2`)

This is the WHATWG URL Standard's serialisation (the `href` its parser gives)
for the http and https URLs it covers, written out so a verifier needs no URL
library. A URL it does not cover is kept as it is after step 3.

The reference implementation is tested against the http and https entries
of web-platform-tests' URL test data (`url/resources/urltestdata.json` at
commit `065d99ab62bf0b6ca04907f423625801c350edb2`): every input it serialises
gives the entry's `href`, it serialises none the data marks as a failure, and
it keeps the rest as written. The Standard percent-encodes `^` in a path, but
not in a query or fragment; some URL libraries keep it in a path too
(Node.js 22's does; Node.js 25's encodes it).

A URL is **kept as written** when any of these holds:

- it does not match `([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)` in full, or
  its scheme, lowercased, is neither `http` nor `https` (so `mailto:`,
  `tel:`, `http:host` and `http:/host` are kept);
- it contains a `\` anywhere (WHATWG reads it as `/` in some places and not
  in others);
- its host (the authority after the last `@`, up to the first `:`) is empty,
  contains a non-ASCII character (test this before lowercasing: Unicode
  lowercases U+212A KELVIN SIGN to `k`), or, lowercased and without one
  trailing `.`, is not a sequence of `.`-separated labels each matching
  `[a-z0-9-]+`.
  This keeps percent-encoded hosts, IDNA and IPv6 hosts and empty labels;
- the last label is all ASCII digits or `0x` followed by hex digits (an IPv4
  address, which WHATWG rewrites, or a host it refuses), or any label begins
  with `xn--` (punycode, which WHATWG validates);
- the port (after that `:`) is not empty and is not all ASCII digits, or its
  value is larger than 65535 (leading zeros, however many, do not count);
- a code point in it has no UTF-8 encoding (a lone surrogate).

Otherwise it is written as:

1. the scheme, lowercased, then `://`;
2. if the authority contains `@`: the text before its last `@` is the
   userinfo; split it at its first `:` into username and password, and
   percent-encode both with the *userinfo set*. Write `username@`, or
   `username:password@` when the password is not empty; write nothing when
   both are empty;
3. the host, lowercased (a trailing `.` is kept);
4. the port, when it is not empty and its value differs from the scheme's
   default (80 for http, 443 for https), as `:` and its value in decimal
   without leading zeros;
5. the path: the text from the end of the authority up to the first `?` or
   `#`. Split it after its leading `/` (an empty path is one empty segment)
   at each `/`, percent-encode each segment with the *path set*, and resolve
   them in order: a segment that is `..`, `.%2e`, `%2e.` or `%2e%2e`
   (case-insensitively) removes the last kept segment, if any; one that is
   `.` or `%2e` is dropped; any other is kept. When the final segment is a
   dot segment, an empty segment is kept after it. Write `/` and the kept
   segments joined by `/`;
6. if there is a `?` before any `#`: `?` and the text up to the `#`,
   percent-encoded with the *query set*;
7. if there is a `#`: `#` and the rest, percent-encoded with the
   *fragment set*.

Percent-encoding with a set writes each code point that is below U+0021,
above U+007E, or in the set as the `%XX` (uppercase hex) of each byte of its
UTF-8 encoding, and every other code point as it is. An existing `%XX` is
not decoded, so nothing is encoded twice. The sets (WHATWG's for special
URLs):

- fragment set: space, `"`, `<`, `>`, `` ` ``;
- query set: space, `"`, `#`, `<`, `>`, `'`;
- path set: space, `"`, `#`, `<`, `>`, `?`, `^`, `` ` ``, `{`, `}`;
- userinfo set: the path set and `/`, `:`, `;`, `=`, `@`, `[`, `\`, `]`,
  `|`.

For example, `HTTPS://X.SharePoint.com/Shared Documents/Q3 report.pdf` is
written `https://x.sharepoint.com/Shared%20Documents/Q3%20report.pdf`, the
same as the `%20` form a mail server sends on.

### Canonical string

1. Split the item sequence into maximal runs of consecutive text items,
   separated by URL and attribute-text items.
2. For each text run, and for each attribute-text item on its own:
   concatenate, remove U+0000–U+001F and U+007F, normalise to Unicode NFC,
   then remove every occurrence of U+0009–U+000D, U+0020, U+0085, U+00A0,
   U+1680, U+2000–U+200D, U+2028, U+2029, U+202F, U+205F, U+2060, U+3000,
   U+FEFF. An attribute-text item that is then empty contributes nothing.
3. Write each URL item as U+001E, the normalised URL, U+001F, and each
   attribute-text item as U+001D, its normalised text, U+001F. Step 2 and
   the URL percent-encoding guarantee those three code points come only
   from these delimiters. URL items are not NFC-normalised and keep their
   whitespace.
4. Concatenate the runs and items in order.
5. `content_sha256` is the SHA-256 of the UTF-8 encoding, in unpadded
   base64url. A lone surrogate code point is replaced with U+FFFD before
   UTF-8 encoding, as the WHATWG Encoding Standard does.

The content's string is built from the walk of the content container's
subtree only.

**Plain text** (no HTML) is one text item: steps 2 and 5 apply. Its digest
equals the digest of an HTML rendering of the same words only when that HTML
carries no link or image. An issuer that turns text into HTML digests the
HTML it actually sends.

Re-wrapped lines, non-breaking spaces and leading or trailing whitespace in a
URL attribute leave the digest unchanged. A changed visible character, link
target, image source, link title or image description changes it.

## Verifying a message

1. Parse the HTML body (see [Parsing](#parsing)). An unparseable body ends
   verification: the verdict is `unparseable`. Otherwise collect the
   violations of the [markup allowlist](#markup-allowlist).
2. Collect tokens: the `X-Complexio-AI-Disclosure` header, if present, and
   every `data-ai-disclosure` attribute in the HTML body. An empty header or
   attribute is still a token, a malformed one: it is an attempt at a
   marker, so it never reads as `no_marker`.
3. For each token, decode the header and payload. Reject a token whose
   header is not as specified above (`typ` other than `ai-disclosure+jwt`,
   `crit` present, `alg` other than `EdDSA` or `none`), or whose payload is
   not a version-1 payload: `spec` other than `complexio-ai-disclosure/1`,
   `ai_generated` not `true`, a missing or wrongly typed claim, or a `mid`
   that is not 32 lowercase hex characters. A rejected token is never
   verified, whatever its signature. A malformed token (see [Token](#token))
   is rejected too, and names no container.
4. Check the signature: find the key whose `kid` matches in Complexio's
   published key set (below) and verify the Ed25519 signature over the JWS
   signing input. Outcomes: valid, invalid, unknown key, or unsigned.
5. Check the content: find the content container with the token's `mid`,
   compute its canonical digest under the token's `canon` (`text-links/2` or
   `text-links/1`; any other value is unsupported) and compare it with
   `content_sha256`. Outcomes: match; mismatch, meaning the content changed
   after signing (a person edited it, or a system in transit altered its
   text, links or images); unsupported; or not found (the container did not
   survive transport).
6. Decide which marker is the message's own, on the parsed tree. A content
   container *leads* the message when, walking the whole document (head
   included) as in [Walk](#walk), no URL item and no text item with a
   character outside the whitespace set comes before it, and it is neither
   inside a `blockquote` nor inside another content container.
   - The original is the first body marker whose container leads the
     message. With a header token, it must also have the header's `mid`.
   - When no container leads, the first body marker whose container is
     missing and whose hidden block itself leads the message, by the same
     test, is the original, with the same condition on the header's `mid`:
     its container was removed in transit, and its content result is "not
     found".
   - A header token whose container does not lead the message is not the
     message's own content: its content result is "not leading". A
     malformed header token is reported, rejected, and names no `mid`, so
     a body marker can still be the original and verify.
   - A malformed body token cannot be placed, like an
     [earlier-format marker](#earlier-marker-format).
   - Every other body marker is a quoted copy from earlier in the
     conversation.
7. Check coverage: does the walk outside the original container produce any
   URL item, any attribute-text item, or any text item with a character
   that step 2 of [Canonical string](#canonical-string) keeps, or does the
   message have any element outside the original container other than the
   scaffolding (`html`, `head`, `body`, and `title` or `meta` in `head`)
   and the hidden block in its issued shape that holds the original body
   marker? Then the message has content outside it, even without text: an
   empty list item numbers itself, a run of line breaks pushes the content
   off screen. That hidden block counts too when the header token verifies
   and the block's own token does not. A reply's quoted conversation is such
   content, and so is anything added around a copied fragment, in the head
   included.

   In an email, the HTML body is the part a MIME reader takes as the body
   when it prefers HTML (the reference implementation uses Python's
   `EmailMessage.get_body`). Every other leaf part a reader may see is also
   content outside the original container: any part that is not marked
   `Content-Disposition: attachment` and is not inside such a part, for
   example a second HTML part, an inline image, an inline forwarded message,
   or a `text/plain` part outside the HTML body's alternative. The one
   exception is the plain-text alternative to the HTML body: a `text/plain`
   part that is a direct child of a `multipart/alternative` part holding the
   HTML body, directly or inside another part (Outlook puts the HTML in a
   `multipart/related`). Most mail clients show the HTML, and Exchange adds
   a generated plain-text alternative to many messages, so a plain-text
   alternative to the HTML body is not checked: it may say something else
   (see [Transport limits](#transport-limits)). An attachment is a file of
   its own: the marker does not cover it, and it does not change the
   verdict.
8. Place each violation inside or outside the original container.

A signature vouches for the text of one container, not for the message
around it, and a signed fragment can be copied into another message.
Verdicts:

| Verdict | Meaning |
| --- | --- |
| `verified` | The original marker is valid, its digest matches, its container holds only allowlisted markup, and outside it the message holds nothing but empty scaffolding (`html`, `head`, `body`, an allowed `meta`, an empty `title`) and the hidden block. In an email, no other part a reader may see is present (step 7); a plain-text alternative to the HTML body is not checked. The words and links are the signed ones; the digest does not cover whitespace, presentation, or how much text a link spans (see [Transport limits](#transport-limits)). |
| `verified_with_unmarked_content` | The signed text is intact, but styling or markup in or around it, which could change how it is shown, is not vouched for, nor is the rest of the message. The original marker is valid and its digest matches, but its container holds a violation of the markup allowlist (styling, a class, a comment, an element outside the list), or the message has content outside its container (text, links, images or any other element, or another part of an email), or violations outside it (a quoted conversation, a head style sheet, a conditional comment, content added around a copied fragment). None of that may be attributed to the marker. A verified PDF always reads this way (see [Verifying a file](#verifying-a-file)). |
| `ai_marked_unverified` | The message carries its own marker but it does not verify: unsigned, bad or unknown signature, rejected token, content changed after signing (for example, a draft a person edited before sending), or missing or non-leading content, a leading hidden block whose container was removed included. Also returned, when no marker of the message's own verifies, for any `X-AI-Generated` header, whatever its value, and for an earlier-format marker or a malformed body token anywhere in the message, a quoted trail included (see below): neither can be placed. A reply that merely quotes an earlier-format message therefore reads `ai_marked_unverified`; a caller checking mail it did not label itself must not read this verdict as "this message was labelled". Beside an original that verifies, such a marker is content outside its container, and the verdict is `verified_with_unmarked_content`; a malformed header token is listed as rejected and leaves the verdict as it is. |
| `quoted_only` | Every marker is a quoted copy; the message quotes a marked message but was not itself marked. |
| `no_marker` | No marker found. |
| `unparseable` | The HTML body exceeds a cap in [Parsing](#parsing) or the parser failed on it. Nothing in it is verified. |

Violations, inside the original container or outside it, turn a verdict
that would otherwise be `verified` into `verified_with_unmarked_content`; a
message without a verifying marker keeps its verdict. The reference detector reports the first violation inside the
original container, or else the first in the message, as
`inside:NAME` or `outside:NAME`, with the total count. `NAME` is an element
(`style`), an element and attribute (`p[style]`), or one of `#comment`,
`#foster-parented`, `#text-in-head` and `#content-not-in-body`.

### Earlier marker format

Messages sent before this specification carry a hidden block whose
`data-ai-disclosure` attribute holds a JSON object (`ai_generated`, `system`,
`on_behalf_of`, `spec: "EU-AI-Act-Article-50"`) rather than a token. Such a
marker is unsigned and has no content container, so it can be detected but
neither verified nor placed as original or quoted. When the message's own
marker verifies, an earlier-format marker elsewhere, a quoted one included,
is content outside the original container, and the verdict is
`verified_with_unmarked_content`. Otherwise, wherever it appears, the
verdict is `ai_marked_unverified`.

## Files

A file carries one marker, its own. Office markers cover the package content
and normalized routing. PDF markers cover only the revision preceding the
marker-bearing update, not the displayed file as a whole. Writing the
marker changes the file's metadata, so each file canonicalisation digests
only what writing the marker leaves alone. The token is never visible in the
document.

| File | Carrier | `canon` |
| --- | --- | --- |
| Office (OOXML) | Custom document property `AIDisclosure` (`vt:lpwstr`) in the custom-properties part | `ooxml-parts/1` |
| PDF | `/AIDisclosure` in the document information dictionary, and `cpxai:AIDisclosure` (`https://complexio.com/ns/ai-disclosure/1.0/`) in the XMP metadata | `pdf-revision/1` |

Alongside the token the file carries unsigned convenience fields:
`AIGenerated`, `AISystem` and `AIGeneratedAt`, and, in a PDF, the IPTC
Digital Source Type `trainedAlgorithmicMedia`. Like `X-AI-Generated` they
prove nothing.

### `ooxml-parts/1`

1. Before reading any part, reject a package with a part that is encrypted or
   neither stored nor deflated, the only methods OPC allows. The reference
   issuer and checker also reject a package with more than 10,000 entries
   (directories included) or more than 512 MiB of declared uncompressed size,
   and a `_rels/.rels`, `[Content_Types].xml` or custom-properties part
   declaring more than 4 MiB; only those three are read whole, every other
   part is hashed as it is read.
   Reject duplicate part names, XML entity declarations, and ambiguous or
   external custom-properties relationships. Select the custom-properties part
   from the package relationship, defaulting to `docProps/custom.xml` when no
   relationship exists. If present, its root must be the OOXML
   custom-properties `Properties` element.
2. List every part except directory entries and the selected custom-properties
   part. Normalize `_rels/.rels` by removing only custom-properties
   relationships, and `[Content_Types].xml` by removing only the selected
   part's `Override`. Serialize these two parts as C14N 2.0, stripping text
   whitespace and rewriting namespace prefixes. All other routing remains
   signed. Sort the list by part name, in Unicode code point order.
3. For each part, write `NAME`, a line feed, the unpadded base64url SHA-256
   of the part's bytes, and a line feed.
4. `content_sha256` is the unpadded base64url SHA-256 of that text, UTF-8
   encoded.

Recompressing (stored or deflated) or reordering the package keeps the
digest; changing any part's content (text, numbers, styles, images) breaks it.

### `pdf-revision/1`

The marker is written as an incremental update, after the file as generated.
`content_sha256` is the unpadded base64url SHA-256 of the file's bytes up to
and including the last `%%EOF` before that update. A verifier finds the token
in the raw bytes and digests up to the last `%%EOF` that precedes it.

- Names compare after their `#xx` escapes are decoded (ISO 32000-1 §7.3.5),
  as whole names: `/AI#44isclosure` is the property, `/AIDisclosureX` is not.
- The token is the first occurrence of that name followed, after whitespace
  and comments, by a string: a literal string, with its escapes decoded (a
  writer can write any byte as one, `.` as `\056`) and balanced parentheses
  kept, or a hexadecimal string. A hexadecimal string whose digits are not
  hex is a malformed token.
- An occurrence followed by anything else (page text such as
  `(see /AIDisclosure) Tj`, a dictionary, an indirect reference) is skipped.
  A name that occurs but is never followed by a string is a malformed token.
- In the XMP, the property is the complete QName `cpxai:AIDisclosure`, as an
  element or an attribute, never the end of a longer QName.

Any change to the generated revision breaks the digest. A later incremental
update appended after the marker does not, and is not covered by it. A tool
that rewrites the whole file (rather than appending) breaks the digest, and
may move the token into a compressed object stream where the reference
detector does not look for it.

### Verifying a file

Steps 2 and 3 of [Verifying a message](#verifying-a-message) apply
unchanged: an `AIDisclosure` property or PDF entry that is empty, or holds
anything but a token, is a malformed token, never `no_marker`. For step 4,
recompute the digest for the token's `canon`; a token whose `canon` does not
belong to the file type is unsupported. The verdict is
`verified` when the signature is valid and the digest matches, and
`ai_marked_unverified` otherwise. PDF verification always reports
`verified_with_unmarked_content` instead of `verified` when the revision's
signature and digest match, with CLI exit status 4: the marker-bearing update
itself, including any page changes it contains, is outside the signature.
It must not be attributed to the marker.

## Keys

Markers are signed with Ed25519. Each deployment of the system signs with its
own key; the `kid` names it. Unless configured otherwise, the `kid` is the
[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint of the public
key, and every key Complexio publishes is named that way. A `kid` is opaque
on purpose: it names no customer, so the public key set does not reveal whom
Complexio signs for. The organisation a marker was issued for is named in
the signed token (`on_behalf_of`). Complexio vouches for every key in the
set: a key in the set belongs to a deployment Complexio operates.

Complexio publishes the public keys as a JWKS document
([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) over HTTPS. Each key is
an OKP JWK with `crv: Ed25519`, `use: sig` and `alg: EdDSA`. A retired key
stays in the set, so mail it signed still checks. A compromised key is
removed, after which mail signed with it no longer verifies; that is
intended. A key has no validity period in this version: a verifier does not
check a token's `iat` against the time the key was in use.

A verifier skips an entry it cannot use, as RFC 7517 section 5 asks, rather
than rejecting the set: a `kty` other than `OKP` or `crv` other than
`Ed25519`, a `use` other than `sig`, an `alg` other than `EdDSA`, `key_ops`
without `verify`, a `kid` that is not a string, or an `x` that is not the
canonical base64url of 32 bytes. An entry without a `kid` is named by its
thumbprint. A `kid` is a name, so it is not compared with the thumbprint
(RFC 7517 section 4.5 leaves it opaque): the set itself is what is trusted.
A `kid` that two usable entries share names no key, since either could be
meant.

The key set is published at
<https://ai-disclosure.complexio.com/.well-known/ai-disclosure-jwks.json>, served
as `application/jwk-set+json` and open to cross-origin reads. Its address does
not change when keys are added or retired. A verifier follows a redirect only
to another `https` address. It bounds the fetch with one deadline:
connecting to each address, the TLS handshake, every read and every
redirect end by it, and a fetch that times out leaves nothing running. Name
resolution is left to the system resolver's own timeout. The site refuses
some HTTP libraries' default `User-Agent` (Python's `Python-urllib/3.x` gets
HTTP 403), so a client names itself.

## Versioning

The `spec` claim names the version. A change a version-1 verifier would
misread (a new required claim, a changed meaning) gets a new version;
verifiers report a token with an unknown `spec` rather than trusting it. A
new canonicalisation gets a new `canon` value instead, so a verifier that
does not know it says it does not support it rather than reporting a
mismatch.

## Transport limits

- Microsoft Graph accepts custom headers only on message creation and only
  with names starting `x-`. Messages created as replies (`createReply`, then
  updated) cannot carry them, so replies carry the body block only. More than
  five custom headers on one message are reported to be refused.
- A header line is limited to 998 characters
  ([RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) §2.1.1), and the token
  cannot be folded. A token that would not fit (an exceptionally long
  `on_behalf_of`) is sent in the body only.
- Mail gateways and clients may remove hidden elements, `data-` attributes or
  custom headers, and copying text out of a message removes all markup. The
  marker is then lost or the content cannot be found; a lost marker does not
  make the content human-written.
- Link-rewriting gateways other than Microsoft Defender Safe Links (for
  example, other vendors' URL protection) change link targets on delivery.
  The digest then no longer matches, and the content is reported as changed
  after signing.
- The digest covers text, link and image targets, link titles and image
  descriptions, not presentation. Allowlisted markup inside the container
  can still be changed without changing the digest: emphasis, headings,
  table layout and list items. A `verified` verdict says
  the words and links are the signed ones, not that they look as they did
  when signed.
- The digest removes every whitespace character from text, so text that
  differs only in spacing has the same digest: `1 000`, `10 00` and `1000`
  read the same, and so do `can not` and `cannot`. A link enters the digest
  as its target, at the point where the link starts, not as the text it
  spans: an anchor can be stretched over neighbouring visible text, or
  shrunk, without changing the digest.
- A plain-text alternative to the HTML body is not checked (step 7 of
  [Verifying a message](#verifying-a-message)). Most mail clients show the
  HTML, and Exchange adds a plain-text alternative written from the HTML to
  many messages. That part can say something else: a reader whose client shows
  plain text, or a program that reads it, sees words the marker does not
  vouch for, and the verdict can still be `verified`.
- Exchange and Outlook may rewrite a message's HTML in transit or on reply.
  A reply composed by Exchange (`createReply`) carries the quoted
  conversation in Outlook's own markup, outside the signed container;
  such a reply reads at best `verified_with_unmarked_content`. Whether Exchange
  keeps the hidden block's `style="display:none"` byte for byte has not been
  confirmed on a received sample; a rewritten block reads as a violation
  outside the container.

## Text watermarking

Complexio does not add a watermark of its own to the generated text.

A statistical text watermark is applied while the text is generated, by
steering, with a secret key, which tokens the model samples, so that a
detector holding the key can later test for the pattern. That control sits
inside the model. Where the text comes from a model reached through its
provider's API, Complexio has no per-token control over sampling, so it
cannot apply such a watermark. Of the routes after generation, inserting
invisible characters does not survive copying or text normalisation, and
substituting words changes the content the reader receives. Neither is used.

The model provider, Anthropic, states that text from its supported models
carries its own watermark, applied in the model, and publishes which models
and platforms carry it
(<https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content>).
Not every model the system may use carries it. Detection of that watermark is
offered by the model provider, not by Complexio. This marker neither depends
on it nor reports on it.

An email is a container with its own metadata, so marking is done there: a
signed token in the message headers and in the HTML body, bound to the text
by its digest.

## Test vectors

`ai_disclosure_vectors.json`, published with this specification, is generated
by the reference implementation. `jwks` is the public key set of a test key
that signs nothing else.

| Section | Each vector holds | A verifier reproduces |
| --- | --- | --- |
| `canonical` | An HTML fragment and the fragment as the issuer balances it (`balanced`) | For `balanced` inside a content container: the canonical string, `content_sha256` and the first violation inside the container |
| `label` | An unsigned label as issued: `html_body` and its `token` | `ai_marked_unverified` with one unsigned marker whose content matches; the canonical string and `content_sha256` |
| `signed_as_written` | Content as issued, `content_html`, and its `token`, signed with the test key | With `jwks`: a valid signature, the `content` result, the `verdict` and the first violation |
| `detection` | `html_body`, an optional `header_token` (`X-Complexio-AI-Disclosure`) and `x_ai_generated` (`X-AI-Generated`), and `jwks`: whether the verifier holds the test key set or none | The `verdict`, `unmarked_content`, the first violation, and in order each marker's carrier, placement, signature and content results, whether its token was `rejected` (a malformed token, or a header or claims outside [Token](#token)) and whether it is in the `legacy` format |

The `detection` vectors are mostly ways a marker must fail to verify: content
changed, removed or not leading, a header token for other content, an
unsupported canonicalisation, a forged signature, an unknown key,
`alg: none` with or without a signature, `HS256` keyed with the public key,
`Ed25519` as `alg`, `crit`, `b64`, `jku`, a `kid` that is not a string, a
repeated header member or claim, `NaN`, a non-canonical signature spelling,
each claim rule, unparseable tokens, an empty header or attribute, a forged
hidden block beside a verifying header, token JSON nested 32 deep (read) and
33 deep (rejected), an earlier-format marker, an `X-AI-Generated` header
alone, and HTML nested too deep.

## Reference implementation

The Python package `ai-disclosure-verify` (import name `ai_disclosure_verify`)
implements detection and verification only. It runs as:

```
ai-disclosure-verify MESSAGE.eml [--jwks KEYS.json | --offline] [--timeout SECONDS] [--json]
ai-disclosure-verify BODY.html [--jwks KEYS.json | --offline] [--timeout SECONDS] [--json]
ai-disclosure-verify REPORT.docx [--jwks KEYS.json | --offline] [--timeout SECONDS] [--json]   # also .xlsx, .pptx, .pdf
```

It prints the verdict and what it means in plain language, whether the
message has content outside the marker, the first violation of
the markup allowlist and their count, and every marker found
with its carrier, placement, signature and content results, each with a
plain-language meaning (for a mismatch: content changed after signing).
`--json` prints the same report as JSON. Values taken from the message
(claims, the key id, the `X-AI-Generated` header, markup names, reasons)
are printed in quotes, with `\`, `"` and every unprintable character
(controls, line separators, bidirectional overrides) written as a Python
escape, so none can start a line of its own or reach the terminal as a
control sequence. The JSON report is ASCII, every other character escaped.
Exit status:

| Status | Meaning |
| --- | --- |
| 0 | `verified` |
| 1 | `no_marker` |
| 2 | The message or key set could not be read (missing file, undecodable charset, input nested too deeply, malformed JWKS, key set not fetched), or `unparseable` |
| 3 | `ai_marked_unverified` or `quoted_only` |
| 4 | `verified_with_unmarked_content`, which includes every verified PDF |

By default the key set is fetched over HTTPS from the published location,
only when a signed marker needs it; `--timeout` sets how long to wait for
it, in seconds (default 10, at most 3600). `--jwks` reads it from a local
file instead. With `--offline` and no `--jwks`, no key set is loaded, so
signatures are reported as not checked.

### Reading the input

The detector tells the kind of input from its content, not its name, in
this order:

1. A zip signature (`PK` 03 04) at the start is an Office file; `%PDF-` at
   the start is a PDF.
2. After a UTF-8 byte-order mark and ASCII whitespace, `<` is an HTML body,
   and a header field (a name of printable ASCII characters other than `:`,
   then `:`, or an mbox `From ` line) is a message, read from that point.
3. `%PDF-` within the first 1024 bytes is a PDF, as PDF readers accept;
   failing that, a zip signature within them is an Office file.
4. A tag anywhere (`<` followed by an ASCII letter, `/` or `!`) is an HTML
   body, such as a fragment that starts with text.
5. Anything else is a message.

A fragment whose first line looks like a header field (`Note: …`) is read
as a message first. When that message has no HTML body and no marker, the
input is read again: as a PDF or Office file when its first 1024 bytes hold
that signature (step 3), reported if its token decodes; failing that, as an
HTML body when it holds a tag, reported if it finds a marker, or if it is
`unparseable` and the input holds `data-ai-disclosure`. So the guess never
turns a marked file or fragment into `no_marker`; the fragment's first line
is text before its container, so its marker reads as quoted. A message whose
MIME parts nest too deeply for the parser is reported as unreadable (exit status
2), as an HTML body over the caps in [Parsing](#parsing) is `unparseable`.
An Office file whose routing XML nests too deeply to serialise keeps its
marker, with its content not found (exit status 3). None of these reads as
`no_marker`.
