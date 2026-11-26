# WHATWG URL test data (http and https subset)

`urltestdata-http.json` holds entries of web-platform-tests'
`url/resources/urltestdata.json` at commit
`065d99ab62bf0b6ca04907f423625801c350edb2`, each unchanged: those whose
`input`, trimmed of leading and trailing C0 controls and spaces and with tabs
and newlines removed (as WHATWG URL parsing does), starts with `http://` or
`https://` in any letter case. That is 359 of the file's 1021 entries; the
others cannot reach text-links/2's URL serialisation.

`test_url_whatwg.py` checks that every input the serialisation handles gives
the entry's `href`, that it handles none WHATWG refuses, and that any input
it declines is kept as written.

Licence: web-platform-tests, 3-Clause BSD License, Copyright © web-platform-tests
contributors (https://github.com/web-platform-tests/wpt/blob/master/LICENSE.md).
