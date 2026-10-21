# Cross-Site Scripting and HTML Injection

**Root cause:** attacker data reaches a browser parsing context (HTML, attribute, script, style, URL) without encoding appropriate to *that* context, or reaches a DOM sink in client code.

## What the sink looks like
- Server output: `echo`/`print`/template raw output of request or stored data; raw-output template features (`|safe`, `mark_safe`, triple-brace raw, `{!! !!}`, `<%- %>`); string-built HTML in JSON/AJAX responses later inserted with `innerHTML`.
- DOM: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`/`.append(string)`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `eval`/`setTimeout(string)`, `location`/`href` assignment from input, `postMessage` handlers without origin checks.
- URL contexts: `href`/`src`/`action` set from input permit `javascript:` and `data:` schemes unless scheme-allowlisted.

## Safe vs unsafe
- Safe: framework auto-escaping in the correct context; `textContent`; `setAttribute` for non-URL attributes; allowlist HTML sanitizers (applied at output, with a restrictive config) for rich content.
- Unsafe: escaping for the wrong context (HTML-escape inside a JS string, an unquoted attribute, or a URL scheme); sanitizing at input but rendering through a different path; sanitizing then modifying the string (mutation); building JSON into `<script>` without escaping `<`, `<!--` and line separators.

## Control correctness
Match escaper to context: body, quoted attribute, unquoted attribute, JS string, URL, CSS. Blocklist tag stripping (`<script>` removal) is bypassable. A strong CSP lowers exploitability but should be assessed for realism (unsafe-inline, wildcard hosts, JSONP endpoints) and does not make the sink safe.

## Reachability and impact
Who views the output matters most: user content shown to admins or moderators is high value; reflected needing a crafted link is lower; self-XSS is usually out of scope. Stored XSS in a component rendered to many users, or in an admin screen, matters most. Check cookie flags (HttpOnly) and the presence of sensitive actions the injected script could perform (CSRF protections do not stop same-origin script).

## Review questions
- Which context is the value in, and what encoding is applied right at output?
- Does the value pass through storage? Written where, rendered where, for whom?
- Is the same value rendered in other places (email, RSS, export, admin list, notifications, search results, `<title>`, meta tags)?
- Client side: where does the data enter (URL, `postMessage`, storage, API) and which sink consumes it?

## False-positive traps
JSON responses with a JSON content type and no sniffable HTML; output only shown to the submitting user; framework auto-escaping that is actually active (check the template engine's setting); values constrained to integers or enums; sanitizer applied at output that you did not read.

## Variant ideas
Attribute-name/value injection in admin tables; titles, usernames, avatars alt text, filenames, error messages, validation messages that echo input; markdown/BBCode renderers; SVG upload (see file card); email templates; PDF/HTML export; third-party widgets embedded with unescaped options.
