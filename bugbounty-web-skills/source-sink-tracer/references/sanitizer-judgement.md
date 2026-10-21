# Judging a Control

Ask these for every sanitizer, escaper, validator, allowlist or filter between source and sink. Record the answer and the `file:line`.

1. **What does it actually do?** Open the function. Names lie. Write one sentence on its real behavior (strips tags? escapes quotes? casts to int? checks a prefix?).
2. **Is it the right control for this sink's context?** HTML-escaping does not protect a SQL query; SQL escaping does not protect an HTML attribute without quotes or a JavaScript string; URL-encoding does not stop `javascript:` in an `href`; a shell-escape function does not protect `eval`. Match control to context (HTML body, attribute, JS string, URL, CSS, SQL value, SQL identifier, shell argument, file path, template).
3. **Is it applied to the value that is actually used?** Common failures: sanitized copy, original used; sanitized on one branch only; sanitized the key not the value; sanitized an array element but the sink takes the whole array; validated in one layer, re-read from the raw request in another.
4. **Order of operations.** Does a later step undo it (URL-decode, base64 decode, unicode normalization, case change, path canonicalization, template re-evaluation, string concatenation of two individually safe pieces)? Validate-then-transform and check-then-use (TOCTOU) are the classic breakers.
5. **Allowlist or blocklist?** Allowlists with strict types (integer cast, enum membership, strict regex with anchors) are strong. Blocklists (strip `<script>`, reject `../` once, reject quotes) are almost always bypassable; say how.
6. **Completeness.** Anchors and flags on regexes (`^...$`, multiline, `.` matching newlines), partial matches (`strpos` or `startswith` on a prefix), `==` vs `===` or loose comparison, locale/case issues, length limits, array-vs-string inputs, null bytes, trailing characters.
7. **Type guarantees.** A value cast to an integer or parsed into a strict schema type before use is genuinely constrained; a value that merely passes through a typed signature in a dynamic language may not be. Check where coercion actually happens.
8. **Does the control hold for every source reaching the sink?** One protected route does not protect a second route that calls the same helper differently.
9. **Framework default.** Is there auto-escaping or parameter binding that applies here, and is it disabled or bypassed (`|safe`, `mark_safe`, raw output helpers, string-built queries, `$queryRawUnsafe`, `dangerouslySetInnerHTML`)?
10. **Verdict on the control:** `holds`, `partial` (say for which inputs it fails), `fails`, or `unverified`, with the reason.

## Auth and authorization checks are controls too
- Is the check performed before the sensitive action, on every path, using the identity from the session rather than from the request?
- Does it verify the *object* (ownership/tenant), not only the *role*?
- Is a CSRF nonce being mistaken for an authorization check? (Nonce proves intent of the browser session, not privilege.)
- Does it fail closed (deny on error) or open?
