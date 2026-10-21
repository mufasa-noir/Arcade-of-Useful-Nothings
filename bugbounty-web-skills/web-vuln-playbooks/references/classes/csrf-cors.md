# CSRF, CORS, Cookies, Clickjacking

**Root cause:** the browser attaches ambient credentials (cookies) to cross-site requests, or cross-origin read access is granted too broadly.

## CSRF
- State-changing endpoints authenticated by cookies and lacking an unpredictable token tied to the session (or lacking an effective SameSite policy/custom header requirement).
- Frameworks: token middleware exempt lists (`csrf_exempt`, ignored routes), safe-method handlers that change state (`GET` that deletes), JSON endpoints that accept `text/plain` or form-encoded content, token checked only when present, token not bound to the user, token validated against a value the attacker can obtain.
- Impact depends on the action (email/password change, privilege change, payments, data deletion). Trivial or idempotent actions are often out of scope.
- WordPress-style nonces: they prove the session rendered the form, not that the user holds the capability; assess authorization separately.

## CORS
- Dangerous: reflecting the request `Origin` while allowing credentials; allowing `null` origin with credentials; broad regex/suffix matching of origins; `Access-Control-Allow-Origin: *` is harmless for cookie-authenticated endpoints because credentials are not sent, but check for tokens in headers or intranet exposure.
- Impact is about what a malicious page can read from an authenticated victim's session.

## Cookies and headers
SameSite value (Lax vs None vs unset behavior varies by browser), HttpOnly, Secure, domain/path scoping (parent-domain cookies shared with untrusted subdomains), cookie tossing. Clickjacking: absence of `X-Frame-Options`/`frame-ancestors` is only relevant on pages with sensitive one-click actions; many programs exclude generic missing-header reports.

## Review questions
- Is the endpoint cookie-authenticated and state-changing? What blocks a cross-site request?
- What exactly validates the token (existence vs equality vs binding)?
- For CORS: how is the allowed origin computed; are credentials allowed; which endpoints carry sensitive data?

## False-positive traps
Bearer-token APIs where the token is not in a cookie; SameSite=Lax/Strict plus non-GET requirement; actions with no security impact; public data.

## Variant ideas
Method override parameters, JSON-to-form content type confusion, alternate API versions without middleware, WebSocket handshakes using cookies without origin checks.
