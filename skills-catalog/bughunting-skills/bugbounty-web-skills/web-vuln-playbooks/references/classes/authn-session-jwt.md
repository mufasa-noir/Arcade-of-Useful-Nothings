# Authentication, Sessions, JWT, Password Reset, Secrets

**Root cause:** identity is established, stored, or recovered in a way an attacker can forge, guess, steal or bypass.

## What to look for
- **Login:** user enumeration via messages/timing, no throttling (note only where program accepts), credential stuffing surfaces, default or hard-coded credentials, backdoor-like debug accounts.
- **Passwords:** weak hashing (fast unsalted hashes), plaintext storage or logging, comparison with `==` (type juggling in loose-typed languages) instead of constant-time strict comparison.
- **Sessions:** predictable or low-entropy IDs, fixation (ID not rotated at login), missing invalidation at logout/password change, cookie flags (HttpOnly, Secure, SameSite), session data trusted from the client, hard-coded or guessable signing secret (framework secret key committed to the repo).
- **JWT:** `alg` handling (accepting `none`, algorithm confusion between asymmetric and symmetric), signature not verified (decode-only functions used where verify is needed), weak or default secrets, missing `exp`/`aud`/`iss` checks, trusting claims such as role or tenant without server-side backing, `kid`/`jku` header injection.
- **Password reset and email verification:** guessable or reusable tokens, tokens not bound to the account, no expiry, token leaked via `Referer` or logs, host header used to build the reset link, reset that doesn't invalidate sessions, change-email without re-auth.
- **OAuth/SSO:** `redirect_uri` validation by prefix, missing `state`, missing nonce/audience checks, account linking by unverified email, trust of unsigned assertions, open redirect in the flow.
- **MFA:** bypass by direct call to the post-MFA endpoint, brute force, backup codes weakness, MFA state held client-side.
- **API keys:** keys compared non-constant-time, never rotated, embedded in clients, scope not enforced.
- **Secrets in code:** live credentials, private keys, signing secrets, third-party tokens, `.env` committed, secrets in client bundles or `NEXT_PUBLIC_`-style variables.

## Review questions
- Where is identity established and where is it re-validated server-side?
- What exactly does verification check (signature, algorithm, expiry, audience, revocation)?
- Source of randomness for each token; length and format.
- Is each secret a real value or a placeholder in examples? Is it used by a deployed configuration?
- What happens after password change, logout, role change?

## False-positive traps
Secrets that are obvious placeholders; test configs; rate-limit findings in programs that exclude them; user enumeration in programs that exclude it; JWT used only for non-sensitive client state.

## Variant ideas
Alternate login paths (API vs web, mobile), legacy auth endpoints, impersonation/"login as" features, installers and setup wizards left reachable, debug endpoints, health endpoints leaking config.
