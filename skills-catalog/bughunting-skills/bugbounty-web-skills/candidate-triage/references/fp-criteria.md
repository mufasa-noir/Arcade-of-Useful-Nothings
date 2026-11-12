# Knock-Down Criteria

Contents: general criteria; per-class additions. For each criterion record `defeats` / `weakens` / `no effect` / `unknown` with evidence (`file:line`).

## General (all classes)
1. **Attacker control.** Does the attacker control the whole value, a fragment, or only a constrained type (integer, enum, UUID, fixed charset, bounded length)? A fragment inside a quoted, typed or prefixed position may not be enough.
2. **Control effectiveness in context.** For each sanitizer/validator/framework default on the path: is it the right control, applied to the used value, in the right order, complete? (See the tracer's `sanitizer-judgement.md`.) Test with concrete hostile inputs mentally or locally; do not assume.
3. **Reachability.** Is the route/hook registered and enabled by default? Is it behind a feature flag or constant that is off? Is the file reachable (not under a deny rule, not an unused include)? Is it test, example, migration, or vendored code that never ships?
4. **Principal required.** Who must the attacker be? Unauthenticated / any user / specific role / admin. If admin or equivalent already grants the impact, the bug usually adds nothing. Check what the program counts.
5. **User interaction and preconditions.** Victim must perform unusual steps? Specific plugin/config/PHP version combos? Object in a rare state? Weigh realism, not possibility.
6. **Framework and platform mitigations.** Auto-escaping, parameter binding, CSRF protections, SameSite, CSP (CSP reduces but rarely eliminates XSS; note nonce/strict-dynamic realism), WAF (not in the repo: do not assume), input type coercion, ORM guards.
7. **Impact.** What does the attacker concretely gain? Reflected output that is JSON with the right content type, data the attacker could already read, or a sink whose result is discarded may mean no impact.
8. **Deployed version.** Does the code exist in the released/deployed version in `scope.md`? Has it been fixed in a later tag (then check whether the target is on it)?
9. **Scope and policy.** Excluded class (self-XSS, missing headers, DoS, rate limiting), out-of-scope component, source-only not accepted, known/duplicate issue.
10. **Duplicates.** Known advisory or public report? (Search advisories/changelog; record what you checked.)

## Per class

### Injection (SQL/NoSQL/command/LDAP/header)
Parameterized with bound values (and the variable part is a value, not an identifier)? Integer cast before use? Allowlist on identifiers (ORDER BY column)? Command invocation without a shell and with an argument array and `--` separation? Value only reachable after admin auth?

### XSS
Output context matches the escaper (body vs attribute vs JS vs URL)? Content type prevents HTML interpretation? Value only shown to the submitting user (self-XSS)? Sanitizer (allowlist HTML sanitizer) applied at output? Framework auto-escape not bypassed? Who views it (higher-privilege viewer raises value)? CSP strength.

### SSRF / open redirect
URL fully attacker-controlled or only a path/query on a fixed host? Allowlist on host after parsing (not substring)? Redirect following disabled and DNS/IP validated after resolution? Response returned to attacker (full read) or only side effect/blind? Open redirect limited to same-origin paths?

### Path traversal / file / upload / archive
Value canonicalized then checked against a base directory? Basename only? Fixed extension appended and null-byte/PHP version irrelevant? Upload stored outside web root or with non-executable handling? Extension allowlist on the *final* stored name? Archive extraction path-checked per entry?

### Deserialization / eval / template injection
Is the input really attacker data, or signed/encrypted with a secret the attacker lacks? Safe loader / allowlisted classes? Template string constant, or built from input? Sandboxed engine and what it permits? Gadget availability is a reachability question: say what is unknown rather than assuming.

### AuthN / session / JWT / secrets
Signature verified with a fixed algorithm and a non-guessable key? Secret is a placeholder in sample config only? Credentials are for a test/mock system? Token entropy and expiry real?

### Authorization
Upstream enforcement (middleware, base class, proxy config) found? Data public by design? Object IDs unguessable and unleaked? Role requirement equal to the impact? Tenant scoping applied at a layer you did not read (ORM default scope)?

### CSRF / CORS
State-changing and cookie-authenticated? SameSite and custom-header requirements? CORS reflects origin with credentials, or just `*` without credentials (usually harmless)? Impact beyond what the attacker's own browser could do?

### Logic / race / mass assignment
Is the invariant truly enforced elsewhere (DB constraint, unique index, transaction)? Is the race window real given locks/transactions? Is the extra field actually persisted and honored?

### Secrets / info disclosure
Live credential or example? Reaches the client or is server-only? Exposed endpoint reachable? Impact of the disclosed data.
