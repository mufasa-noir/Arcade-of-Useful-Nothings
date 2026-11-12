# Impact and Severity Reasoning

Always defer to the program's own severity table. Use CVSS only when asked or when the program uses it.

## Impact checklist
- **Principal:** unauthenticated / any registered user / specific role / admin. Lower required privilege raises severity.
- **Interaction:** none / victim must click or visit / unusual action. 
- **Scope of effect:** one user's data, all users, tenant, whole application, host.
- **CIA:** what can be read (which data, how sensitive), changed (which state), or disrupted.
- **Persistence:** one-shot vs stored/permanent.
- **Realism:** default configuration vs unusual settings.
- **Chains:** describe separately ("combined with X, impact becomes Y") and label as a chain. Do not inflate the base finding with a speculative chain.
- **What the attacker cannot do:** state limits (needs valid session, cannot reach other tenants, read-only, etc.). Triagers trust reports that name their own limits.

## CVSS 3.1 notes (metrics to justify one by one)
AV (network for web), AC (low unless unusual conditions), PR (none / low = any user / high = admin), UI (none / required), S (scope changed only if it crosses a security boundary, e.g. stored XSS affecting other users' browser contexts is often argued as changed; justify), C/I/A (none/low/high by data and function).
Write each metric with a one-clause reason. Quote the vector string. If CVSS 4.0 is required, justify its equivalent metrics similarly.

## Typical class impact framing (starting points, not scores)
- Unauthenticated SQLi with data read: high to critical; authenticated-admin SQLi: usually low to medium.
- Stored XSS reachable by low-privilege users and viewed by admins: often medium to high (admin session impact); reflected XSS needing interaction: lower.
- IDOR exposing other users' personal data: medium to high depending on data; writable IDOR higher.
- Missing function-level authorization on privileged actions: high if privilege escalation to admin; lower if the action is minor.
- SSRF: depends on what is reachable (cloud metadata and internal services high; blind to the public internet low).
- Path traversal: depends on files readable and writable.
- Remote code execution via any route: critical, but require a verified path.
- CSRF on sensitive state changes: medium; on trivial actions: low or out of scope.
- Hard-coded secrets: depends on whether the secret is live, and what it unlocks.
