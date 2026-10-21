# PoC Plan

Contents: environments, plan format, safe proof patterns by class, cleanup.

## Environments (prefer top to bottom)
1. **Local instance of the exact version.** Containerize or install the same release locally (for WordPress plugins: a local WordPress with the exact plugin version and the plugin's required stack; for apps: docker-compose from the repo). Seed with fake data and your own test accounts for each role needed.
2. **Unit-style harness.** Call the vulnerable function directly with the hostile input and assert on the result (good for pure functions, escapers, parsers, query builders).
3. **Program-provided test environment or staging**, if the program offers one.
4. **Live target**, only with scope permission AND a logged CP4 approval of this exact plan.

## Plan format (write this into the finding file before running)
```markdown
### PoC plan for C-### / F-###
- Environment: <local vX.Y / harness / staging / live>
- Accounts/roles: <own accounts; roles required>
- Preconditions/config: <...>
- Steps / requests: <numbered, exact>
- Expected observation (proves the bug): <specific, observable>
- Why it is non-destructive: <...>
- Program rule that allows it: <scope.md reference>
- Cleanup: <...>
- Approval (CP4) quote and log#: <for non-local steps>
```

## Safe proof patterns (choose the weakest proof that is convincing)
- **SQL injection:** boolean difference or a bounded time delay; read a value you own (your own record or the DB version string). No table dumps, no writes.
- **XSS:** a benign marker that shows DOM execution context (for example altering the page title or `document.domain` in your own session); no cookie theft, no external beacons to third parties.
- **Command injection / code exec:** run an innocuous command and show its output (`id`), or write a file in a temp directory you own on the local instance. Never on live systems unless explicitly allowed.
- **SSRF:** request to a server you control showing the inbound request; internal metadata or intranet access only if the program explicitly allows probing, otherwise demonstrate reachability with a harmless internal address and stop.
- **Path traversal / file read:** read a harmless world-readable file (such as a known static file or `/etc/hostname` locally); not config, keys or other users' files.
- **IDOR/BOLA:** two accounts you own; account A reads or modifies account B's *test* object. Never use someone else's data.
- **Auth bypass / privilege escalation:** show a low-privilege session performing a privileged action on your own test objects.
- **Open redirect / CSRF:** a minimal page or request showing the behavior; no attack against real users.
- **Deserialization / SSTI:** demonstrate with a harmless side effect locally; exploitation chains on live systems are out unless explicitly allowed.
- **Secrets:** confirm the secret type and location; do not use the credential against any system. If the program requires validation, ask the human and follow its rule.

## Rate and footprint
Single requests or the minimum needed. No scanning, no brute force, no automated fuzzing of live targets unless the program explicitly allows it.

## Cleanup
Delete test objects, reset test accounts, stop local containers. Note anything you could not clean up.
