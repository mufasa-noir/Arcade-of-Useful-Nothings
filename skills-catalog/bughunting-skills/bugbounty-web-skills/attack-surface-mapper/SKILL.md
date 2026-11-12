---
name: attack-surface-mapper
description: Maps the attack surface of a web application's source code before any bug hunting. Orients in the repo, acquires missing code (source maps, bundles), inventories every route and entry point, documents the authentication/authorization model, inventories dangerous capabilities (SQL, exec, file, HTTP client, deserialization, templates), checks secrets and dependencies, and ranks hot spots. Use at the start of any white-box web audit or bug bounty source review, when the user says "map the attack surface", "enumerate routes/endpoints/entry points", "where should I start in this codebase", "orient me in this repo", or when audit/attack-surface.md does not exist yet. Also use when a new component joins scope and needs mapping.
---

# Attack Surface Mapper

Your job is to produce `audit/attack-surface.md`: a map that lets the hunt phase spend its time on the 10% of code that matters. You find and describe; you do not decide what is exploitable.

Why map first: white-box review is a reading problem before it is an exploitation problem. The first minutes are reading order, not bug hunting. A reviewer who starts at a random grep hit wastes hours on code an attacker can never reach.

## Workspace contract
Read first: `AGENTS.md`, `audit/scope.md`, `audit/human-context.md`. Write: `audit/attack-surface.md` (template: `references/attack-surface-template.md`). Append `audit/log.md` after each checklist item P1.x and tick `audit/checklist.md`. New leads go to `audit/candidates.md` as `NEW` with `origin: mapper`. Cite `path:line` for every claim.

## Procedure

### 1. Orient (P1.1)
Read in this order, stopping when you can state the architecture in five lines:
README / docs → dependency manifests (`composer.json`, `package.json`, `requirements*.txt`/`pyproject.toml`, `pom.xml`/`build.gradle`, `Gemfile`, `go.mod`) → entry files (`index.php`, main plugin file, `app.py`, `server.js`, `next.config.*`, `Application.java`) → config → directory layout.
Record: language(s), framework(s) and versions, how requests reach code, DB layer, templating, auth library, build/bundle setup. Make a **skip-list**: `vendor/`, `node_modules/`, `dist/`, minified files, tests, fixtures, generated code, i18n. Say what you skipped and why.

### 2. Acquire and verify the code (P1.2)
Confirm the code you have is the code that ships: tag/commit vs the deployed version in `scope.md`. If part of the target is client-side or only available as a bundle, read `references/acquiring-code.md` (source maps, beautifying, decompiling). Submodules and monorepo packages: list them and say which are in scope.

### 3. Inventory entry points (P1.3)
Enumerate every way external input enters: HTTP routes, framework hooks, background job payloads, webhooks, file uploads, WebSocket handlers, CLI/cron that read user data, import/export parsers, email handlers, deep links. Use `references/route-discovery.md` for framework-specific patterns. Assign IDs `R-001...` and record: method, path or hook name, handler `file:line`, parameters, who is *intended* to reach it (best guess, flagged as guess), and the auth check you can see at the handler.
Count them. If the count looks too low for the app's size, you have missed a registration mechanism; search for it.

### 4. Document the auth model (P1.4)
Describe: how users authenticate (session, cookie, JWT, API key, OAuth), where identity is established (`file:line`), the role/capability model, where authorization is enforced (middleware, decorators, policies, in-handler checks, framework defaults), and what is the *default* for a new route (default-allow or default-deny). This section is what `authz-matrix-audit` builds on, so be precise. If roles are ambiguous, list the question for the human rather than guessing.

### 5. Inventory dangerous capabilities (P1.5)
Count and locate, grouped by class, the operations that become vulnerabilities when reached by attacker data: raw SQL, shell/process execution, filesystem access with variable paths, outbound HTTP, deserialization, template rendering of dynamic strings, `eval`-like calls, XML parsing, redirects, file upload handling, crypto/random for tokens. Use the stack catalog in `../web-vuln-playbooks/references/stacks/` for the sink names. Use `rg`/`grep` for seeds; if Semgrep is available, `semgrep --config=auto --json` is a fast way to seed the list, but treat results as pointers, not findings.
Output counts per class and the top locations; do not paste hundreds of hits. Cluster them by file or module.

### 6. Secrets and dependencies (P1.6)
Run gitleaks or trufflehog over history if available (otherwise targeted `rg` for key patterns and `.env`/config files). Record locations and types only; do not use or print secret values. Run the ecosystem audit tool if present (`composer audit`, `npm audit`, `pip-audit`) and list dependencies with known advisories that are actually *used* in reachable code. A vulnerable dependency that is never called is not a lead.

### 7. Git history signals (P1.7)
Do a quick scan (details belong to `patch-variant-hunt`): `git log --oneline | rg -i 'security|vuln|cve|xss|sqli|inject|csrf|sanitiz|escape|auth|bypass|traversal|ssrf'`. Record the commits and hand them over; do not analyze them deeply here.

### 8. Rank hot spots (P1.8)
Score each candidate area by: reachable without or with low privilege, handles attacker-controlled data, touches a dangerous capability, has complex or custom validation, has a history of fixes, has sparse tests or is old/unmaintained, sits at a trust boundary (uploads, imports, webhooks, admin-to-user rendering). List 8-15 hot spots with a one-line reason each, ordered. These feed CP1.

### 9. Stop for the human (P1.9)
Fill the template, log, tick, then present CP1 (see `../web-audit-orchestrator/references/checkpoints.md`). Include a short "could not determine" list; honest gaps are more useful than confident guesses.

## Rules
- Describe, do not judge exploitability. "This route accepts `id` and calls `$wpdb->query`" is a map entry; "SQL injection here" is a candidate for the tracer.
- Prefer breadth over depth. If you catch yourself tracing one flow end to end, log it as a candidate and move on.
- Be explicit about coverage: what you mapped, what you skipped, and what you suspect you missed.
- Do not run the application or send requests. Everything here is static.

## Files
- `references/attack-surface-template.md`: exact output structure.
- `references/route-discovery.md`: entry-point patterns by framework.
- `references/acquiring-code.md`: getting and normalizing code (source maps, bundles, APKs, exposed repos).
