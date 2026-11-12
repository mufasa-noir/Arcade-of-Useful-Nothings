---
name: authz-matrix-audit
description: Builds a route-by-route authorization matrix for a web application's source code (expected principal vs enforced check) and flags gaps such as missing authentication, missing function-level checks, IDOR/BOLA, mass assignment of privilege fields, tenant isolation failures, nonce-instead-of-capability checks, and middleware ordering or matcher holes. Use whenever the user asks about access control, authorization, IDOR, privilege escalation, "who can call this endpoint", broken access control, role checks, permission_callback, capability checks, or wants the authz review part of a source audit, since scanners rarely catch missing authorization and this needs a deliberate method.
---

# Authorization Matrix Audit

Missing or inconsistent authorization is one of the most common high-value bugs in web apps, and static scanners largely miss it: no rule can know that `/export` was *supposed* to require admin. The method is to write down, for every entry point, who should reach it and what the code actually enforces, then look at the gaps.

## Workspace contract
Read first: `AGENTS.md`, `audit/human-context.md`, `audit/scope.md`, `audit/attack-surface.md` (entry points `R-###` and the auth-model section). Write rows to `audit/authz-matrix.md` (format: `references/matrix-format.md`) and create `audit/candidates.md` rows (`origin: authz`, `class: authz`) plus a note in `audit/notes/` for each gap using the candidate template. Log after each route group; tick the checklist item. Cite `path:line` for every enforced check and every gap.

## Scope of one job
One route group (roughly 20-40 handlers that share a router, controller area or plugin module). The orchestrator parallelizes across groups.

## Method

### 1. Establish principals
From the auth-model section, list the principals: anonymous, authenticated user, each role/capability tier, admin, service/API key, other tenants. If the model is unclear or the roles are custom, **ask the human** (batch the questions); otherwise you will "find" bugs against a guessed model.

### 2. Decide the expected principal per route
Use evidence in this order: explicit docs/tests/comments, route naming and placement (`/admin`, `/internal`, `/me`), what the handler does (writes vs reads, touches other users' data, changes config, exposes PII, runs privileged operations), UI placement (menu only shown to admins is a hint, not an enforcement). Mark each expectation `documented`, `inferred`, or `ask-human`.

### 3. Find the enforced check
For each route, trace the actual enforcement and cite it: framework/global default, middleware chain (order and path matchers), decorators/annotations/dependencies, route-level options, in-handler checks, policy/gate classes, base-class constructors. Look *upstream* (reverse proxy or ingress config in the repo, `.htaccess`, nginx conf) and in framework defaults before concluding a check is absent. Use the "Authorization primitives" section of the relevant stack catalog in `../web-vuln-playbooks/references/stacks/`.

### 4. Classify gaps
Compare expected vs enforced and classify with `references/gap-classes.md`:
- missing authentication; missing function-level (vertical) authorization; object-level (horizontal) IDOR/BOLA; tenant/org isolation; mass assignment or writable privilege fields; state/workflow bypass (skipping steps, re-using one-time tokens); client-only enforcement; inconsistent enforcement across alternative paths (REST vs GraphQL, v1 vs v2, batch/export/download endpoints, WebSocket, legacy handlers); method confusion; trusting identity from request headers or body; check performed after the action; default-allow gaps; CSRF nonce used as authorization.

### 5. Test each gap against false-positive traps
Before logging a candidate: is there upstream enforcement you missed? Is the data public by design? Is the "object ID" actually unguessable *and* never leaked (still a bug if leaked elsewhere, note it)? Is the role requirement already equivalent to the impact (admin-only bug that grants admin)? Does program scope exclude it? Record your answer in the note.

### 6. Output and stop
Rows into the matrix, candidates for confirmed gaps with the impact in one line ("any logged-in user can read any other user's private messages"), and open questions for the human. Return to the orchestrator; do not judge severity beyond the gap class.

## Rules
- Every matrix row has both columns filled: expected principal (with basis) and enforced check (with `file:line`, or `none found` plus where you looked).
- "Not found" is a claim: list the places searched.
- Distinguish authentication (who are you) from authorization (are you allowed) from CSRF/nonce (did this browser session intend it).
- Object-level checks are the most-missed: for every handler taking an object ID, show where ownership or tenant scoping is applied to the query or the loaded object.
- Do not send requests. Everything is static; propose dynamic checks for later phases only.

## Files
- `references/matrix-format.md`: matrix columns and example rows.
- `references/gap-classes.md`: gap classes with what to look for and common false positives.
