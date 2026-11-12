# authz-matrix.md format

One table per route group, appended to `audit/authz-matrix.md`.

```markdown
## Group: <name> (routes R-031..R-066, <paths/files>)
Reviewed: <date> by authz-matrix-audit. Principals: anonymous, user, moderator, admin.

| Route | Handler file:line | Action (reads/writes what) | Expected principal (basis) | Enforced check (file:line) | Object scoping (file:line) | Gap? | Candidate |
|-------|-------------------|----------------------------|----------------------------|----------------------------|----------------------------|------|-----------|
| R-031 POST /api/topics/{id}/edit | api/topics.php:112 | edits any topic | owner or moderator (inferred) | login check only: api/topics.php:115 | none found; looked in api/topics.php:112-160, base class, middleware | object-level | C-021 |
| R-032 GET /api/export | api/export.php:20 | dumps all users | admin (inferred; matches /admin placement) | capability check: api/export.php:22 | n/a (global) | no | |

Notes: <ambiguities, questions for the human, places searched for missing checks>
```

Gap column values: `no`, `authn`, `function-level`, `object-level`, `tenant`, `mass-assignment`, `workflow`, `client-only`, `inconsistent`, `method`, `header-trust`, `check-after-action`, `nonce-as-authz`, `unclear`.
