# Authorization Gap Classes

For each: what to look for, then common false positives.

## Missing authentication
Handlers reachable without identity that read or change non-public data. Look for: unauthenticated hook registrations (e.g. WordPress `wp_ajax_nopriv_`, REST routes with permissive or absent `permission_callback`), routes outside the auth middleware group, routes mounted before auth middleware, default-allow permission settings (DRF without default permission classes), files directly reachable under the web root. FP: genuinely public endpoints (login, public listing), webhooks verified by signature (check the signature check is real).

## Function-level (vertical) authorization
A lower-privileged principal can call a privileged function. Look for: authentication check without a role/capability check, role checks in the UI but not the handler, admin handlers reachable via a second route or HTTP method, GraphQL mutations without field-level auth, action dispatchers that route by a request parameter and check privilege only for some actions. FP: privilege enforced in a base class or middleware you did not read.

## Object-level (horizontal) IDOR/BOLA
Handler accepts an identifier (id, slug, uuid, filename, token) and loads or mutates the object without verifying the current principal may access *that* object. Look for: `find(id)`/`findById`/`get_post($id)`/`Model.objects.get(pk=...)` with no owner/tenant scoping, authorization checked on the parent but not the child, list endpoints scoped but detail endpoints not, bulk/export/download/preview/thumbnail endpoints, ID taken from the body while the check uses the URL (or reverse). FP: IDs unguessable and never exposed (note leak vectors anyway), object is public by design.

## Tenant / organization isolation
Multi-tenant apps where queries omit the tenant filter or take the tenant from the request. Look for: missing `tenant_id` in raw queries, tenant read from a header/body, caches keyed without tenant, shared storage paths.

## Mass assignment / privileged fields
Request body bound straight into a model or update call so the attacker can set `role`, `is_admin`, `owner_id`, `status`, `price`, `verified`, capability meta, etc. Look for: `Model(**data)`, `update(request.all())`, `fields = '__all__'`, Jackson binding into entities, `wp_update_user` with request-controlled `role`, `Object.assign(obj, req.body)`. FP: allowlisted fields, read-only serializer fields (confirm them).

## State / workflow bypass
Steps that should happen in order (payment, approval, email verification, password reset, 2FA) can be skipped or replayed. Look for: server trusting a client-sent state flag, tokens not bound to user or not invalidated after use, direct calls to a later-step endpoint.

## Client-only enforcement
Authorization appears only in client code (hidden buttons, JS role checks, `NEXT_PUBLIC_` flags). Confirm the server endpoint has no equivalent check.

## Inconsistent enforcement across paths
The same action is exposed via REST and GraphQL, v1 and v2, web and mobile API, bulk and single, legacy handler and new handler, and only some are protected. Build a list of all entry points that reach the same underlying function and compare checks.

## Method confusion and routing quirks
Checks apply to `POST` but the handler also accepts `GET`/`PUT`/`PATCH`; middleware matchers cover `/admin` but not `/admin/` or case variants or alternate prefixes; framework-specific pattern matching differences (trailing slashes, suffix patterns, encoded characters). Read the matcher precisely.

## Trusting request-supplied identity
User id, role, tenant, or "is_internal" taken from headers (`X-User-Id`, `X-Forwarded-*`), cookies not signed, JWT claims not verified (see `authn-session-jwt` card), or hidden form fields.

## Check after action
The state change or data read happens before the permission check, or the check result is ignored (not returned/thrown).

## CSRF nonce mistaken for authorization
A nonce or CSRF token proves the request came from a session that rendered the form, not that the user holds the capability. Handlers that verify only a nonce can be called by any logged-in user who can obtain a nonce (nonces are often exposed to all users on any page).

## Common false-positive traps (all classes)
Upstream enforcement (proxy, middleware, base class); "admin-only" bugs whose impact is already admin; features disabled by default; test/example/dead code; public-by-design data; program scope exclusions.
