# Tracing Playbook

Contents: wrappers and helpers, hooks and callbacks, framework magic, second-order flows, long flows, reading discipline, mini-examples.

## Wrappers and helpers
Open every helper that touches the value. Record what it returns for hostile input, not what its name implies. A `get_param()` that trims and decodes is not a sanitizer; a `clean()` that only strips tags is not an SQL control. If a helper is used in many places, note it once and reference it; if it is flawed, ask whether other call sites have the same flaw (log as new candidates, do not trace them).

## Hooks, events and callbacks
Find registrations (`add_action`/`add_filter`, event emitters, signal handlers, observers, lifecycle callbacks, middleware chains). Determine order and priority; a later hook can undo an earlier sanitization or add data from the request. For string-based callbacks and reflection, grep for the string name and list candidate targets; mark the link `inferred` if you cannot prove which one runs.

## Framework magic
- Request binding: which parameters does the framework put into the handler's arguments or object (mass assignment, nested keys, arrays instead of strings, operators in JSON bodies)?
- ORM: parameter binding applies to values, not identifiers (column names, `ORDER BY`, table names, `LIKE` wildcards), and raw/`text()`/unsafe variants bypass it.
- Templates: auto-escape applies to the template's output context; raw filters, string-rendered templates and context-specific placements (attribute, script, style, URL) need separate analysis.
- Middleware: order and scope. A middleware registered after the route, or with a path matcher that misses variants (trailing slash, case, encoded characters, alternate prefixes), does not protect it.

## Second-order (stored) flows
Two flows, linked: (a) write path: attacker input stored (post content, profile field, option, filename, header logged, imported file); (b) read path: stored value used later in a sink, perhaps by another user or role, perhaps with a different encoding assumption. Escaping at write time is usually the wrong place; check the read-time context. Record both paths and the storage location.

## Long flows
When a flow crosses many files, build a hop table first (file:line, function, what the value is called there), then evaluate controls. If the flow fans out, trace the shortest attacker-reachable branch fully and list the others as branches to assess later. Use Semgrep taint or CodeQL to enumerate flows, then confirm by reading.

## Reading discipline
- Quote less, cite more: `path:line` beats pasting code.
- Read callers, not just callees; a safe-looking function can be called with attacker data from an unexpected route.
- Watch for early returns, error branches, feature flags, and `if (!defined(...))` guards that change reachability.
- Check git blame only when intent is unclear; the code, not the commit message, is the evidence.

## Mini-example (backward trace, PHP)
Starting point: `includes/search.php:88` runs `$wpdb->get_results("SELECT ... WHERE title LIKE '%$term%'")`.
1. Caller: `search.php:61` passes `$term` from `$_GET['q']` after `sanitize_text_field()` (`search.php:58`).
2. Judge control: `sanitize_text_field` strips tags and extra whitespace but does not escape quotes for SQL; wrong control for an SQL value. Fails.
3. Sink: string interpolation into `get_results` without `$wpdb->prepare`; the prepared form exists elsewhere in the file (`search.php:120`).
4. Preconditions: handler registered via `wp_ajax_nopriv_` at `ajax.php:14`; reachable unauthenticated. No nonce check seen (`unverified:` check the filter at `ajax.php:9`).
Assessment: established flow, wrong control; medium-high confidence pending the nonce question; open question for the human: any WAF or custom DB layer that rewrites queries?

## Mini-example (clean negative)
Sink: `db.query('SELECT * FROM users WHERE id = $1', [req.params.id])` (`users.js:30`). Value bound as a parameter; `id` is also cast with `Number()` at `users.js:27`. Control holds for SQL injection. Recommend dismissal for injection; the missing ownership check on this route is an authorization lead, logged as a NEW candidate with `origin: tracer`.
