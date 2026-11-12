# Injection (SQL, NoSQL, OS command, LDAP, header/CRLF)

**Root cause:** attacker data is interpreted as syntax by an interpreter (query engine, shell, directory, HTTP parser) because it was concatenated or interpolated instead of passed through a channel that keeps data and code apart.

## What the sink looks like
- SQL: query strings built by concatenation, interpolation, `format`, `%`, template literals, then passed to `query/execute/raw`.
- NoSQL: request body objects passed straight into query filters (operator injection such as comparison/regex/`$where` operators), string-built JS queries.
- Command: shell invoked with a string containing input (`system`, `exec`, `shell=True`, `child_process.exec`), or argument injection into tools via input starting with `-`.
- LDAP/XPath/GraphQL-to-backend: filter strings assembled from input.
- Header/CRLF: input placed into response headers, redirect `Location`, mail headers, or log lines.

## Safe vs unsafe
- Safe for values: parameterized queries with bound parameters; ORM filters with plain values.
- Unsafe: binding does not protect **identifiers** (column names, table names, `ORDER BY`, `LIMIT`), operators, or `LIKE` wildcard semantics. These need allowlists.
- `IN (...)` lists: building placeholders correctly is safe; joining raw values is not.
- Escaping functions (database-specific string escapes) only protect *quoted string* positions; they do nothing for unquoted numeric positions or identifiers.
- Command: array-argument APIs without a shell (`execFile`, `subprocess.run([...])`) are safe from shell metacharacters, but input beginning with `-` can still become an option; use `--` where supported and validate.

## Control correctness
Integer cast or strict schema type before use (genuine control); allowlist of identifiers (genuine); blocklists of quotes/keywords (bypassable); HTML escaping or tag stripping (irrelevant for SQL/shell); WAF (not in the repo, do not count on it).

## Reachability and impact
Unauthenticated or low-privilege reachability and read of sensitive data/credentials is high value; blind (boolean/time) variants still count; writes and stacked statements depend on driver settings. Second-order: stored value later concatenated into a query by a different route.

## Review questions
- Is the variable part a value, an identifier, or an operator?
- Where is each concatenated piece sourced? Any copy that skipped the sanitizer?
- Is there a prepared form elsewhere in the same file (a sign this one is a mistake, not a design)?
- For NoSQL: can the attacker send an object or array instead of a string? Is the type enforced?
- For command: is a shell involved? Can input start with `-`? Is the binary path or environment attacker influenced?

## False-positive traps
Value cast to int earlier; value from a constant or enum; value only from admin-only code and scope excludes it; ORM-bound query that merely *looks* concatenated (read the builder); dead or test code.

## Variant ideas
Same helper used in other queries; sort/filter/search/export/report parameters; batch endpoints; stored values (profile fields, options) interpolated later; import features; REST vs AJAX duplicates of the same query.
