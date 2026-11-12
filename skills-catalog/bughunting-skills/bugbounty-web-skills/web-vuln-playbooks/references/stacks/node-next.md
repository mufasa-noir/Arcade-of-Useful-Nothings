# Node.js (Express/Fastify) and Next.js: Source/Sink Catalog

Contents: sources, sinks, gotchas, Next.js specifics, authorization primitives, config pitfalls, grep seeds. Confirm framework version behavior when it matters.

## Sources
- Express/Fastify/Koa: `req.query`, `req.body`, `req.params`, `req.headers`, `req.cookies`, `req.files`, `req.hostname`/`req.get('host')`, `x-forwarded-*` headers, WebSocket messages, GraphQL arguments.
- Body parsers can produce **objects and arrays**, not just strings (`qs` extended parsing of `a[b]=c`, JSON bodies). Code that assumes strings is vulnerable to operator and type confusion.
- Next.js: `searchParams`, `params`, `cookies()`, `headers()`, `FormData` in server actions, `request.json()` in route handlers, `context.query` in `getServerSideProps`, middleware request data.
- Stored data and third-party API responses rendered or used later.

## Sinks and safe counterparts
| class | sink / pattern | safe counterpart / notes |
|-------|----------------|--------------------------|
| SQL | template literals or concatenation into `db.query`, `knex.raw`, `sequelize.query` without `replacements`/`bind`, Prisma `$queryRawUnsafe`/`$executeRawUnsafe` | parameterized queries (`$1`/`?`), Prisma tagged `$queryRaw`, ORM filters; allowlist identifiers |
| NoSQL | `Model.find(req.body)`, `find({ user: req.body.user })` where value can be an object (`{"$ne": null}`, regex, `$where`), `$expr` | validate types (strings only), `mongo-sanitize`-style stripping of `$` keys, schema validation |
| Command | `child_process.exec/execSync` (shell), `spawn(..., {shell:true})` | `execFile`/`spawn` with args array and no shell; validate args; `--` |
| Code exec | `eval`, `new Function`, `vm.runIn*` (not a security boundary), `require(userInput)`/dynamic `import()`, `setTimeout(string)` | allowlist; no dynamic code from input |
| Template | `ejs.render(userString)`, `pug.compile(user)`, `handlebars.compile(user)`, `lodash.template(user)`, user-controlled render options (EJS option pollution via query/body), React `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `bypassSecurityTrustHtml` | variables only; sanitize with DOMPurify at output; do not pass `req.query` objects as template options |
| Prototype pollution | recursive merge/extend/clone/`set(path, value)` with attacker keys (`__proto__`, `constructor.prototype`) via lodash-style utilities (older versions), custom merge helpers, `Object.assign` onto prototypes via JSON.parse reviver patterns | key allowlists, `Object.create(null)`, patched versions; identify a concrete gadget (options objects, `isAdmin`-style checks, child-process or template options) |
| File | `fs.*` with variable paths, `path.join(base, user)` (does not prevent `..`), `res.sendFile(user)` (needs `root` option and validation), `express.static` with unusual config, `unzipper`/`adm-zip`/`tar` extraction (zip-slip) | `path.resolve` then verify `startsWith(base + path.sep)`; per-entry extraction checks; `sendFile` with `root` and `dotfiles: 'deny'` |
| SSRF | `fetch`, `axios`, `got`, `node-fetch`, `http.request` with user URL; link previews, webhooks, image proxies; Next.js `images.remotePatterns/domains` too broad; `rewrites` to attacker-influenced destinations | host allowlist, resolved-IP checks with pinned connection, redirect limits |
| Redirect | `res.redirect(req.query.next)`, `NextResponse.redirect(user)`, `router.push(user)`, `window.location = user` | relative-path or exact-allowlist validation |
| Deserialization | `node-serialize`, `serialize-javascript` misuse, `js-yaml` unsafe types in old versions, `vm`-based sandboxes | JSON; `yaml` safe schema |
| JWT/session | `jwt.decode` used instead of `jwt.verify`, missing `algorithms`, hard-coded secrets, `none` handling, long-lived tokens, session cookies lacking flags | `jwt.verify` with fixed algorithms and claim checks |
| ReDoS | catastrophic regexes on user input | usually low severity; note only if DoS is in scope |

## Next.js specifics
- **Server actions** (`'use server'`): each exported action is reachable as an HTTP POST endpoint; authentication and authorization must be inside the action, using the session, never relying on being "only called from an authenticated page". Arguments are attacker-controlled.
- **Route handlers** (`app/**/route.ts`) and **API routes** (`pages/api/**`): check method handling (a handler that accepts all methods), body validation, auth per handler.
- **Middleware** (`middleware.ts`): check the `matcher`: paths not matched are unprotected (`/api` variants, trailing slashes, static asset exceptions). Authorization performed only in middleware is a recurring weak pattern; a known example is a 2025 middleware authorization bypass in Next.js (CVE-2025-29927, via an internal subrequest header); check the framework version and whether sensitive routes re-check authorization in the handler.
- **Server components**: data fetched server-side must be authorized per request; caching (`fetch` cache, `unstable_cache`, ISR/static generation) can serve one user's data to another if the cache key lacks the user; check `cookies()`/`headers()` usage and dynamic rendering.
- **Environment exposure**: variables prefixed `NEXT_PUBLIC_` are bundled into client code; secrets there are public. Check `next.config.js` `env` and client components importing server-only modules.
- **Client components**: `dangerouslySetInnerHTML`, `href={userValue}` (allows `javascript:`), embedding JSON in `<script>` without escaping `<`.
- **Image optimizer / rewrites / headers** in `next.config.js` as SSRF and cache-poisoning surface.
- **Source maps**: production source maps (`productionBrowserSourceMaps`) expose original source and sometimes hidden routes.

## Authorization primitives
- Express: middleware order matters (auth middleware must be registered **before** the routes it protects); router-level `router.use(auth)` vs per-route middleware; `app.use('/admin', adminRouter)` mounted without auth; role checks in handlers; JWT payload claims trusted without server-side confirmation; object-level scoping by `req.user.id` in queries (absent scoping means IDOR).
- Fastify: hooks (`onRequest`/`preHandler`) and plugin encapsulation: a hook registered inside a plugin applies only to that plugin's scope.
- GraphQL: authorization at resolver/field level, not just at the endpoint; introspection and batching/alias abuse are separate concerns.
- Next.js: see specifics above; use `getServerSession`/auth helper inside every handler and action.
- Common wrong checks: client-side role checks, `req.body.userId` instead of session identity, checks that run after the mutation, `if (user)` without role/ownership.

## Config pitfalls
`cors({ origin: true, credentials: true })` or reflected origins, `app.disable('x-powered-by')` (cosmetic), missing `helmet`-style headers (usually excluded), `express.static` serving the project root or dotfiles, committed `.env`, debug routes, verbose error handlers returning stack traces, `trust proxy` misconfiguration affecting IP-based controls, cookie flags unset.

## Grep seeds
```bash
rg -n 'req\.(query|body|params|headers|cookies)|searchParams|request\.json\(|formData\(' --glob '*.{js,ts,tsx,jsx}' --glob '!node_modules'
rg -n "'use server'|\"use server\"" --glob '*.{js,ts,tsx,jsx}'
rg -n 'child_process|\bexec(Sync)?\(|spawn\(|\beval\(|new Function|vm\.' --glob '*.{js,ts}' --glob '!node_modules'
rg -n '\$queryRawUnsafe|\$executeRawUnsafe|\.raw\(|\.query\(\s*`|sequelize\.query' --glob '*.{js,ts}'
rg -n 'dangerouslySetInnerHTML|innerHTML|v-html|bypassSecurityTrust' --glob '*.{js,ts,tsx,jsx,vue}'
rg -n '\b(merge|extend|defaultsDeep|set)\(|__proto__|constructor\.prototype' --glob '*.{js,ts}' --glob '!node_modules'
rg -n 'fetch\(|axios\.|got\(|http\.request|remotePatterns|domains:' --glob '*.{js,ts,tsx,mjs}'
rg -n 'jwt\.(decode|verify|sign)|jsonwebtoken|algorithms' --glob '*.{js,ts}'
rg -n 'res\.redirect|NextResponse\.redirect|sendFile|path\.join|createReadStream' --glob '*.{js,ts}'
rg -n 'matcher|middleware' --glob 'middleware.*' --glob 'next.config.*'
rg -n 'NEXT_PUBLIC_|process\.env\.' --glob '*.{js,ts,tsx}'
```
