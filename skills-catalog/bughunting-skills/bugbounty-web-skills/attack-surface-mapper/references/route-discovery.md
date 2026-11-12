# Route and Entry-Point Discovery by Framework

Contents: WordPress/bbPress, generic PHP, Laravel, Express/Fastify/Koa, Next.js, Flask/Django/FastAPI, Spring, Rails, plus non-HTTP entry points.
Use these as search seeds with `rg`; confirm by reading the registration code. If counts look low, hunt for a custom registration mechanism (dynamic route tables, plugin loaders, reflection).

## WordPress / bbPress plugins
- Unauthenticated + authenticated AJAX: `add_action( 'wp_ajax_nopriv_<x>'` (reachable without login), `add_action( 'wp_ajax_<x>'` (any logged-in user, not only admins). Both resolve through `admin-ajax.php`.
- REST: `register_rest_route(` and check each `permission_callback` (missing, `__return_true`, or only a login check are leads).
- Form handlers: `admin_post_nopriv_`, `admin_post_`, handlers on `init`, `template_redirect`, `wp_loaded`, `parse_request` that read `$_POST`/`$_GET`/`$_REQUEST` directly.
- Shortcodes (`add_shortcode`) and blocks (`register_block_type`) take attacker-influenced attributes if content authors are not fully trusted.
- Query vars and rewrite rules: `add_rewrite_rule`, `query_vars` filter, `get_query_var`.
- Others: XML-RPC, cron callbacks reading stored data (`add_action` on custom events), `wp_enqueue_script` + `wp_localize_script` (data into JS), widgets, settings pages (`register_setting` sanitize callbacks), file upload handlers (`wp_handle_upload`, `$_FILES`).
- bbPress specifics (verify against your checked-out version): post-request routing through bbPress action hooks keyed off request data, `bbp_*` capability checks and nonce helpers, forum/topic/reply post types and their visibility statuses (public/private/hidden), subscription/favorite actions, topic/reply edit, move, merge, split actions, BuddyPress integration surfaces.

## Generic PHP
Front controllers (`index.php`, `.htaccess` rewrites), files directly reachable under the web root (every `.php` file without a guard is an entry point), includes chosen by a parameter, `$_SERVER['PATH_INFO']`/`REQUEST_URI` routing.

## Laravel
`routes/web.php`, `routes/api.php`, `Route::` groups with `middleware([...])`, `Route::resource`, controller constructors with `$this->middleware(...)`, `Gate::`/policies, `FormRequest::authorize()`, `$request->all()` into `create/update` (mass assignment, check `$fillable`/`$guarded`).

## Express / Fastify / Koa (Node)
`app.get|post|put|patch|delete|all|use(`, `router.<verb>(`, `app.use('/prefix', router)` mounts, middleware order (auth middleware declared AFTER a route does not protect it), `fastify.register`, `fastify.route`, plugin prefixes, WebSocket (`ws`, `socket.io` `on('event'`), GraphQL resolvers (every resolver is an entry point; check field-level auth).

## Next.js
- Pages router: `pages/api/**` handlers (check HTTP method handling), `getServerSideProps` (reads `context.query/params/req`).
- App router: `app/**/route.ts` handlers (exported `GET/POST/...`), `app/**/page.tsx` server components reading `searchParams`/`params`, **server actions** (`'use server'`): each is a publicly callable POST endpoint, auth must be inside the action.
- `middleware.ts` and its `matcher`: note which paths it covers and what it enforces; auth only in middleware is a weak pattern.
- `next.config.js`: `rewrites`, `redirects`, `images.remotePatterns/domains` (SSRF surface), `headers`, `env`/`NEXT_PUBLIC_*` (secrets exposed to the client).

## Flask / Django / FastAPI
- Flask: `@app.route(`, `@bp.route(`, `app.register_blueprint(`, `before_request` hooks, `add_url_rule`.
- Django: `urls.py` (`path(`, `re_path(`, `include(`), views (function or class-based), DRF `ViewSet`/`router.register`, `permission_classes` and the global `REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']`, `@csrf_exempt`, admin site registration.
- FastAPI: `@app.get|post(...)`, `APIRouter` + `app.include_router(..., dependencies=[...])`, `Depends(...)` on each route (a route without the auth dependency is public), WebSocket routes, background tasks, mounted sub-apps (`app.mount`).

## Spring (Java)
`@RestController`/`@Controller` with `@RequestMapping|GetMapping|PostMapping...`, `@PathVariable/@RequestParam/@RequestBody`, security config (`SecurityFilterChain`, `requestMatchers/antMatchers`, `permitAll`), `@PreAuthorize/@Secured` and whether method security is enabled, servlet `@WebServlet`/filters, Actuator endpoints, WebSocket/STOMP handlers.

## Rails
`config/routes.rb` (`resources`, `namespace`, `match`, `mount`), controllers with `before_action` (check `only/except` lists and `skip_before_action`), `params.permit`/strong parameters, `protect_from_forgery` exceptions, Active Storage routes.

## Non-HTTP entry points to include
Job/queue consumers, webhooks (signature verified?), CSV/XML/JSON/zip importers, email ingestion, file watchers, OAuth/SSO callbacks, deep links and postMessage handlers in client code, CLI commands that read user-stored data.
