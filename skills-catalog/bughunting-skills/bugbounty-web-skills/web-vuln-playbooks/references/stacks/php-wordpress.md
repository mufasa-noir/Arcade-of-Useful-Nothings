# PHP and WordPress / bbPress Plugins: Source/Sink Catalog

Contents: sources, sinks, safe counterparts and gotchas, authorization primitives, bbPress notes, config pitfalls, grep seeds. Items are starting hypotheses; confirm behavior in the checked-out WordPress/PHP versions.

## Sources
- Superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER` (`REQUEST_URI`, `PHP_SELF`, `HTTP_HOST`, `HTTP_REFERER`, `HTTP_USER_AGENT`, `HTTP_X_FORWARDED_FOR`), `php://input`.
- WordPress wrappers: `get_query_var`, `WP_REST_Request` (`get_param`, `get_json_params`, `get_body_params`, `get_url_params`, `get_header`), shortcode attributes and content, block attributes.
- Stored (second-order): `get_option`, `get_post_meta`, `get_user_meta`, post content/title/excerpt, comment fields, transients, term names, custom DB tables. Anything an unprivileged user can write that another route later reads is a source for the read-time sink.
- Note: WordPress adds slashes to superglobals; `wp_unslash` removes them. Mishandling this affects escaping logic and can create inconsistencies.

## Sinks and safe counterparts
| class | sink / pattern | safe counterpart / notes |
|-------|----------------|--------------------------|
| SQL | `$wpdb->query/get_results/get_var/get_row/get_col` with interpolated or concatenated input | `$wpdb->prepare()` with `%s/%d/%f` placeholders; still unsafe for identifiers and `ORDER BY`/`LIMIT` fragments (allowlist them) |
| SQL gotchas | `prepare()` with interpolated pieces inside the format string; `IN (...)` built with `implode` of raw values; `LIKE` without `esc_like`; `esc_sql` on unquoted numeric positions or identifiers; double-prepare confusion | Build placeholders list for `IN`; cast ints with `absint`; use `$wpdb->esc_like` + prepare for LIKE |
| XSS (server) | `echo`/`print` of request or stored data without escaping; `printf` with raw args; `add_query_arg`/`remove_query_arg` results echoed unescaped; `$_SERVER['PHP_SELF']`/`REQUEST_URI` in forms/links | `esc_html`, `esc_attr`, `esc_url` (for output URLs), `esc_url_raw` (storage/redirects), `esc_js`, `wp_kses`/`wp_kses_post` allowlists; match the escaper to the context |
| XSS (JS bridge) | `wp_localize_script` / inline `<script>` JSON with unescaped values; admin notices echoing request data | `wp_json_encode` with proper flags and `wp_add_inline_script`; escape per context |
| Command | `exec`, `system`, `passthru`, `shell_exec`, backticks, `popen`, `proc_open`, `mail()` additional parameters | `escapeshellarg`/`escapeshellcmd` have known limits; prefer no shell and fixed args |
| Code exec | `eval`, `assert` (older PHP), `create_function` (removed in PHP 8), `preg_replace` with the `/e` modifier (removed in PHP 7), `include/require` with variable paths, `call_user_func(_array)` with attacker-chosen callable, variable functions, `extract()`/`parse_str()` without result array (variable overwrite) | constants and allowlists |
| Deserialization | `unserialize`, `maybe_unserialize` on user or stored-user data; file functions on user-controlled paths accepting `phar://` (in PHP versions before 8.0 phar metadata deserialization could be triggered) | JSON; `allowed_classes => false`; confirm PHP version |
| File | `include/require`, `file_get_contents`, `readfile`, `fopen`, `unlink`, `copy`, `rename`, `move_uploaded_file`, `ZipArchive::extractTo` with variable paths | canonicalize with `realpath` and compare to base; `sanitize_file_name` is for names, not a traversal defense for paths; per-entry zip checks |
| Upload | `wp_handle_upload` with overridden `mimes` or `test_type => false`, custom handlers saving `$_FILES['x']['name']`; `.htaccess` uploads | `wp_check_filetype_and_ext`, extension allowlist on the final name, store outside executable paths |
| SSRF | `wp_remote_get/post/request`, `file_get_contents(url)`, cURL, `download_url`, `getimagesize(url)` | `wp_safe_remote_*` and `wp_http_validate_url` provide partial protection; verify exact behavior and DNS rebinding handling; use host allowlists |
| Redirect | `wp_redirect($input)`, header `Location` from input | `wp_safe_redirect` with allowed hosts filter; confirm it is applied to the final URL |
| XXE | `simplexml_load_*`, `DOMDocument::load*`, `XMLReader` with entity loading enabled | disable DTD/entity substitution explicitly; check PHP/libxml versions |
| Type juggling | `==` between strings (e.g. `"0e123" == "0e456"`), `strcmp` with arrays, `in_array`/`array_search` loose, `switch` loose comparisons, `md5($x) == "0e..."` | `===`, `hash_equals`, strict `in_array(..., true)` |

## Sanitizer gotchas
- `sanitize_text_field` strips tags and normalizes whitespace; it is not an SQL control and not a substitute for output escaping.
- `esc_html` in an attribute value without quotes, `esc_attr` inside JavaScript, `esc_html` inside `href` (does not block `javascript:`) are context errors; `esc_url` blocks dangerous schemes for output.
- `intval`/`absint`/`(int)` cast is a real control for numeric positions.
- `wp_kses` is only as strict as the allowed-tags array; check custom arrays and filters that expand them.
- Escape late (at output), validate early. Escaping at write time and then rendering in a different context is a recurring mistake.

## Authorization primitives
- Authentication: `is_user_logged_in()` (identity only, not privilege); `wp_get_current_user()`.
- Authorization: `current_user_can( 'capability' )` or with an object (`current_user_can( 'edit_post', $post_id )`) for object-level checks. A handler doing a state change with no `current_user_can` is a lead.
- CSRF: `check_ajax_referer`, `check_admin_referer`, `wp_verify_nonce`. Nonces are **not** authorization. Check `check_ajax_referer`'s third argument (die behavior) and whether the result is acted upon (`wp_verify_nonce` returns false/1/2).
- `is_admin()` is **not** an authorization check; it reports whether the request targets an admin screen and is true for `admin-ajax.php` requests from anonymous users.
- Unauthenticated entry points: `wp_ajax_nopriv_*`, `admin_post_nopriv_*`, `register_rest_route` with missing/permissive `permission_callback` (`__return_true`), handlers on `init`/`wp_loaded` reading request data.
- REST: `permission_callback` must verify capability and object access; arguments' `validate_callback`/`sanitize_callback` are not authorization.
- Privilege fields: `wp_update_user`/`update_user_meta` with request-controlled `role` or `wp_capabilities`; options pages that accept arbitrary option names (`update_option($_POST['name'], ...)`).
- Object access: custom queries returning private/draft/hidden posts without status or capability filters; `get_post($id)` followed by output without `current_user_can('read_post', $id)`.

## bbPress notes (verify against the checked-out version)
- Content types: forums, topics, replies with visibility statuses (public/private/hidden) and moderation states (spam, trash, closed, pending); check that every read/list/search/feed/REST/AJAX path applies status and capability filters consistently.
- Roles/capabilities: bbPress defines its own forum roles and `bbp_*` capabilities; compare each action handler's required capability with what the UI implies; check cases where WordPress roles map into forum roles.
- Request handling: bbPress routes many form submissions through its own action hooks keyed by request data; review the handlers for nonce verification, capability checks, and the object-level checks (can this user edit/move/merge/split/subscribe *this* topic).
- Integrations: BuddyPress/theme compatibility files and shortcodes are extra surface; shortcode attributes reach output.
- Stored content: titles, content, tags, revision logs, and user-visible metadata displayed in other contexts (admin lists, emails, notifications, feeds); trace write-time filters (`bbp_new_*_pre_*` style filters, kses) against the read-time contexts.

## Config and hardening pitfalls
`display_errors` on, debug logging to a web-readable path, backup/zip files in plugin directories, `phpinfo()` files, direct-access guards missing (files executable by URL without `defined('ABSPATH') || exit;` matter only if they do something harmful when run directly), `allow_url_fopen`/`allow_url_include`, upload directory execution.

## Grep seeds
```bash
rg -n '\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b' --glob '*.php' --glob '!vendor'
rg -n 'wp_ajax_nopriv_|admin_post_nopriv_|register_rest_route|permission_callback|__return_true' --glob '*.php'
rg -n '\$wpdb->(query|get_results|get_var|get_row|get_col)\(' --glob '*.php'      # then check for prepare()
rg -n '\bprepare\(' --glob '*.php'                                               # review format strings
rg -n 'unserialize\(|maybe_unserialize\(|eval\(|assert\(|create_function|extract\(|parse_str\(' --glob '*.php'
rg -n '\b(exec|system|passthru|shell_exec|popen|proc_open)\(' --glob '*.php'
rg -n 'wp_remote_(get|post|request)\(|file_get_contents\(|curl_init|download_url\(' --glob '*.php'
rg -n 'wp_redirect\(|header\(\s*.Location' --glob '*.php'
rg -n 'current_user_can\(|check_ajax_referer\(|wp_verify_nonce\(|check_admin_referer\(' --glob '*.php'   # absence in a handler matters
rg -n '(include|require)(_once)?\s*\(?\s*\$' --glob '*.php'
rg -n 'update_option\(\s*\$|wp_update_user\(|set_role\(|add_role\(' --glob '*.php'
```
