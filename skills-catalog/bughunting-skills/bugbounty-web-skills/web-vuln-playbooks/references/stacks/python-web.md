# Python Web (Flask, Django/DRF, FastAPI): Source/Sink Catalog

Contents: sources, sinks, gotchas, authorization primitives, config pitfalls, grep seeds. Confirm framework version behavior when it matters.

## Sources
- Flask: `request.args/form/values/json/get_json()/data/files/cookies/headers/view_args`, URL converters.
- Django: `request.GET/POST/body/FILES/COOKIES/META/headers`, URL kwargs, DRF `request.data/query_params`.
- FastAPI: path/query/header/cookie/body parameters; Pydantic models. Type annotations validate and coerce types (an `int` parameter is a genuine constraint for SQL positions); `str`/`dict`/`Any` are not.
- Stored data, environment variables from tenant config, file contents uploaded by users.

## Sinks and safe counterparts
| class | sink / pattern | safe counterpart / notes |
|-------|----------------|--------------------------|
| SQL | `cursor.execute(f"...")`, `%`/`.format`/`+` building, SQLAlchemy `text(f"...")`, Django `.raw()`, `.extra()`, `RawSQL`, `cursor.execute` with interpolated identifiers | bound parameters (`execute(sql, params)`, `text(...).bindparams`), ORM filters; allowlist identifiers/ordering |
| ORM abuse | `Model.objects.filter(**request.GET.dict())` (attacker picks lookups such as relation traversals and `__startswith`, enabling data leaks), `.order_by(request.GET['sort'])` with relation traversal, `Model(**data)` / `update(**data)` | allowlist fields and lookups |
| Command | `os.system`, `subprocess.*(..., shell=True)`, string commands, `os.popen`, `commands` equivalents | `subprocess.run([...])` without a shell; validate args; `--` separator |
| Code exec | `eval`, `exec`, `compile`, `__import__`/`importlib` with input, `getattr` chains on input | allowlist |
| Deserialization | `pickle.loads/load`, `marshal`, `shelve`, `yaml.load` with non-safe loader, `jsonpickle`, `dill` | `yaml.safe_load`, JSON, signed data with secret keys |
| Templates | `render_template_string(user)`, `jinja2.Template(user)`, `Environment().from_string(user)`, Django `Template(user)`, `mark_safe`, `|safe`, `{% autoescape off %}` | variables only; sandboxed environments (know the limits) |
| File | `open(user_path)`, `send_file(user_path)`, `os.path.join(base, user)` (an absolute second argument discards `base`), `pathlib.Path(base) / user` (same), `tarfile.extractall`, `zipfile.extractall`, `shutil` ops | `send_from_directory`, `werkzeug.utils.secure_filename` (names only), canonicalize with `resolve()` and compare to base; extraction with per-member checks or extraction filters on supporting Python versions |
| SSRF | `requests.get(user_url)`, `urllib.request.urlopen`, `httpx`, `aiohttp`, `urlretrieve` | host allowlist, resolved-IP checks with pinned connections, redirects disabled |
| Redirect | `redirect(request.args['next'])`, `HttpResponseRedirect(user)` | `url_has_allowed_host_and_scheme` (Django), exact allowlist |
| XML | `lxml.etree` with `resolve_entities` or network enabled, `xml.dom.minidom`/`xml.sax` older defaults, `xmltodict` on untrusted XML | `defusedxml`, parser flags |
| JWT | `jwt.decode(token, options={"verify_signature": False})`, missing `algorithms=[...]`, shared secret defaults | fixed algorithm list, verified claims (`exp`, `aud`, `iss`) |

## Sanitizer gotchas
- Binding protects values only; identifiers, `ORDER BY`, and `LIMIT` need allowlists.
- Pydantic/type hints are constraints only for the declared type; check `Any`, `dict`, `Union` and custom validators.
- Django auto-escapes templates; `mark_safe`, `|safe`, `format_html` misuse, and JSON-in-script placements are the usual bypasses. Jinja2 in Flask autoescapes only for certain template extensions (`.html`, `.htm`, `.xml`, `.xhtml`) and not for strings rendered via `render_template_string` unless configured; verify.
- `secure_filename` can return an empty or surprising name; do not use it for paths.

## Authorization primitives
- Flask: decorators (`@login_required` from Flask-Login or custom), `before_request` hooks (check scope/order and path exemptions), blueprint-level hooks; `session` is a signed client-side cookie, so a leaked or hard-coded `SECRET_KEY` allows forging sessions.
- Django: `@login_required`, `@permission_required`, `LoginRequiredMixin`, `PermissionRequiredMixin`, middleware; `@csrf_exempt` removes CSRF protection; admin site exposure; object-level scoping via `get_queryset()` filtering by the user. DRF: `permission_classes` per view and global `DEFAULT_PERMISSION_CLASSES` (when unset, the default permits any request); `has_object_permission` runs only when `get_object()` is used; serializers with `fields = '__all__'` can expose or accept sensitive fields; `ModelViewSet` exposes every action unless restricted.
- FastAPI: `Depends(...)` per route or `dependencies=[...]` on routers/apps; a route lacking the dependency is public; object-level checks must be in the handler or a dependency using the path parameter; `response_model` controls data exposure; CORS middleware settings (`allow_origins`, `allow_credentials`).
- Common wrong checks: UI-only restrictions; checking `request.user.is_authenticated` and nothing else; trusting a user ID from the body or query; role checked on list but not detail endpoints.

## Config pitfalls
`DEBUG=True` in deployed config, hard-coded `SECRET_KEY`/JWT secrets, `ALLOWED_HOSTS = ['*']` with host-header-derived links, `app.run(debug=True)` (Werkzeug debugger), permissive CORS with credentials, verbose error pages, default admin credentials, `/docs` and `/openapi.json` exposure of internal routes, unsafe `pickle`-based session or cache backends.

## Grep seeds
```bash
rg -n 'request\.(args|form|values|json|get_json|data|files|cookies|headers|GET|POST|body|META)' --glob '*.py'
rg -n 'execute\(\s*f?["'"'"']|\.raw\(|\.extra\(|RawSQL|text\(f' --glob '*.py'
rg -n 'subprocess\.|os\.system|os\.popen|shell\s*=\s*True' --glob '*.py'
rg -n '\beval\(|\bexec\(|pickle\.loads?|yaml\.load\(|marshal\.loads?' --glob '*.py'
rg -n 'render_template_string|Template\(|mark_safe|\|safe|autoescape' --glob '*.py' --glob '*.html'
rg -n 'requests\.(get|post|request)|urlopen\(|httpx\.|aiohttp' --glob '*.py'
rg -n 'send_file|send_from_directory|open\(|os\.path\.join|extractall' --glob '*.py'
rg -n 'login_required|permission_classes|Depends\(|csrf_exempt|@app\.(route|get|post)|include_router' --glob '*.py'
rg -n 'SECRET_KEY|DEBUG\s*=|ALLOWED_HOSTS|verify_signature|algorithms' --glob '*.py'
```
