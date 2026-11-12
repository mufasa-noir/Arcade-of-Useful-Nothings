---
name: web-vuln-playbooks
description: Reference library for white-box web vulnerability review. Lean per-class cards (injection, XSS, SSRF and redirects, file/path/upload/archive, deserialization/eval/SSTI, authn/session/JWT/secrets, CSRF/CORS, logic/race/mass assignment, XXE/parsers) and per-stack source/sink catalogs (PHP/WordPress/bbPress, Python Flask/Django/FastAPI, Node/Express/Next.js, Java/Spring) with sink names, safe counterparts, sanitizer gotchas, authorization primitives and grep seeds. Load the specific card and stack file when tracing a flow, mapping dangerous capabilities, judging a sanitizer, or reviewing authorization in a codebase; do not load everything.
---

# Web Vuln Playbooks

This is a knowledge skill, not a workflow. Other skills (`source-sink-tracer`, `authz-matrix-audit`, `attack-surface-mapper`, `candidate-triage`, `patch-variant-hunt`) pull from it. It is deliberately lean: one card per vulnerability *family* rather than one skill per class, because the method is the same (find a source, a sink and the controls between them) and only the vocabulary changes.

## How to use
1. Identify the stack from `audit/attack-surface.md` or the manifests. Read the matching file in `references/stacks/`.
2. Identify the vulnerability family you are testing. Read the matching card in `references/classes/`.
3. Read only those two. Return to this index if the flow crosses families (e.g., SSRF into deserialization).

## Class cards (`references/classes/`)
- `injection.md`: SQL, NoSQL, OS command, LDAP, header/CRLF, expression injection into queries.
- `xss.md`: reflected, stored, DOM, template-context and URL-scheme issues.
- `ssrf-redirect.md`: server-side request forgery and open redirects.
- `file-path-upload.md`: path traversal, arbitrary file read/write, uploads, archive extraction.
- `deserialization-eval-ssti.md`: unsafe deserialization, dynamic code evaluation, server-side template injection, prototype pollution.
- `authn-session-jwt.md`: authentication, sessions, tokens, JWT, password reset, secrets.
- `csrf-cors.md`: CSRF, CORS, cookie settings, clickjacking.
- `logic-race-massassign.md`: business logic, races, mass assignment, workflow bypass.
- `xxe-parsers.md`: XML external entities and parser abuse (XML, YAML, CSV, archives, regex DoS note).

Authorization is covered by `authz-matrix-audit` (method) plus the "Authorization primitives" section of each stack file.

## Stack catalogs (`references/stacks/`)
- `php-wordpress.md`: PHP and WordPress/bbPress plugin specifics.
- `python-web.md`: Flask, Django/DRF, FastAPI.
- `node-next.md`: Express/Fastify, Next.js (pages, app router, server actions, middleware).
- `java-spring.md`: Spring MVC/Boot, Spring Security, common Java sinks.
- `_template.md`: copy this to add a stack (Rails, Laravel, Go, .NET, ...), then add a line above.

## Class card format (use when adding cards)
Root cause; what the sink looks like; safe vs unsafe forms; control correctness by context; reachability and impact conditions; review questions; false-positive traps; variant ideas. Keep each card under ~80 lines.

## Reliability note
Entries are starting points from general knowledge of these ecosystems. Framework behavior changes between versions; when a decision depends on exact behavior (a default, a function's escaping rules, a CVE), confirm in the checked-out dependency source or official docs and say so in the note.
