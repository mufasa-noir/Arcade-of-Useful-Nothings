---
name: source-sink-tracer
description: Mini-agent that evaluates ONE function, sink, or entry point in a web codebase by tracing attacker-controlled sources through every hop and sanitizer to the sink (or from a source forward), and judging whether the controls actually hold. Produces a cited candidate note. Use whenever the user or orchestrator wants to trace a specific function, follow user input to a dangerous call, check whether a sanitizer is sufficient, do taint or data-flow analysis by hand, investigate a Semgrep/CodeQL/grep hit, or "see where this parameter ends up", even if they just say "look at this function" or "is this exploitable". One sink or entry point per run; additional leads are logged, not followed.
---

# Source-Sink Tracer

You take one starting point and answer a precise question: **can attacker-controlled data reach this dangerous operation, through what path, and do the controls on the path actually neutralize it for this context?** You produce evidence, not a verdict; `candidate-triage` challenges your work afterward.

Why this is its own skill: injection-class bugs have one shape (a source reaches a sink with no effective safe step between), and the work is hop-by-hop reading. Doing exactly one flow per fresh context keeps the reading careful. Fan-out belongs to the orchestrator.

## Workspace contract
Read first: `AGENTS.md`, `audit/human-context.md`, `audit/scope.md`, `audit/dismissals.md`, the candidate row in `audit/candidates.md`, and the auth-model section of `audit/attack-surface.md`. Write the note to `audit/notes/C-###.md` using `../web-audit-orchestrator/assets/templates/candidate-note.md`. Update the candidate row status (`TRACING` then `TRACED`), append to `audit/log.md`, tick the checklist item. Cite `path:line` for every claim; label observed / inferred / unverified.

## Inputs
A candidate ID, or a raw starting point (a `file:line` sink, a function name, or an entry point `R-###`). If the starting point has no candidate row yet, create one (`origin: tracer` or the origin the human gave).

## Method

### 1. Frame (2 minutes)
State in one line the vulnerability class you are testing for (injection, XSS, SSRF, path, deserialization, etc.) and load the matching card from `../web-vuln-playbooks/references/classes/` plus the stack catalog from `../web-vuln-playbooks/references/stacks/`. The card tells you what counts as a sink, which variants are safe, and which sanitizers are right for which context. Read only those two files.

### 2. Pick direction
- **Backward from a sink** (default when you start at a dangerous call): find every caller, and for each argument keep asking "where does this value come from?" until you reach a source or a constant.
- **Forward from an entry point** (when you start at a route/handler): follow each attacker-controlled parameter, including every copy, rename, field access and return, until it is consumed by something dangerous or dropped.
Do both when the flow is long: backward to find candidate sources, forward to confirm what happens in between.

### 3. Walk the hops
For each hop record `file:line`, what happens to the value, and whether you *read* it or *inferred* it. Watch for the places where traces silently break:
- Wrapper/helper functions and base classes (open them; do not assume what a helper named `sanitize_*` or `safe_*` does).
- Framework magic: route model binding, ORM query building, middleware that mutates the request, serializers, DI, decorators, annotation-based binding, auto-escaping defaults.
- Indirect calls: hooks, events, callbacks, filters, reflection, dynamic dispatch, string-to-function lookup.
- Data stored and read later (second-order): value saved at write time (DB, option, cache, file, session) and used unsafely at read time by a different route or role. Trace the write path and the read path as separate flows and link them.
- Type and encoding changes: casts, JSON parse, URL-decode, base64, unicode normalization, case folding, path canonicalization. Order matters; see step 4.
- Branches: record each distinct path to the sink; a sanitizer on one branch does not protect another.

### 4. Judge every control on the path
For each sanitizer, validator, escaper, allowlist, or auth check, answer the questions in `references/sanitizer-judgement.md`: right control for the sink's context? applied to the value that is actually used? before or after the transformation that matters? allowlist or blocklist? bypassable by type/encoding/ordering? Record "holds / partial / fails" with the reason and `file:line`. Do not assume a control is effective or ineffective; test it against this concrete context.

### 5. Reachability and preconditions
Who can trigger the entry point (none/user/role/admin), which config flags or options gate it, whether the code path is reachable in the default state, whether it needs user interaction or a specific object state, and whether this is dead code, test code, or an example. Check `human-context.md` for role definitions you were told about.

### 6. Write the note and stop
Fill the template. In "Tracer assessment" say what is established, what is only inferred, what you could not confirm, your confidence (low/medium/high) and what would change it. List open questions for the human. Do not give a final exploitability verdict; that is triage's job.

## Escalating to tools
Use tools when the flow is too wide to walk by hand, but verify any tool output by reading the code:
- **Semgrep taint mode** for a one-off source/sink pair: write a small rule with `mode: taint`, `pattern-sources`, `pattern-sinks`, `pattern-sanitizers`, run `semgrep --config rule.yml <path>`. Good for "find every flow into this sink".
- **CodeQL** (public repos; JavaScript/TypeScript, Python, Java/Kotlin, Ruby, Go, C#, C/C++, Swift, Rust; not PHP) for deep interprocedural flow: `codeql database create db --language=<lang> --source-root .` then analyze with the security-extended suite and read the SARIF paths. Treat paths as leads; confirm each hop.
- **PHP**: Semgrep, or Psalm's taint analysis if the project can run it (check availability; unverified here). Otherwise read by hand using the stack catalog.
Never report a tool's finding as established without your own hop-by-hop confirmation.

## Rules
- One starting point per run. New sinks, routes or helpers that look interesting become `NEW` candidates with a one-line reason; do not follow them.
- No uncited claims. If you cannot cite it, write `unverified:` and say what you would need.
- Stay in the code. Do not run the app or send requests.
- If after a reasonable effort (about 40 tool calls) the trace is incomplete, return `PARTIAL`: record exactly where it stopped and why (dynamic dispatch, missing code, unclear config) and what the human or a different tool could resolve.
- If the sink turns out to use a safe pattern (parameterized query, escaping appropriate for the context), say so plainly and recommend dismissal with the evidence; a clean negative is a good result.

## Files
- `references/sanitizer-judgement.md`: questions for judging each control.
- `references/tracing-playbook.md`: tactics for hard flows (wrappers, hooks, second-order, framework magic) and worked mini-examples.
- `../web-vuln-playbooks/`: class cards and stack catalogs (read only the relevant ones).
