# Audit Agent Operating Rules

Drop this file at the root of the audit workspace (or merge into `CLAUDE.md`). It applies to every agent and mini-agent working on the audit. The skills carry the detailed method; this file carries the rules that must never be forgotten.

## 1. Scope and safety
- Work only on code and systems the human has confirmed are in scope (`audit/scope.md`). If scope is empty or unclear, stop and ask.
- The hunt, tracing and triage phases are read-only on source and require **no network requests to live targets**. Never send traffic to a live target without an explicit checkpoint approval recorded in `audit/log.md`.
- Never modify the target source in place. Work in `audit/` or on a copy.
- Proofs of concept demonstrate, they do not exploit: no data exfiltration, no destructive actions, no access to other people's data, no persistence.

## 2. Human in the loop
- Stop at every checkpoint defined by `web-audit-orchestrator` (CP0 to CP4). Present what you did, what you found, what you are unsure about, and what you propose next. Then wait.
- When you are unsure what the code is *supposed* to do (expected role, intended behavior), ask. Batch questions; do not trickle them.
- Read `audit/human-context.md` before starting any task. Treat it as ground truth from the human; if the code contradicts it, say so rather than silently choosing.

## 3. Evidence standard
- Every factual claim about code carries `path:line` (or `path:startLine-endLine`). No citation, no claim.
- Separate **observed** (you read it) from **inferred** (you reasoned to it) from **unverified** (could not confirm). Label them.
- Scanner output, grep hits and your own pattern-matching are *candidates*. Do not call anything a vulnerability until a trace shows attacker-controlled input reaching a dangerous operation with no effective control in between, and triage has tried to knock it down.
- Before declaring a control missing (auth check, sanitizer, validation), look upstream and downstream: middleware, decorators, framework defaults, filters, base classes, proxies/config in the repo.
- Before declaring a mitigation effective, test it against *this* context (encoding, ordering, type, edge cases). Do not assume a patch or sanitizer is sufficient or insufficient; check.

## 4. Checklist and log discipline
- `audit/checklist.md` is the source of truth for progress. Tick an item only when it is done AND you can cite the log entry number that records it: `- [x] P1.3 Route inventory — log#014`.
- Append to `audit/log.md` after **every** completed task, before starting the next. One entry: number, UTC time, agent/skill, checklist item, what was done, files touched, result, next step. Append only; never rewrite history.
- If you cannot finish a task, log it as `BLOCKED` or `PARTIAL` with the reason. Never tick it.

## 5. Mini-agent hygiene
- One agent, one job, one fresh context. Pass state through files in `audit/`, not through memory of earlier chat.
- Stay in your lane: if you discover a new lead outside your task, add it to `audit/candidates.md` as `NEW` with its origin, and keep going on your task.
- Keep outputs in the formats the skill defines so the next agent can parse them.

## 6. Tone of findings
- Be calibrated. State confidence (low/medium/high) and what would change it.
- Prefer "I could not confirm X because Y" over a confident guess. A shorter, honest candidate list beats a long speculative one.
