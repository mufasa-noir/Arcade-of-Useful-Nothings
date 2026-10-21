# Bug Bounty Web Source-Audit Skills

A set of agent skills for **white-box source code analysis of web targets** (open-source apps, self-hosted products, plugins, leaked or in-scope repos, decompiled/bundled JS). Designed around three ideas:

1. **Human in the loop.** The agent stops at defined checkpoints, shows its work, and takes your context ("that sanitizer is custom", "skip the legacy module") before it goes on.
2. **Mini agents.** Each skill is one narrow job (trace one flow, build one matrix, triage one candidate) run in a fresh context and handing off through files, not through a long chat.
3. **Evidence over vibes.** Every claim carries `file:line`. Tools produce *candidates*; only reviewed, evidenced candidates become findings.

## The skills

| Skill | Job | Writes |
|---|---|---|
| `web-audit-orchestrator` | Entry point. Sets up the workspace, owns checklist + log, dispatches the others, enforces checkpoints | `audit/checklist.md`, `audit/log.md`, `audit/candidates.md` |
| `attack-surface-mapper` | Orient, inventory routes/entry points/auth model/dangerous capabilities, rank hot spots | `audit/attack-surface.md` |
| `source-sink-tracer` | Trace ONE sink/function/entry point: sources, hops, sanitizers, sink | `audit/notes/C-###.md` |
| `authz-matrix-audit` | Route-by-route authorization matrix; IDOR/BOLA, function-level gaps | `audit/authz-matrix.md` + candidates |
| `candidate-triage` | Adversarial false-positive filter on ONE candidate | verdict inside the candidate note |
| `patch-variant-hunt` | Mine git history / advisories for fixes, then hunt variants and incomplete fixes | candidates |
| `verify-and-report` | Safe PoC plan, impact, duplicate check, report | `audit/findings/F-###.md` |
| `web-vuln-playbooks` | Reference only: lean per-class cards + per-stack source/sink catalogs, loaded on demand | none |

## Flow

```
Phase 0  Scope & intake ........ [CP0 human confirms scope + context]
Phase 1  Recon ................. attack-surface-mapper ........ [CP1 human reviews map + hot spots]
Phase 2  Hunt .................. source-sink-tracer (xN) | authz-matrix-audit | patch-variant-hunt
                                                              [CP2 human prunes/prioritises candidates]
Phase 3  Triage ................ candidate-triage (one fresh agent per candidate)
                                                              [CP3 human approves what gets verified]
Phase 4  Verify & report ....... verify-and-report ........... [CP4 human approves ANY live-target request]
```

## Install

Keep all eight folders together (skills read `web-vuln-playbooks` and the orchestrator's templates).

- **Claude Code:** copy the eight folders into `~/.claude/skills/` (or `<repo>/.claude/skills/`). Put `AGENTS.md` at the root of your audit workspace (or append it to `CLAUDE.md`).
- **Claude.ai:** zip each skill folder separately and upload under Settings → Capabilities → Skills.
- **Other agents (Codex, Gemini CLI, Cursor, ...):** put the folders somewhere readable, add `AGENTS.md` to the workspace, and tell the agent to start from `web-audit-orchestrator/SKILL.md`.

## Quick start

Open your agent in a directory containing the target source (or tell it where the source is), then:

> Use the web-audit-orchestrator skill. Target: `./target-app` (PHP/WordPress plugin). Program scope: <paste scope or policy URL>. Known context: <anything you already know>. Start at Phase 0.

Resume later with: `Resume the audit in ./audit — read checklist.md and log.md first.`

Inject context any time: `Add to human context: <fact>` — the agent appends it to `audit/human-context.md` and every later mini-agent reads it.

## Extending

- New stack (Rails, Laravel, Go, .NET): copy `web-vuln-playbooks/references/stacks/_template.md`, fill it, and add one line to the index in `web-vuln-playbooks/SKILL.md`.
- New vuln class: add a card to `web-vuln-playbooks/references/classes/` using the card format in that skill. Do not create a separate skill per class; the tracer plus a card covers it.
- Repo-specific lessons: put them in `audit/dismissals.md`; triage reads it every time.

## Optional tooling (agents degrade gracefully to `grep`/`rg` + reading)

Semgrep (taint mode, `p/owasp-top-ten`, `--config=auto`), CodeQL (public repos; no PHP support), gitleaks / trufflehog, `git log -p` / `git log -S`, jadx and source-map extraction for acquiring client code, `git-dumper` for exposed `.git` (only where in scope). Stack-specific: Psalm taint analysis for PHP, `npm audit` / `pip-audit` / `composer audit` for dependencies.

## Ground rules

Authorized targets only. Read the program policy first. These skills never need you to touch a live system for the hunt phase; verification defaults to a local copy of the same version.
