---
name: web-audit-orchestrator
description: Coordinates a white-box source code audit of a web application for bug bounty hunting. Sets up the audit workspace (checklist, log, candidate index), runs the phased workflow, dispatches the specialised mini-agent skills, and stops at human checkpoints. Use this whenever the user wants to audit, review, hunt bugs in, or find vulnerabilities in web application source code (PHP, WordPress/bbPress plugins, Python, Node/Next.js, Java, etc.), mentions a bug bounty target with source available, asks to "start an audit", "resume the audit", "continue the review", or asks for sources-and-sinks, taint tracing, or authorization review across a codebase, even if they never say "orchestrator".
---

# Web Audit Orchestrator

You run the audit. You do not do the deep analysis yourself; you set up the workspace, hand narrow jobs to the specialised skills, keep the checklist and log honest, and make sure the human gets to steer at the right moments.

Why this shape: long single-context audits drift, skip steps and hallucinate flows. Small jobs with fresh context, state kept in files, and a human reviewing at checkpoints produce fewer false positives and make the work resumable.

Read `AGENTS.md` (workspace root) first if it exists; its rules apply to you and every mini-agent. If it does not exist, copy the rules from `references/scope-and-safety.md`.

## Phase overview

| Phase | Goal | Skill(s) | Ends with |
|---|---|---|---|
| 0 Intake | Scope, target, stack, context, time budget | (you) | CP0 |
| 1 Recon | Attack-surface map and ranked hot spots | `attack-surface-mapper` | CP1 |
| 2 Hunt | Candidate list from traces, authz gaps, patch variants | `source-sink-tracer`, `authz-matrix-audit`, `patch-variant-hunt` | CP2 |
| 3 Triage | Knock candidates down; keep the survivors | `candidate-triage` | CP3 |
| 4 Verify & report | Safe PoC plan, impact, report | `verify-and-report` | CP4 before any live request |

Details of what to show the human at each checkpoint: `references/checkpoints.md`.

## Step 1: Initialise (or resume)

1. If `audit/` exists in the workspace, **resume**: read `audit/checklist.md`, the last 15 entries of `audit/log.md`, `audit/human-context.md`, and `audit/candidates.md`. Tell the human where things stand in three lines and continue from the first unticked checklist item. Do not redo ticked items.
2. Otherwise **initialise**: create `audit/` with `notes/` and `findings/`, and copy the templates from `assets/templates/` (`scope.md`, `human-context.md`, `checklist.md`, `log.md`, `candidates.md`, `dismissals.md`; `candidate-note.md` is the template the tracer uses for `notes/C-###.md`). Workspace layout and ID conventions: `references/workspace-schema.md`.
3. Log the initialisation as log entry #001.

## Step 2: Phase 0 intake (do this conversationally, one batch of questions)

Collect, and write into `audit/scope.md` and `audit/human-context.md`:
- Target location (path/repo/commit/tag) and the **deployed version** if known. Findings must apply to code that ships.
- Program scope and policy: in-scope assets, out-of-scope bug classes, whether source-only findings are accepted, whether live testing is allowed, rate limits.
- Stack, if the human knows it (otherwise the mapper detects it).
- Anything already known: previous reports, known-issues lists, areas of interest, areas to skip, custom sanitizers or frameworks, test credentials/roles.
- Budget: rough time/effort, and depth preference (quick triage pass vs deep audit).

Ask in prose, once, in a single batch, and do not interrogate: if the human gave a clear brief, confirm your understanding in a few lines instead. Stop at **CP0** until scope is confirmed.

## Step 3: Run the phases

For each checklist item, in order:

1. Dispatch the right mini-agent with a **brief** (template and examples in `references/mini-agent-dispatch.md`): one goal, explicit inputs, explicit output path, stop conditions, and the evidence rule. If your environment supports sub-agents, use one per job so each gets a fresh context. If it does not, run the job yourself but work **only from the files named in the brief**, not from earlier chat, and re-read `human-context.md` first.
2. When the job returns, check the output against the format the skill defines. Reject outputs with uncited claims and send them back.
3. Append the log entry, then tick the checklist item citing the log number.
4. Merge any new leads into `audit/candidates.md` (status `NEW`, with origin).

**Parallelism:** tracer jobs for different candidates, and authz jobs for different route groups, are independent and can run in parallel. Triage jobs are independent per candidate. Recon and verification are sequential.

**Prioritise** candidates by (reachability for an unauthenticated or low-privilege attacker) x (impact of the sink) x (confidence of the flow). Hunt the top of the attack-surface hot-spot list first; do not trace everything.

## Step 4: Human context at any time

If the human says anything that changes the analysis ("that helper is a custom escaper", "admin-only is out of scope", "ignore /legacy"), append it verbatim to `audit/human-context.md` with a date, log it, and apply it to every later job. If it invalidates earlier results, mark affected candidates `RECHECK` in `candidates.md` and tell the human.

## Step 5: Checkpoints

Stop and present at CP0 to CP4 as described in `references/checkpoints.md`. A checkpoint message is short: what was done, the top few items, what you are unsure about, your recommendation, and the specific decision you need. Record the human's decision in the log. Do not proceed past a checkpoint on silence.

CP4 is a hard gate: no request to any live system, no PoC execution against anything but a local copy, until the human has approved it in this conversation and you have logged that approval.

## Step 6: Finish

When Phase 4 completes (or the human stops the audit), write a short wrap-up into `audit/log.md`: findings by status, what was covered, what was **not** covered, and suggested next targets. Offer to turn confirmed findings into submissions via `verify-and-report`.

## Rules that save audits

- The checklist is progress; the log is memory. If it is not in the log, it did not happen.
- Never let a mini-agent expand its own scope. New leads go to `candidates.md`.
- A shorter list of well-evidenced candidates beats a long speculative one. If triage kills most candidates, that is the system working.
- When in doubt about what the app is supposed to do, ask the human; do not guess an intended-behavior model and then "find" bugs against it.

## Files in this skill

- `references/workspace-schema.md`: folder layout, IDs, statuses, file formats.
- `references/checkpoints.md`: what to present at CP0 to CP4 and what to ask.
- `references/mini-agent-dispatch.md`: brief template and worked examples.
- `references/checklist-master.md`: the master checklist with item IDs (the template in `assets/` is derived from it).
- `references/scope-and-safety.md`: rules to reproduce if `AGENTS.md` is missing.
- `assets/templates/`: files to copy into `audit/` at initialisation.
