---
name: verify-and-report
description: Takes human-approved source-audit candidates through a safe, minimal proof of concept plan, realistic impact and severity reasoning, duplicate and known-issue checks, and a bug bounty report with file:line evidence and a suggested fix. Defaults to verifying against a local copy of the same version and never touches a live target without a logged checkpoint approval. Use when the user says "write the report", "prepare a PoC", "verify this finding", "is this reportable", "estimate severity", "draft the submission", or when candidates are marked APPROVED in an audit, even if they only say "let's write this up".
---

# Verify and Report

Triage says a candidate is probably real; this skill proves it safely and packages it so a triager can reproduce and accept it quickly. A report that is correct but hard to reproduce gets closed; a PoC that harms real data gets you banned. Both failures are avoidable.

## Workspace contract
Read first: `AGENTS.md`, `audit/scope.md`, `audit/human-context.md`, the candidate note (including Triage). Only work on candidates with status `APPROVED`. Write `audit/findings/F-###.md` (template: `references/report-template.md`), link it to the `C-###`, update the row (`VERIFIED` then `REPORTED`), log, tick P4.x. Cite `path:line` throughout.

## Procedure

### 1. Restate the claim (P4.1)
In three lines: the vulnerability, the attacker's starting position (principal), and the impact. If the claim has drifted from the triage note, stop and reconcile.

### 2. Choose where to verify
Preferred order: (a) local instance of the exact version (container, local install, unit-test harness calling the function), (b) the program's designated test environment, (c) the live target, only if `scope.md` allows it and the human approves the specific plan at CP4. Source-level findings may be reportable without a PoC if the program accepts them; check `scope.md`. See `references/poc-plan.md` for how to build the environment and write the plan.

### 3. Write the PoC plan before running anything
Exact steps/requests, accounts and roles used (your own), the observation that proves the bug, why it is non-destructive, and how to clean up. Use harmless proof: a time delay, a benign marker string reflected, reading a record you own via another account you also own, a callback to a server you control, `id`/`whoami` rather than file or data dumps. Present the plan at CP4 for any non-local step and wait for approval; record the approval text in the log.

### 4. Execute and record (P4.3)
Run the plan. Capture exact requests/responses (redact secrets), the code lines involved, and the observation. If it fails, diagnose against the trace: that means the analysis was wrong somewhere, which is valuable (update the note, tell the human, and re-run triage if needed). Do not keep retrying variations against a live target.

### 5. Impact and severity (P4.4)
Reason from facts, not adjectives: principal required, user interaction, data/functions exposed, blast radius (one user, all users, tenant, server), chaining potential (state it separately and do not inflate the base finding with a speculative chain). Suggest a CVSS vector if the program uses CVSS and show your reasoning per metric (`references/severity-and-impact.md`); defer to the program's own severity table if it has one. State plainly what the attacker cannot do.

### 6. Duplicate and known-issue check
Search the product's advisories, changelog, public disclosures, and your own `dismissals.md`. Check whether a newer release already fixes it and whether the program accepts findings in outdated versions. Record what you checked.

### 7. Write the report (P4.5)
Use the template. Lead with a one-paragraph summary a triager can act on, then root cause with `file:line`, reproduction steps, evidence, impact, and a minimal fix suggestion. Keep tone neutral and factual; no hype, no threats. Before finishing, run the checklist at the end of `references/report-template.md`.

### 8. Stop for the human
Present the draft and the verification evidence; the human decides whether to submit. Never submit on their behalf.

## Rules
- No live-target traffic without a logged CP4 approval for that exact plan.
- Demonstrate, do not exploit: no exfiltration beyond your own test data, no destructive payloads, no persistence, no pivoting, no testing against other users' data.
- If you accidentally encounter real user data or credentials, stop, do not copy or use them, note the location, and tell the human.
- Report only what you verified or clearly label it as `unverified`/theoretical.
- One root cause, one report. Chains go in a separate section, labeled as such.

## Files
- `references/poc-plan.md`: environment setup and PoC plan format.
- `references/severity-and-impact.md`: impact reasoning and CVSS notes.
- `references/report-template.md`: report structure and pre-submit checklist.
