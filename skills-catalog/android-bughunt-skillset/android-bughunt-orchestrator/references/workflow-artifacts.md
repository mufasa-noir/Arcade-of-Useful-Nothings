# Workflow Artifacts — Shared Templates

Every skill in the android-bughunt set reads/writes these same artifacts so the pipeline stays coherent whether it's run by sub-agents or manually, one stage at a time.

## checklist.md

```markdown
# Android Bug Hunt Checklist — <app name / package id>

Scope: <source root, decompiler type, package/module if scoped>
Started: <date>

## Pipeline stages
- [ ] Bug review complete
- [ ] Convention review complete
- [ ] Security review complete
- [ ] Issue triage complete
- [ ] Finding verification complete
- [ ] User go-ahead for fixing received
- [ ] Fixing complete
- [ ] Final report assembled

## Findings (ticked once verified — not when first raised)
- [ ] F-001 — <short title> (<severity once known>)
- [ ] F-002 — ...
```

## task-log.md

Append-only. One line per completed task, oldest first. Never rewrite or delete prior entries — if something needs correcting, append a correction line.

```
<UTC timestamp> | <skill> | <event> | <detail>
```

Example:
```
2026-11-03 14:02 UTC | bug-reviewer | started | scope: com.example.app/ui
2026-11-03 14:15 UTC | bug-reviewer | completed | 7 candidate findings -> findings/bug-raw.md
2026-11-03 14:16 UTC | security-reviewer | started | scope: com.example.app
2026-11-03 14:40 UTC | security-reviewer | completed | 11 candidate findings -> findings/security-raw.md
2026-11-03 14:41 UTC | issue-triage | started | input: 3 raw findings files, 24 candidates
2026-11-03 14:50 UTC | issue-triage | completed | 16 candidates after dedupe -> findings/triaged.md
```

`event` is one of: `started`, `completed`, `blocked`, `skipped`. Use `blocked` when a stage can't proceed (e.g. verifier can't reach a code path) and say why in `detail`.

## Raw finding entry (bug / convention / security reviewers)

One entry per candidate, appended to that reviewer's own findings file (`findings/bug-raw.md`, `findings/convention-raw.md`, `findings/security-raw.md`):

```markdown
### [<PREFIX>-<NNN>] <short title>
- **Reviewer:** bug-reviewer | convention-reviewer | security-reviewer
- **Location:** <path/to/File>:<line or line range>
- **Category:** <reviewer-specific category, e.g. "null safety", "naming inconsistency", "insecure storage">
- **Description:** What the code does and why it's a candidate issue.
- **Why it matters:** Concrete consequence if true (crash, data leak, bypass, etc.) — not just "this is bad practice."
- **Confidence:** low | medium | high
```

Prefixes: `BUG-`, `CONV-`, `SEC-`. Numbers are per-reviewer, not global — triage assigns the global `F-NNN` IDs used in the checklist and final report.

## Triaged finding (issue-triage)

Same fields as above, plus:
```markdown
- **Status:** kept | merged-with-<other-id> | dropped-<reason>
- **Global ID:** F-<NNN>
```
Dropped and merged entries stay in the triaged file (don't delete them) so the reasoning is auditable — just mark their status.

## Verified finding (finding-verifier)

Adds to the triaged entry:
```markdown
- **Verification status:** confirmed | unverified | false-positive
- **Verification evidence:** What was actually traced/read/tested to reach this conclusion — specific enough that someone else could redo the check.
- **Severity:** critical | high | medium | low | info
- **Reproduction notes:** Steps or conditions needed to trigger it, if applicable.
```

## Fix entry (fixing-agent)

Adds to the verified entry:
```markdown
- **Fix type:** recommendation-only | patch-snippet | rebuilt-apk-poc
- **Fix detail:** The recommendation text, patch snippet, or path to the rebuilt APK/patched source.
- **Fix status:** proposed | applied-to-poc | not-attempted-<reason>
```

## findings-report.md (final report structure)

```markdown
# Android Bug Hunt Report — <app name>

## Summary
App / package, source scope, decompiler used, date, which stages ran.

## Findings by severity
### Critical
### High
### Medium
### Low / Info
(Each finding: full entry from verification + fix sections above.)

## Unverified / inconclusive
Findings the verifier couldn't confirm either way — kept visible, not discarded.

## Appendix: task log
Full contents of task-log.md.
```
