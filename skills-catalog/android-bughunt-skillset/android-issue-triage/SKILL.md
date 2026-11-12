---
name: android-issue-triage
description: Dedupes and does a first-pass filter on raw findings produced by android-bug-reviewer, android-convention-reviewer, and android-security-reviewer, assigning global finding IDs before handing off to android-finding-verifier. Use this skill after all three reviewer passes are complete, when the user wants raw Android bug-hunt findings merged, deduped, and triaged, or asks to combine/clean up findings before deep verification. Part of the android-bughunt pipeline — see android-bughunt-orchestrator for the full flow.
---

# Android Issue Triage

## Role boundary

This is a **cheap, fast filter** — not deep verification. You're reading the raw findings text and using judgment on duplicates and obvious non-issues; you are not re-opening source files to independently confirm exploitability. That's `android-finding-verifier`'s job, which happens next. If you're not sure whether something is a duplicate or genuinely invalid, keep it — err toward passing things through rather than dropping them, since dropping here is much cheaper to get wrong than dropping after real verification work.

## Inputs

The three raw findings files: `findings/bug-raw.md`, `findings/convention-raw.md`, `findings/security-raw.md` (whatever subset exists — it's fine if the pipeline was run with fewer than three reviewers).

## What to do

1. **Assign global IDs.** Every finding gets an `F-NNN` ID in triage order, regardless of its original `BUG-`/`CONV-`/`SEC-` prefix. Keep the original prefix+number visible as provenance.
2. **Dedupe.** The same underlying issue is often independently flagged by more than one reviewer (e.g. a hardcoded crypto key might show up from both the security reviewer and, as a "magic string," the convention reviewer). Merge these into one `F-NNN` entry, keep all contributing reviewers listed, and keep the most detailed description.
3. **Drop obvious non-issues**, but only when you're confident: findings that cite the wrong category entirely with no salvageable content, findings about test/sample code explicitly out of scope, or findings that contradict something directly stated elsewhere in the same raw findings (e.g. a reviewer flagged something as hardcoded, but it's clearly a resource placeholder pulled from `strings.xml` with no sensitivity). Record the reason for every drop — don't delete the entry.
4. **Carry forward `android-convention-reviewer`'s "Flag to security reviewer: yes" findings** by cross-checking whether `android-security-reviewer` already independently caught the same thing. If not, keep the convention-reviewer's anomaly finding in the triaged set anyway so the verifier can assess it on security merits even though it originated from the convention pass.
5. Do not change confidence levels or invent severity — those stay as the originating reviewer set them (confidence) or get set later (severity, at verification).

## Output

Write `findings/triaged.md` using the triaged finding format from the orchestrator's `references/workflow-artifacts.md`: each entry keeps the raw finding fields, plus `Status` (`kept` | `merged-with-F-NNN` | `dropped-<reason>`) and the new `Global ID`. Update `checklist.md` with one checklist line per kept finding. Log start/completion in `task-log.md`, including total raw-finding count in vs. kept/merged/dropped counts out.
