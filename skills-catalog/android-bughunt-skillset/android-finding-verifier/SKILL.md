---
name: android-finding-verifier
description: Deeply verifies triaged Android bug-hunt findings by tracing actual code paths, confirming reachability and real-world exploitability, and assigning final severity — the quality gate before anything is treated as a confirmed finding. Use this skill after android-issue-triage, when the user wants findings actually confirmed against the source (not just listed), or asks to verify whether a reported Android bug/vulnerability is real. Part of the android-bughunt pipeline — see android-bughunt-orchestrator for the full flow.
---

# Android Finding Verifier

## Role boundary

This is the quality gate. Nothing should be reported as a confirmed bug or vulnerability in the final report unless it passed through here. Where triage was a cheap text-level pass, this is real work: open the actual files, trace the actual call paths, and only mark something `confirmed` when you could explain to someone else exactly how you know it's real.

## What "verified" actually requires

For each triaged finding, per category:

- **Reachability**: can the vulnerable/buggy code path actually be reached from a real entry point (exported component, user action, network response)? Trace it — don't assume the reviewer who raised it already confirmed this; reviewers generate candidates, they don't verify them.
- **Preconditions**: what does an attacker (or just bad luck, for bug-reviewer findings) actually need? Re-derive this yourself from the code rather than trusting the raw finding's "Exploit precondition" line at face value — it's a reviewer's estimate, not a verified fact yet.
- **Guards**: is there a check elsewhere in the codebase — a permission check in a different method, a feature flag, a server-side validation the client-side code ultimately depends on — that the original finding missed? This is the single most common reason a plausible-looking finding turns out to be a false positive.
- **Consequence**: if reachable and unguarded, what can actually happen? Be concrete (what data is exposed, what action is performed, what crash/state corruption results) — this is what severity gets based on.

## Verification techniques by finding type

See `references/verification-techniques.md` for concrete per-category verification steps (how to confirm a manifest exposure is really unguarded, how to confirm a crypto weakness is really exploitable, etc.).

## Possible outcomes

- **confirmed** — reachability, lack of guards, and consequence are all established with concrete evidence.
- **false-positive** — tracing shows it's not actually reachable, or a guard elsewhere neutralizes it, or the premise was wrong.
- **unverified** — you could not fully confirm or refute it (e.g. the code path depends on native code you can't fully trace statically, or server-side behavior you can't observe from source alone). This is a legitimate outcome, not a failure — record exactly what's blocking confirmation so a human can decide whether it's worth deeper (e.g. dynamic/instrumented) investigation outside this skill's scope.

Never silently upgrade `unverified` to `confirmed` for the sake of a cleaner report, and never silently drop `unverified` findings — both go in the final report, in their own sections.

## Severity assignment

Own the final severity call (triage and the reviewers don't set this). Base it on reachability + precondition + consequence, roughly:
- **Critical**: remotely/externally reachable with no precondition, high-impact consequence (RCE-equivalent, full data exfiltration, auth bypass)
- **High**: reachable with a plausible precondition (e.g. a malicious co-installed app, a MITM position), significant consequence
- **Medium**: reachable but with a harder precondition, or reachable easily but with limited consequence
- **Low**: real but requires an unlikely precondition or has minor consequence
- **Info**: technically true but not independently actionable (e.g. a defense-in-depth gap with no direct exploitation path found)

## Output

Update `findings/triaged.md` → `findings/verified.md`, adding the verified finding fields from the orchestrator's `references/workflow-artifacts.md` (verification status, evidence, severity, reproduction notes) to every entry — confirmed, false-positive, and unverified alike. Tick off verified findings in `checklist.md`. Log start/completion in `task-log.md`, and log a `blocked` event for any finding where verification is genuinely stuck (with the reason), rather than letting it sit silently unresolved.
