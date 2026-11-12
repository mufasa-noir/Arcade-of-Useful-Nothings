---
name: android-bughunt-orchestrator
description: Coordinates a full Android APK bug-hunting pipeline across reviewer, validation, and fixing sub-skills, given already-decompiled Android sources (jadx/apktool output). Use this skill whenever the user wants to reverse-engineer or audit an Android APK's decompiled source for bugs or vulnerabilities, asks to "find bugs in this APK", "review this decompiled app", "audit this Android app's source", mentions AndroidManifest.xml / smali / JNI source review, or wants a structured multi-stage code review of a mobile app. This is the entry point — it dispatches to android-bug-reviewer, android-convention-reviewer, android-security-reviewer, android-issue-triage, android-finding-verifier, and android-fixing-agent, and should be consulted first before those are used individually, unless the user explicitly asks to run only one stage.
---

# Android APK Bug Hunt — Orchestrator

## What this coordinates

This is the entry point for a 7-skill pipeline:

1. `android-bug-reviewer` — functional/logic bugs (not security-specific)
2. `android-convention-reviewer` — coding convention violations (also a tell for injected/obfuscated/anomalous code)
3. `android-security-reviewer` — security vulnerabilities (manifest exposure, crypto, WebView, network, IPC, native libs, dependencies)
4. `android-issue-triage` — dedupes and filters raw findings from stages 1–3 (quick pass, not deep verification)
5. `android-finding-verifier` — deep verification: traces code, confirms a finding is real and reproducible before it counts
6. `android-fixing-agent` — produces remediation for verified findings (recommendation/patch and/or rebuilt APK PoC, per the user's choice)

Stages 1–3 generate candidates. Stage 4 is a cheap filter. Stage 5 is the actual quality gate — nothing should be treated as a confirmed bug until it passes verification.

## Expected input

Already-decompiled Android app sources — not a raw `.apk`. Typically either:
- **jadx output**: readable Java-ish source under `sources/`, resources under `resources/res/`
- **apktool output**: smali under `smali/` (possibly `smali_classes2/`, etc.), resources under `res/`, `AndroidManifest.xml` at the root

If the source root isn't given, ask for it. If it's ambiguous which decompiler produced it, check for `sources/` (jadx) vs `smali/` (apktool) — this affects which reviewers can do what (smali-only trees limit the bug/convention reviewers' usual Java-level heuristics; note this as a scoping caveat rather than failing).

For large codebases, ask whether to scope to a specific package/module before starting — don't silently review everything if the tree is huge.

## Standard pipeline (sub-agent-capable environments: Claude Code / Cowork)

1. Confirm source root, decompiler type, and scope.
2. Initialize `checklist.md` and `task-log.md` in the output directory (templates in `references/workflow-artifacts.md`).
3. Spawn `android-bug-reviewer`, `android-convention-reviewer`, and `android-security-reviewer` in parallel as sub-agents against the source root. Each writes its own raw findings file.
4. Run `android-issue-triage` over the combined raw findings to dedupe and drop obviously invalid candidates.
5. Run `android-finding-verifier` over the triaged list.
6. **Checkpoint — stop here.** Present verified findings to the user and get explicit go-ahead before fixing anything.
7. Run `android-fixing-agent` on the findings the user approves. Ask up front (or per-finding) whether they want a written recommendation/patch snippet, a rebuilt APK PoC, or both.
8. Assemble `findings-report.md` from the checklist, task log, verified findings, and fix status.

## Manual pipeline (no sub-agent support — e.g. claude.ai chat)

Walk through the stages yourself, one at a time, carrying each stage's output into the next rather than blending them into one pass:

1. "Reviewing as the bug reviewer" → follow `android-bug-reviewer`'s instructions.
2. "Reviewing as the convention reviewer" → follow `android-convention-reviewer`'s instructions. Keep this a genuinely separate pass, not a continuation of the bug review — the separation of perspective is the point.
3. "Reviewing as the security reviewer" → follow `android-security-reviewer`'s instructions.
4. Combine the three raw findings lists, then follow `android-issue-triage`.
5. Follow `android-finding-verifier` on the triaged list.
6. **Checkpoint** — show the user verified findings, wait for go-ahead.
7. Follow `android-fixing-agent` on approved findings.
8. Assemble the final report.

Be explicit about which "hat" is on at each stage so the user can follow along and interject.

## Checkpoints — never skip these

- **Verification → fixing boundary**: always get explicit user go-ahead before running the fixing agent. Never auto-proceed from verified findings straight to fixes.
- **Inconclusive findings**: if `android-finding-verifier` can't confirm something, surface it as "unverified" in the report — don't silently drop it or treat it as confirmed either way.

## Design notes

- The bug, convention, and security reviewers should NOT try to validate their own findings. That's deliberately deferred to triage/verification so each reviewer stays focused on generating candidates, not judging them — keeps their output noisier but more complete.
- If the convention reviewer flags something structurally odd (naming that breaks from the rest of the codebase, unusual control flow, dead code paths, inconsistent obfuscation), flag it to the security reviewer too — convention anomalies are a common tell for injected or tampered logic, independent of whether they're a "convention" issue in the style sense.
- Severity and confidence are assigned at verification, not at the raw-finding stage — reviewers should note their own confidence, but the verifier owns the final severity call.

## Output artifacts

- `checklist.md` — pipeline stages + individual findings, ticked off as completed
- `task-log.md` — append-only, timestamped log of every task performed by every stage
- `findings-report.md` — final report: verified findings grouped by severity, each with description, location, originating reviewer, verification evidence, and fix status

See `references/workflow-artifacts.md` for the exact templates.
