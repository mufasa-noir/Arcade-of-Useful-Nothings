---
name: android-bug-reviewer
description: Reviews already-decompiled Android app source (jadx/apktool output) for functional and logic bugs — not security vulnerabilities, not style/convention issues. Use this skill when the user wants a bug-focused pass over decompiled Android source as part of the android-bughunt pipeline, or asks specifically to check for crashes, null pointer risks, lifecycle bugs, race conditions, resource leaks, or broken logic in an Android app's source. One of three parallel reviewer skills (alongside android-convention-reviewer and android-security-reviewer) feeding android-issue-triage. See android-bughunt-orchestrator for the full pipeline this belongs to.
---

# Android Bug Reviewer

## Role boundary

Find things that make the app **behave incorrectly or crash** — not things that make it insecure (that's `android-security-reviewer`) and not things that merely look inconsistent or non-idiomatic (that's `android-convention-reviewer`). If something is both a functional bug and a security issue (e.g. a race condition that also creates a TOCTOU vuln), note it here and let the security reviewer independently catch the security angle — don't skip it just because it overlaps.

Don't validate your own findings and don't assign final severity — note your own confidence (low/medium/high) and move on. `android-issue-triage` and `android-finding-verifier` own validation.

## What to look for

See `references/bug-playbook.md` for the full checklist. Categories, roughly in order of how often they turn out to be real:

- Android lifecycle bugs (leaked Activity/Context, work started but never cancelled on destroy, state not restored/saved correctly)
- Null-safety gaps (unchecked nullable fields, especially across Kotlin/Java interop boundaries where nullability annotations get lost in decompilation)
- Resource leaks (streams, cursors, file descriptors, camera/sensor handles not released)
- Concurrency bugs (missing synchronization, shared mutable state touched from multiple threads/coroutines, AsyncTask/Handler misuse)
- Logic errors (off-by-one, inverted conditionals, wrong operator, dead branches that should be reachable)
- State management bugs (stale cached data, race between UI state and background updates, config-change (rotation) data loss)
- Error handling gaps (swallowed exceptions, catch blocks that hide real failures, retry logic that can loop forever or never retry)

## Approach

1. Confirm scope with the orchestrator (or the user, if run standalone) — which package/module to review.
2. Start from entry points (Activities, Services, Fragments, BroadcastReceivers in the manifest) and work inward, rather than reading files in alphabetical order — bugs that matter are the ones reachable from real app flows.
3. For each candidate, write down what you'd need to see to be sure it's real (this becomes useful input for the verifier later).
4. Prefer fewer, well-explained findings over a long list of speculative ones — but don't self-censor into silence either; low-confidence findings are fine as long as they're marked as such.

## Output

Append each finding to `findings/bug-raw.md` using the raw finding entry format from the orchestrator's `references/workflow-artifacts.md` (prefix `BUG-`). Log start/completion in `task-log.md` per that same reference.

If `android-bughunt-orchestrator`'s reference file isn't reachable (skill run standalone, outside the full set), use this fallback format for each finding:

```markdown
### [BUG-NNN] <short title>
- **Location:** path/to/File:line
- **Category:** <one of the categories above>
- **Description:** ...
- **Why it matters:** ...
- **Confidence:** low | medium | high
```
