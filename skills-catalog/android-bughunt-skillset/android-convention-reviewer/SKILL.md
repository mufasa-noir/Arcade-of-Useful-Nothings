---
name: android-convention-reviewer
description: Reviews already-decompiled Android app source (jadx/apktool output) for coding-convention violations and structural anomalies — inconsistent naming, unidiomatic patterns, dead code, and code that doesn't match the rest of the codebase's style. Use this skill when the user wants a convention/style-focused pass over decompiled Android source as part of the android-bughunt pipeline, or asks to check for code smells, inconsistent style, or signs of injected/tampered code in an Android app's source. One of three parallel reviewer skills (alongside android-bug-reviewer and android-security-reviewer) feeding android-issue-triage. See android-bughunt-orchestrator for the full pipeline this belongs to.
---

# Android Convention Reviewer

## Role boundary

This is a convention/style pass — but on **decompiled** code, "convention violation" means something different than it does on original source. Decompilers normalize a lot of formatting, so whitespace/indentation differences aren't meaningful. What *is* meaningful: naming patterns, structural idioms, and consistency relative to the rest of the same codebase. Don't duplicate `android-bug-reviewer` (correctness) or `android-security-reviewer` (exploitability) — your job is "does this look like it belongs here," and the payoff is that anomalies are often the cheapest way to find tampered or injected code in a decompiled app.

Don't validate your own findings or assign final severity. Note confidence and move on.

## What to look for

See `references/convention-playbook.md` for the full checklist. Two groups:

**Ordinary convention issues** (lower signal, still worth noting):
- Inconsistent naming conventions within the same package (camelCase mixed with snake_case, inconsistent Hungarian-ish prefixes)
- Deprecated Android API usage where the rest of the codebase has moved on
- Dead code / unreachable branches / unused classes still present
- Inconsistent error-handling style across otherwise-similar classes

**Anomaly signals** (higher signal — flag to the security reviewer too, per the orchestrator's design notes):
- A class or method whose naming/obfuscation level doesn't match its neighbors (e.g. everything else nicely named, one class is `a.b.c` — can indicate a separately-injected or repackaged component)
- Reflection, `DexClassLoader`, or dynamic code loading used in a codebase that otherwise doesn't need it
- A permission or capability used by one class with no corresponding legitimate feature elsewhere in the app
- Strings or resources that don't match the app's apparent language/branding (leftover test/malicious strings)
- Package structure that doesn't match the declared package in the manifest (repackaging signal)

## Approach

1. Build a quick mental model of the codebase's "normal" first — skim a representative sample of classes before flagging anything as anomalous. You can't spot what's inconsistent without a baseline.
2. Treat anomaly signals as genuinely higher priority than ordinary style nits — don't bury them in a long list of minor naming complaints.
3. When flagging an anomaly signal, explicitly note it should also be considered by the security reviewer.

## Output

Append each finding to `findings/convention-raw.md` using the raw finding entry format from the orchestrator's `references/workflow-artifacts.md` (prefix `CONV-`). For anomaly-signal findings, add a line `- **Flag to security reviewer:** yes` so triage carries it forward.

Fallback format, if run standalone without the orchestrator's reference file:

```markdown
### [CONV-NNN] <short title>
- **Location:** path/to/File:line
- **Category:** ordinary-convention | anomaly-signal
- **Description:** ...
- **Why it matters:** ...
- **Confidence:** low | medium | high
- **Flag to security reviewer:** yes | no
```
