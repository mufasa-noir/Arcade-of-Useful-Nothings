---
name: android-fixing-agent
description: Produces remediation for verified (confirmed) Android bug-hunt findings — either a written recommendation/patch snippet, or an actual patched-and-rebuilt APK proof-of-concept. Use this skill after android-finding-verifier and after the user has explicitly approved which findings to fix, or when the user asks to fix/patch/remediate a confirmed Android bug or vulnerability. Never run this on findings that aren't status confirmed, and never run it without explicit user go-ahead. Part of the android-bughunt pipeline — see android-bughunt-orchestrator for the full flow.
---

# Android Fixing Agent

## Preconditions — check before doing anything

1. The finding's status in `findings/verified.md` must be `confirmed`. Refuse (and say why) if asked to "fix" something `unverified` or `false-positive` — send it back to `android-finding-verifier` first.
2. The user must have explicitly approved this specific finding (or an explicit batch including it) for fixing. If running standalone without that context, ask first — don't infer approval from the finding simply being confirmed.
3. Confirm with the user which output they want for this run if not already specified: **recommendation-only**, **patch-snippet**, or **rebuilt-apk-poc** (or more than one). Default to asking rather than guessing — the right choice depends on context (bug bounty report vs. demonstrating impact vs. fixing an app the user actually owns/maintains) that this skill can't infer on its own.

## Recommendation-only / patch-snippet output

Write the actual fix, not just a description of what should change:
- For a recommendation, describe the concrete change needed (which check to add, which API to use instead, which flag to flip) in enough detail that someone unfamiliar with this finding could implement it.
- For a patch snippet, write real code in the source language visible at that location (Java/Kotlin-style for jadx trees, noting that it's illustrative-equivalent-source rather than literal smali if working from an apktool tree — say so explicitly rather than presenting smali-level pseudocode as if it compiles).
- Keep the snippet scoped to the actual fix — don't refactor surrounding code unless the fix requires it.

## Rebuilt-APK-PoC output

Only attempt this when the source tree is an **apktool** decompile (smali + resources), since that's what can be reassembled. If working from a jadx-only tree, say so and fall back to recommendation/patch-snippet output, or ask the user to also provide the apktool output for the same APK.

Steps (Claude Code / Cowork environment with real tool access):

1. **Make the smali edit.** Locate the exact method/field in the `smali/` tree corresponding to the verified finding's location, and make the minimal edit needed to demonstrate the fix (or, if the goal is a vulnerability PoC rather than a fix demo, the minimal edit needed to demonstrate exploitability — confirm which with the user, since "prove it's broken" and "prove the fix works" are different POCs).
2. **Rebuild**: `apktool b <decompiled-dir> -o patched.apk`
3. **Sign**: unsigned APKs won't install. Generate or reuse a debug keystore and sign with `apksigner`:
   ```
   keytool -genkey -v -keystore debug.keystore -alias androiddebugkey \
     -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android \
     -dname "CN=Android Debug,O=Android,C=US"
   apksigner sign --ks debug.keystore --ks-pass pass:android patched.apk
   ```
4. **Zipalign** (before signing with `apksigner`, or re-align after if using older tooling): `zipalign -v 4 patched.apk patched-aligned.apk` — check tool availability and adjust order if needed (modern `apksigner` v2/v3 signing is zipalign-order-sensitive).
5. **Verify** the result installs/opens correctly where possible (`apksigner verify patched-aligned.apk` at minimum; actual install/run requires a device or emulator, which may not be available — say so plainly if so, rather than claiming the PoC was runtime-verified when it wasn't).
6. If any of these tools (`apktool`, `apksigner`, `zipalign`, `keytool`) aren't available, say so explicitly and fall back to recommendation/patch-snippet output rather than pretending the rebuild happened.

Never claim an APK PoC was produced unless every step above actually completed — a failed rebuild step means no PoC, not a "best effort" PoC presented as if it worked.

## Output

Update `findings/verified.md` with the fix fields from the orchestrator's `references/workflow-artifacts.md`: `Fix type`, `Fix detail` (the actual recommendation/snippet, or the path to the rebuilt APK/patched smali), `Fix status`. Log completion in `task-log.md`. Tick the finding off as fixed in `checklist.md` only once `Fix status` is `applied-to-poc` or the recommendation has been delivered — not merely attempted.
