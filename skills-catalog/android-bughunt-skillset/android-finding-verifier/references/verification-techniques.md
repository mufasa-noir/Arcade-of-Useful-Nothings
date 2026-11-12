# Verification Techniques by Finding Type

Concrete steps to actually confirm (or refute) a finding, by category. "Confirm" means you did the thing below and can point to what you saw — not that it seems plausible.

## Manifest & component exposure (SEC, category 1)

- Re-open `AndroidManifest.xml` yourself; don't trust the reviewer's quoted attribute. Confirm `exported="true"` (or implicit exposure via intent-filter on old `targetSdkVersion`) is actually present on that exact component.
- Check every `android:permission` on the component, and separately check whether that permission is declared with `android:protectionLevel="signature"` (or `signatureOrSystem`) elsewhere in the manifest — a normal/dangerous-level permission does not meaningfully restrict who can hit the component.
- Open the component's class and read what it does with no assumptions about caller identity — if it immediately performs a sensitive action without further checks, that's reachability confirmed.

## IPC & Intent handling (SEC, category 2)

- Trace the actual data flow from `getIntent()`/`onBind()`/provider method parameters to where it's used. Confirm there's no validation step you missed in between (check for early returns, helper methods that might validate, or try/catch that silently neutralizes bad input).
- For `PendingIntent` findings, confirm the actual flags used (`FLAG_IMMUTABLE`, `FLAG_MUTABLE`) at the exact construction site and cross-check against the API level where defaults changed, using `minSdkVersion`/`targetSdkVersion`.
- For `ContentProvider` injection/traversal findings, read the exact query-building code — confirm it's real string concatenation of untrusted input (not, e.g., a parameterized query that looks risky but isn't) and for path traversal, confirm there's no canonicalization/prefix check on the resulting path.

## Data storage & crypto (SEC, category 3)

- For hardcoded secrets: confirm the string is actually used as a live credential (passed to an auth header, used as a key, etc.) and not, e.g., a placeholder/example that's never exercised.
- For weak crypto: confirm the actual `Cipher.getInstance(...)` string and IV handling at the call site — "uses AES" isn't enough, confirm the mode and IV source.
- For insecure storage: confirm what's actually written (open the write call, not just the file open) and confirm it's genuinely sensitive data, not, e.g., a non-sensitive cache.

## Network & TLS (SEC, category 4)

- For custom `TrustManager`/`HostnameVerifier`: read the full method body of `checkServerTrusted`/`verify`, not just the class name — confirm it's actually a no-op or always-true, not a real (if unusual) validation implementation.
- For cleartext traffic: confirm the manifest/network-security-config setting actually applies to the domains the app uses (a network-security-config can scope cleartext exceptions narrowly — check whether the exception covers more than the finding assumed).
- Cross-reference: if a `TrustManager` bypass exists but is only wired up behind a `BuildConfig.DEBUG` check that's `false` in the build you're reviewing, that's a guard — downgrade accordingly (still worth noting as present-but-dormant).

## WebView & JS bridge (SEC, category 5)

- Confirm what `loadUrl`/`loadData` is actually called with at runtime — a fixed, bundled HTML asset is very different from a URL built from Intent/deep-link data. Trace backward from the `WebView` instance to how its URL/content is determined.
- For `addJavascriptInterface`, enumerate the actual public methods on the bound object and assess what each one can do — the finding is only as serious as the most dangerous exposed method.
- Confirm `minSdkVersion` for the pre-17 reflection-based exploitation note; if `minSdkVersion` >= 17, that specific angle doesn't apply (the general "arbitrary bridge method exposure" point still can).

## Business logic / client-side bypass (SEC, category 6)

- This category lives or dies on whether there's a server-side check. You can't always confirm server-side behavior from source alone — if the app's networking code reveals the actual API being called, check whether the request includes anything that looks like it depends on a prior server-verified state (a signed token, a server-issued entitlement) vs. the client just asserting a boolean. If you genuinely can't tell from source, mark `unverified` and say so explicitly — don't assume either way.

## Native libraries (JNI/.so) (SEC, category 7)

- Confirm the actual JNI function signature and trace what Java-side data flows into it, and whether any length/bounds value is attacker-influenced before it reaches native code.
- If full native-code tracing is beyond what's feasible statically (no decompiled native source, only strings/symbols available), say so and mark `unverified` with a note on what tool/approach would be needed (e.g. Ghidra/IDA on the `.so`) rather than guessing.

## Dependencies (SEC, category 8)

- Confirm the exact library name and version string you can see, and be explicit that you have not independently checked it against a live CVE database (unless you actually have, with a tool). Mark as `confirmed` only for "this version is present," not for "this version is vulnerable to CVE-X" unless you've verified that mapping with a real source.

## Bug-reviewer findings (BUG-*)

- Lifecycle/resource-leak findings: confirm by tracing the full lifecycle method set for the class (not just the one method cited) to see whether a cleanup path exists elsewhere that the raw finding missed.
- Concurrency findings: confirm the field/collection in question is genuinely accessed from more than one thread — trace both access sites, don't assume from a single site that looks suspicious.
- Logic errors: re-derive the logic yourself from the actual conditionals rather than trusting the reviewer's restatement of what it does.

## Convention-reviewer anomaly findings (CONV-*, flagged to security)

- Re-establish whether the "baseline" the convention reviewer used was reasonable — sample a few more classes yourself if the anomaly claim seems borderline.
- Assess the anomaly against the security categories above (does the anomalous reflection/dynamic-loading/permission actually lead anywhere sensitive?) rather than verifying it as "anomalous" per se — anomaly alone isn't a severity-bearing finding, what it enables is.
