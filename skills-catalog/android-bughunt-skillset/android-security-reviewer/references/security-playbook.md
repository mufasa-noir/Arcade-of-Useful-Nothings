# Security Reviewer Playbook

Concrete patterns per category. Grep suggestions assume a jadx-style tree (`sources/`) or apktool tree (`smali/` + root `AndroidManifest.xml`) — adjust paths accordingly.

## 1. Manifest & component exposure

Start here, always — it's the attack-surface map.

- `AndroidManifest.xml`: any `<activity>`, `<service>`, `<receiver>`, `<provider>` with `android:exported="true"` — or, on `targetSdkVersion` < 31, no `exported` attribute at all *and* an `<intent-filter>` present (implicitly exported pre-Android 12).
- For each exported component, check whether `android:permission` is set, and if so whether it's a signature-level permission (safe) or a normal/dangerous permission any app can hold (not protective).
- `<provider>` entries: check `android:grantUriPermissions`, `android:exported`, and whether `android:readPermission`/`writePermission` are actually set — an exported provider with no permissions and a broad `<path-permission>` is a classic data-exposure bug.
- Deep links: `<intent-filter>` with `android:scheme`/`android:host` under `<data>` — trace where the resulting Activity reads the Intent/URI and whether it validates the source or just trusts it.
- `android:debuggable="true"` or `android:allowBackup="true"` left in what looks like a release build — both expand attacker capability (debuggable allows attaching a debugger/run-as; allowBackup allows `adb backup` extraction of app data on older API levels or specific configurations).
- `android:usesCleartextTraffic` — covered in detail under Network, but note it here since it's a manifest-level flag.

## 2. IPC & Intent handling

Once you've found an entry point from category 1, trace what happens to the data it receives:

- `getIntent().getExtras()` / `getStringExtra()`/`getParcelableExtra()` etc. used without validating the caller or the data — look for the result flowing into a `startActivity`, file path, SQL query, or reflection call.
- `PendingIntent` created with a mutable/implicit intent and handed to another component — can potentially be intercepted or modified (check for `FLAG_IMMUTABLE` usage, or its absence, keeping in mind API-level defaults changed over time).
- `ContentProvider.query()`/`openFile()` implementations: string-concatenated SQL (injection), or file paths built from caller-supplied input without canonicalization/containment checks (path traversal via `../`).
- Custom permission checks implemented in code (`checkCallingPermission`, `getCallingUid`) that can be bypassed by logic errors (wrong permission string, inverted check, checked after the sensitive action instead of before).

## 3. Data storage & crypto

- **Hardcoded secrets**: string literals that look like API keys, tokens, or passwords — grep for patterns like `"[A-Za-z0-9_\-]{20,}"` near variable names containing `key`, `secret`, `token`, `password`, `apikey`; also check `BuildConfig` fields and `strings.xml` for the same.
- **Weak/custom crypto**: `Cipher.getInstance("AES/ECB/...")` (ECB mode — no IV, pattern-preserving), hardcoded or static IVs passed to `Cipher.init`, home-rolled XOR "encryption," `DES`/`RC4`/`MD5` used for anything security-sensitive (vs. just checksums), keys derived from predictable material (device ID, hardcoded salt with a fast hash).
- **Insecure storage**: secrets or PII written to `SharedPreferences` in plaintext, `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` (legacy but still worth checking), unencrypted SQLite databases holding sensitive data, files written to external storage (`getExternalFilesDir`, `Environment.getExternalStorageDirectory`) without encryption.
- **Weak hashing**: `MessageDigest.getInstance("MD5")` or `"SHA-1"` used for password hashing (vs. `bcrypt`/`scrypt`/`Argon2`/`PBKDF2` with proper iteration counts) — MD5/SHA-1 for non-password integrity checks is lower severity, note the distinction.
- **Revealing comments/logs**: `Log.d`/`Log.v`/`Log.i` calls that print tokens, passwords, full request/response bodies, or stack traces with sensitive data, especially if not stripped for release; decompiled comments (when present, e.g. from Kotlin metadata or debug builds) that reveal internal endpoints, test credentials, or TODOs about known-insecure shortcuts.

## 4. Network & TLS

- `android:usesCleartextTraffic="true"` in the manifest, or a `network_security_config.xml` that allows cleartext for specific/all domains — check `res/xml/network_security_config.xml` if referenced.
- Certificate pinning: absent entirely (not automatically a finding on its own, but worth noting as a gap for sensitive apps), or present but bypassable — e.g. pin set only in a `TrustManager` that's conditionally skipped in a "debug" code path still present in the release build.
- Custom `TrustManager`/`HostnameVerifier` implementations where `checkServerTrusted` or `verify` are empty/no-op (`// TODO` or literally do nothing) — this is one of the highest-value things to grep for: `implements X509TrustManager` and check the method bodies.
- `SSLContext.init` called with a trust-all manager, or `HttpsURLConnection.setDefaultHostnameVerifier` overridden to always return true.
- Secrets or endpoint URLs that reveal internal/staging infrastructure not meant to be user-facing.

## 5. WebView & JS bridge

- `addJavascriptInterface(obj, "name")` — every exposed method on `obj` is reachable from any JS the WebView loads; check what the WebView actually loads (fixed trusted content vs. arbitrary/remote URLs vs. user-influenced URLs) and what the bridge methods can do (file access, other IPC, data exfiltration).
- `setJavaScriptEnabled(true)` combined with `loadUrl()` on a URL built from Intent data, deep-link data, or any external input — can let an attacker control what JS runs in the WebView.
- `setAllowFileAccess(true)` / `setAllowFileAccessFromFileURLs(true)` / `setAllowUniversalAccessFromFileURLs(true)` — these widen what local/remote content can reach.
- `shouldOverrideUrlLoading`/`shouldInterceptRequest` overrides that don't validate the scheme/host before proceeding (open redirect or scheme-confusion risk).
- Target API level: on API < 17, `addJavascriptInterface` is exploitable via reflection regardless of which methods were "intended" to be exposed — check `minSdkVersion` in the manifest/build config.

## 6. Business logic / client-side bypass

- Root/tamper/emulator detection whose result only gates a client-side UI flag (e.g. sets a boolean that disables a button) rather than being enforced server-side too — note that client-side detection is inherently bypassable, but the finding is specifically where it's the *only* enforcement for something security-relevant (DRM, payment, fraud checks).
- License/subscription/paywall checks performed entirely in-app (e.g. a `isPremium` flag read from local storage or computed from a client-side check) without a corresponding server-side entitlement check on the actual protected action/API call.
- Auth state (`isLoggedIn`, role/permission flags) stored and trusted client-side for actions that should be re-verified server-side (e.g. an admin-only screen gated only by a local boolean, with the underlying API not independently checking the caller's role).

## 7. Native libraries (JNI/.so)

- JNI method signatures (`Java_com_example_...`) in native code — check for missing bounds checks on array/buffer accesses derived from Java-supplied lengths, especially where the Java side doesn't independently validate size.
- Hardcoded secrets or security-relevant logic embedded in native code specifically to obscure it from a Java-level read (common evasion pattern) — strings extracted from the `.so` via `strings`/`nm` worth cross-referencing against what the Java layer calls.
- Native code receiving untrusted input (file data, network data, IPC) with C-level memory-safety issues (buffer sizes computed from attacker-influenced values) — flag these even without full exploitability analysis; that's what later verification is for.
- `System.loadLibrary` targets that aren't bundled in the APK's expected `lib/<abi>/` structure (could indicate dynamic loading from a writable path).

## 8. Dependencies

- Library versions visible in `build.gradle`/`build.gradle.kts` if present in the decompiled bundle, `BuildConfig`, or identifiable from class/package names and bundled metadata (e.g. `META-INF` entries, embedded version strings).
- Cross-reference major known-vulnerable libraries by name/version if you recognize them (old OkHttp, old Gson deserialization issues, old WebView-related support libraries) — don't guess CVEs you're not sure about; note the library+version and flag it as "worth checking against current CVE databases" rather than asserting a specific CVE without certainty.

## General notes

- Prioritize findings that are reachable from exported components or network input over ones requiring an attacker to already have local code execution — the latter is lower severity in almost all mobile threat models.
- When in doubt about whether something is "security" vs. "bug," ask: does this let someone bypass a protection, access data they shouldn't, or do something the app's own design didn't intend an external actor to do? If yes, it's a security finding even if the root cause looks like an ordinary logic bug.
