# Convention Reviewer Playbook

## Establishing a baseline first

Before flagging anything, sample 10-15 classes across different packages and note:
- Typical naming style (packages, classes, methods, fields)
- Typical obfuscation level (is the whole app ProGuard/R8-obfuscated with short names, or mostly readable?) — if the whole app is obfuscated, a short-named class is normal, not anomalous. The signal is a class that's *less* obfuscated or *differently* obfuscated than its neighbors, not obfuscation itself.
- Typical error-handling and logging style
- Package structure vs. the manifest's declared package name

Everything below is judged relative to this baseline, not against an abstract "good code" standard.

## Ordinary convention issues

- Naming inconsistency within one package (mixed casing conventions, inconsistent abbreviations)
- Deprecated Android API usage (e.g. `AsyncTask`, old permission-check patterns) where newer equivalents are used elsewhere in the same app
- Dead code: unused classes/methods, unreachable branches, commented-out blocks left in (decompilers sometimes preserve debug info that reveals this)
- Inconsistent logging (some classes behind a logger abstraction, others using raw `Log.d`/`System.out`, especially in release builds where that's itself worth a lower-confidence note)
- Magic numbers/strings duplicated instead of using existing constants defined elsewhere in the same codebase

## Anomaly signals (higher priority, flag to security reviewer)

- **Obfuscation mismatch**: one class/package stands out from the app's general obfuscation level in either direction.
- **Unexplained dynamic loading**: `DexClassLoader`, `PathClassLoader` with external paths, `System.loadLibrary` for a library name that doesn't match the app's apparent purpose, runtime `.dex`/`.so` fetching.
- **Unexplained reflection**: reflective access to fields/methods that have normal public accessors elsewhere — reflection is sometimes legitimate (framework interop) but worth a second look when it reaches sensitive APIs (crypto, account manager, package manager).
- **Permission without feature**: a declared permission in the manifest with no corresponding UI/feature that would plausibly need it.
- **Orphan strings/resources**: strings in `res/values/strings.xml` or similar that reference a different app name, different company, test/debug content, or look like leftover template/sample code.
- **Package/manifest mismatch**: directory structure under `smali/`/`sources/` using a different base package than `AndroidManifest.xml`'s `package` attribute, or multiple unrelated top-level packages in a single-purpose app — can indicate bundling of a second, unrelated payload.
- **Suspicious build metadata**: version/build info in the manifest or resources that doesn't match what's plausible for the app's actual feature set (e.g. signs of being built from a different, larger project and stripped down).

## How to phrase findings

For anomaly signals especially, describe *what's different and from what baseline* — "this class uses reflection to call `Class.forName` on a PackageManager-adjacent API, which no other class in the app does" is useful; "this looks suspicious" is not.
