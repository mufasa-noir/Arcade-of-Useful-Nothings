---
name: patch-variant-hunt
description: Mines a web project's security history (git log, release diffs, changelogs, advisories, reverted fixes) to find fixed vulnerabilities, then performs variant analysis to find the same root cause elsewhere, incomplete fixes, and bypasses. Use whenever the user wants to check past CVEs or security patches for a target, find silent security fixes between versions, hunt variants of a known bug, look for incomplete patches or fix bypasses, review security-related commits, or says "what was fixed recently", "look at the git history for security", "find bugs similar to this CVE", or "diff these two versions". Run early in an audit because history tells you where the developers' blind spots are.
---

# Patch and Variant Hunt

Bugs cluster. A fix tells you the root cause the developers finally understood, and the same root cause usually survives in sibling code, other entry points, older branches, or in the fix itself. Mining history converts "somewhere in 200k lines" into "near here, and here is the pattern".

## Workspace contract
Read first: `AGENTS.md`, `audit/human-context.md`, `audit/scope.md`, git-history signals in `audit/attack-surface.md`. Output: candidate rows (`origin: variant`) and notes for each, plus a short `audit/notes/history-summary.md` listing fixes analyzed. Log, tick P2.1. Cite `path:line` and commit hashes.

## Procedure

### 1. Collect fixes
Use `references/git-mining.md`: keyword scans of commit messages, `git log -S` / `-G` pickaxe for sanitizer or guard additions, diffs between the deployed version and the latest release, changelog/readme "security" entries, repository advisories, issue tracker, and CVE/advisory databases for the product and its dependencies. Include reverted and re-applied commits (often an unfinished fix) and fixes that landed without a security message (a new escaping call, a new capability check, a prepared statement replacing concatenation).
Record each fix as: commit/version, date, what changed (`file:line` before/after), class, and claimed severity. Aim for the 10-20 most informative, not everything.

### 2. Extract the root cause (per fix)
Write one line: "Untrusted X reached Y because Z was missing/wrong." Distinguish the *instance* (this call site) from the *root cause* (a helper that does not escape, a base class that skips auth, a pattern developers keep writing). The second is what generalizes.

### 3. Hunt variants
For each root cause, search for the same pattern elsewhere:
- **Siblings:** other functions in the same file/module doing the same thing; other handlers calling the same helper; same mistake in other actions of one dispatcher.
- **Other entry points:** another route, API version, import/export path, AJAX vs REST vs form handler that reaches the same sink.
- **Other layers:** same bug via a stored value, a different parameter, a different HTTP method, or a different file type.
- **Incomplete fix:** does the patch cover all branches, all parameter names, all encodings and casings, arrays vs strings, both write and read paths? Is the check placed before the dangerous operation on every path? Can the fix be bypassed by an alternative route to the same function?
- **Regressions:** a refactor after the fix that dropped the guard; feature added later that copies the old pattern.
- **Other branches/forks:** older supported branches missing the backport (check whether the deployed version is one of them).
Use `rg` for the pattern, Semgrep for structural variants (write a rule from the fix diff: pattern = vulnerable shape, with the sanitizer as pattern-not), and the stack catalog for sink names.

### 4. Create candidates
One candidate per distinct variant location, with a note: the original fix reference, the shared root cause, why this location is unpatched, and `unverified:` for anything not yet traced. Hand each to `source-sink-tracer` via the orchestrator; do not trace deeply yourself.

### 5. Dedupe against public knowledge
For each candidate, record whether a public advisory, changelog line, or patch already covers it in a newer release (a bug fixed in a newer version may still be live on the deployed one; say which). Duplicate risk is real in bounty programs: note it for the human.

## Rules
- Fixes are leads, not findings. Every variant still needs the tracer and triage.
- Keep a fix log even for fixes that produce no variants; it documents coverage.
- Do not run exploits from public advisories against live targets. Use advisories to understand the pattern.
- Stay within the audited version and scope; note when a variant exists only in an out-of-scope version.

## Files
- `references/git-mining.md`: commands and search patterns.
- `references/variant-analysis.md`: root-cause extraction and variant search worksheet.
