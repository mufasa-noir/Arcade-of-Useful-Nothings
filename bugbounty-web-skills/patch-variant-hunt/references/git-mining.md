# Git Mining Cheat Sheet

Contents: commit message scans, content-based scans, version diffs, history shape, advisories, writing a rule from a fix.

## Commit message scans
```bash
git log --oneline -i --grep='security\|vuln\|cve-\|xss\|sqli\|sql injection\|inject\|csrf\|ssrf\|traversal\|sanitiz\|escape\|nonce\|capabilit\|permission\|authoriz\|bypass\|hardening\|fix.*(auth|access)' | head -200
git log --all --oneline -i --grep='revert' | head -50
git log --format='%h %ad %s' --date=short -i --grep='security' --since='3 years ago'
```
Also scan `CHANGELOG*`, `readme.txt`, `RELEASES`, and GitHub release notes for words like "security", "hardening", "escape", "sanitize", "capability check".

## Silent fixes: content-based scans
Guards added in a commit often have no security message. Search for diffs that ADD a protective call:
```bash
git log -p -G'prepare\(|esc_html|esc_attr|esc_url|wp_kses|current_user_can|check_ajax_referer|wp_verify_nonce|absint|intval' --since='3 years ago' -- '*.php'
git log -p -G'parameterized|escapeHtml|DOMPurify|sanitize|authorize|requireAuth|permission_classes|@PreAuthorize' --since='3 years ago'
git log -S'wp_ajax_nopriv_' --oneline        # when unauthenticated hooks were added or removed
git log -S'permission_callback' --oneline
```
Adapt the regex to the stack (see the stack catalog's "grep seeds").

## Version diffs
```bash
git diff <deployed-tag>..<latest-tag> --stat
git diff <deployed-tag>..<latest-tag> -- <dir>          # review only security-relevant directories
git log <deployed-tag>..<latest-tag> --oneline          # what changed after the deployed version
```
Fixes in the range between deployed and latest are, by definition, bugs that may still be live on the deployed version. For packaged software without a repo, diff two extracted release archives (`diff -ru old/ new/`).

## History shape
```bash
git log --format='%h %an %ad %s' --date=short -- <path>       # churn and authors for a risky file
git blame -w -C <file>                                         # who wrote this guard, when, with what message
git log --follow -p -- <file>                                  # file history including renames
git shortlog -sn -- <dir>                                      # who maintains this area (bus factor)
```
High churn plus few tests plus no review around a sensitive file is a hot spot.

## Advisories and databases
Check: the project's security policy and advisories page, the ecosystem registry advisories (npm/PyPI/Packagist/Maven), CVE/NVD/OSV entries for the product and for each reachable dependency, and prior bounty disclosures if public. For WordPress plugins, check the plugin's changelog and public vulnerability databases for the slug.

## Turning a fix into a search rule
From the diff, identify (a) the vulnerable shape (call + argument form), (b) the safe shape that replaced it. Then:
```bash
rg -n '<vulnerable regex>' --glob '!vendor' --glob '!node_modules'
```
or a Semgrep rule: `pattern: <vulnerable shape>` with `pattern-not: <safe shape>`, run across the repo. Review every hit for the same root cause; confirm by reading.
