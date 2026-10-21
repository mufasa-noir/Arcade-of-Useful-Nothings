# Variant Analysis Worksheet

Fill one block per fix analyzed. Keep it in `audit/notes/history-summary.md`.

```markdown
### Fix: <commit/version> (<date>) - <title>
- Class:
- Instance: <file:line before> -> <file:line after>
- What changed: <the guard/escape/check added or the unsafe call removed>
- Root cause (one line): Untrusted <X> reached <Y> because <Z>.
- Why developers made it: <helper that looks safe | copy-paste pattern | trusted-input assumption | framework default misunderstood>

#### Variant search
| axis | question | search used | hits | candidates |
|------|----------|-------------|------|------------|
| siblings | same shape elsewhere in the module? | rg '...' | | |
| other entry points | other routes/handlers reaching the same sink? | | | |
| other layers | stored or alternate parameter/method? | | | |
| incomplete fix | all branches / encodings / arrays / casings / write+read paths covered? | | | |
| regression | later refactor dropped the guard? | git log -p -S'...' | | |
| other branches | backported to the deployed branch? | git diff | | |

#### Public coverage
Advisory/changelog/patch in a newer release? <yes/no, where>. Deployed version affected? <yes/no/unknown>.
```

## Questions that find incomplete fixes
- Does the fix sanitize the *parameter that was reported* but not its siblings (`id` vs `ids[]`, `orderby` vs `order`)?
- Does it add the check in the handler but leave a second code path (AJAX vs REST vs admin-post) to the same function?
- Does it escape on output in one template but not in the equivalent email/export/RSS/JSON template?
- Does it block `../` once (non-recursive) or check a prefix without canonicalizing?
- Does it use a blocklist where an allowlist is needed?
- Did it fix the read path but not the stored data already poisoned, or the write path but not the importer?
- Was the fix applied to the main branch only?
