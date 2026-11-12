# Report templates

Skeletons for the three Stage 6 deliverables. Keep them as plain markdown files alongside the PoC artifact(s).

## checklist.md

```markdown
# Checklist — [bug name/CVE]

- [x] Spec parsed (spec.md)
- [x] Environment verified reachable
- [ ] Stage 3 plan drafted
- [ ] Branch A — [task]: [sub-agent | direct]
- [ ] Branch B — [task]: [sub-agent | direct]
- [ ] ...
- [ ] PoC assembled
- [ ] Verified via independent pass
- [ ] Report written
```

Tick items off as they're actually done — don't pre-check items to make the list look clean.

## task-log.md

```markdown
# Task log — [bug name/CVE]

## [timestamp] Spec intake
- Parsed from: [write-up provided | CVE-XXXX-XXXXX advisory]
- Success condition: [...]

## [timestamp] Environment
- [what was verified/built, versions, commands used]

## [timestamp] Stage 3 plan
- [the decomposition decided on, and why — which pattern(s) applied]

## [timestamp] Branch A — [sub-agent | direct]
- Mandate: [...]
- Outcome: [worked | didn't work | partial]
- Notes: [include dead ends — what was tried and ruled out, not just what worked]

## [timestamp] Branch B — ...

## [timestamp] Verification
- Method: [independent sub-agent | direct re-run]
- Result: [...]
- Evidence: [pointer to captured evidence]
```

Log dead ends and failed branches, not just the successful path — that's what makes this useful to come back to later.

## poc-report.md

```markdown
# PoC report — [bug name/CVE]

## Summary
[One paragraph: what the bug is, where it lives, impact.]

## Target
- Component/product: [...]
- Affected version(s): [...]
- Environment used for this PoC: [...]

## Preconditions
[What has to be true for the PoC to work — access level, config, build flags, etc.]

## Exploit / repro
[Either the runnable script/payload (embedded or linked), or a numbered
step-by-step repro procedure, or both — whichever the bug class calls for.
Be exact: exact commands, exact inputs, exact expected output at each step.]

## Evidence it works
[The hard evidence from Stage 5 verification — command output, crash
dump excerpt, request/response pair, screenshot reference, etc. Include
the independent-verification result, not just the original build.]

## Notes / caveats
[Reliability/flake rate if not 100%, anything environment-specific that
might not transfer, suggested fix if relevant.]
```
