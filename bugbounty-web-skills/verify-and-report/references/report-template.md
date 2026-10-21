# Report Template (findings/F-###.md)

```markdown
# F-###: <vulnerability class> in <component>: <one-line impact>

Linked candidate: C-###   Status: <VERIFIED | REPORTED>   Date: <date>
Program: <name>   Target/version: <version, commit>   Severity (my assessment): <per program table or CVSS vector>

## Summary
<3-5 sentences: what the bug is, who can exploit it, what they gain, and where it lives (file:line).>

## Root cause
<Explain the flaw with path:line citations: source -> hops -> sink, and why the control fails.>
Code references:
- <path:line> <what it does>

## Preconditions
<Required role/config/version/user interaction. Say if default configuration.>

## Steps to reproduce
Environment: <local version / staging / live (approved)>
1. ...
2. ...
Expected result: <specific observation>
Actual result: <what happened; include request/response excerpts with secrets redacted>

## Impact
<Concrete, factual; list what the attacker can do and cannot do. Chains in a separate subsection, labeled.>

## Suggested fix
<Minimal change with the correct control, e.g. use a prepared statement with placeholders; add a capability check before the action; escape with the context-correct function. Note any related call sites to review (variants).>

## Duplicate / known-issue check
<Where you looked: advisories, changelog, public reports; result.>

## Notes and limits
<Anything unverified, version coverage, tested vs reasoned.>
```

## Pre-submit checklist
- [ ] Every claim has a citation or evidence; unverified items labeled.
- [ ] Steps reproduce from a clean state by someone who has not seen the code.
- [ ] Requests/responses contain no secrets or real user data.
- [ ] Version/commit stated and matches shipped code.
- [ ] Impact is factual, limits stated, no speculative chain presented as the base finding.
- [ ] Within scope; excluded classes checked; program rules followed (no prohibited testing).
- [ ] Duplicate check done and recorded.
- [ ] Fix suggestion is minimal and correct for the context.
- [ ] Tone neutral and professional.
