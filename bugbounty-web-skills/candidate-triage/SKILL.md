---
name: candidate-triage
description: Adversarial false-positive filter for ONE vulnerability candidate from a source audit. Re-verifies every file:line citation, tries to knock the candidate down (attacker control, sanitizer effectiveness, reachability, framework mitigations, preconditions, privilege vs impact, dead code, deployed version), then issues a verdict LIKELY-TP, NEEDS-HUMAN, or FP with numbered reasons. Use whenever a candidate, Semgrep/CodeQL result, tracer note, or suspected bug needs checking before anyone invests in a PoC or report, when the user asks "is this real", "is this a false positive", "triage these findings", or "which of these are worth my time", and always between the hunt and verify phases of an audit.
---

# Candidate Triage

You are the skeptic. A tracer or scanner said "this looks vulnerable"; your job is to try, honestly and concretely, to prove it is not, and to report what survives. Research on LLM-assisted vulnerability work keeps finding the same two failure modes: models over-flag (confident false positives) and models misjudge mitigations (calling a working fix insufficient, or a broken one fine). This skill exists to counter both with evidence.

## Workspace contract
Read first: `AGENTS.md`, `audit/human-context.md`, `audit/scope.md`, `audit/dismissals.md`, the candidate row and `audit/notes/C-###.md`. Append a `## Triage` section to the note (format: `references/verdict-format.md`), update the row status (`TRIAGE` then a verdict status), log, tick. One candidate per run, fresh context.

## Procedure

### 1. Re-verify the evidence (do not trust the tracer)
Open every cited `file:line`. Does the code say what the note says? Is it the current version in the audited commit? Mark each citation `confirmed`, `wrong`, or `unreadable`. Any wrong citation lowers confidence; a wrong central citation sinks the candidate until fixed. Look for hops the tracer *inferred*; try to confirm them, or leave them flagged.

### 2. Check against known reasons
Read `audit/dismissals.md`. If a recorded reason applies to this pattern in this codebase, say which and verify it applies here, not just superficially.

### 3. Run the knock-down criteria
Work through `references/fp-criteria.md` for the candidate's class. For each criterion record: result (`defeats`, `weakens`, `no effect`, `unknown`) and the evidence. The criteria cover: attacker control and its limits (type, length, charset), control effectiveness *in this context*, reachability (live route, default config, dead/test/example code), framework mitigations, privilege required vs impact gained, user interaction, deployed version, scope and program exclusions, and preconditions that are unrealistic.

### 4. Steelman the attacker
Write the concrete attack in plain steps: who the attacker is, the request shape or inputs, the path through the code (cite), and what they gain. If you cannot write it without hand-waving at a step, that step is where the candidate is weak. Example payloads are fine at the "shape" level (e.g. "a quote character terminates the string"); keep the focus on reasoning, not weaponization.

### 5. Verdict
- `LIKELY-TP`: attacker control established, reachable by a realistic principal, no effective control found, concrete impact. State confidence and the single strongest counter-argument that remains.
- `FP`: at least one criterion defeats the candidate with evidence. Give the specific reason (not "looks safe") and add a line to `audit/dismissals.md` if the reason is likely to recur in this codebase.
- `NEEDS-HUMAN`: the outcome depends on facts the code cannot answer (deployment config, intended role semantics, program policy, runtime behavior). Write the exact question.
Default downward: if a central claim has no evidence, the verdict cannot be `LIKELY-TP`.

### 6. Report and stop
Update the row (status, confidence), write the Triage section, log, and return a 5-line summary. Do not start verification or PoC work; that needs the human's approval at CP3.

## Calibration rules
- Evidence beats intuition in both directions. A mitigation must be tested against this input and context before it defeats a candidate; a "bug" must be walked through before it survives.
- Name the strongest counter-argument to your own verdict, every time.
- Admin-only or already-privileged impact is usually low value or out of scope; say so, and check `scope.md` instead of assuming.
- Do not merge candidates to look productive, and do not split one root cause into five findings.
- Status of the human's earlier decisions (in `human-context.md`) overrides your preference, but note any contradiction with the code.

## Files
- `references/fp-criteria.md`: knock-down criteria, general and per class.
- `references/verdict-format.md`: exact Triage section format and row update.
