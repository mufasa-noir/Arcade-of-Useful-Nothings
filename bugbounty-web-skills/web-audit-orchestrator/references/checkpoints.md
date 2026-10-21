# Checkpoints

A checkpoint is a deliberate stop. Keep the message short (under ~25 lines), concrete, and ending in a specific decision request. Record the decision as a `DECISION` log entry.

## CP0: Scope confirmed (end of Phase 0)
Show: target and version, scope summary (what is in/out, source-only findings accepted?, live testing allowed?), stack guess, budget/depth, anything already known.
Ask: "Is this scope and context correct? Anything to add or exclude before I map the attack surface?"
Gate: scope.md has been confirmed by the human.

## CP1: Attack surface reviewed (end of Phase 1)
Show: stack and entry-point counts, auth model in two lines, the top 8-10 hot spots with the reason each is ranked high, list of things the mapper could not determine.
Ask: "Do the roles and trust boundaries look right? Which hot spots do you want traced first, and is there anything to skip?"
Gate: human picks or confirms the priority list. Put it in human-context.md.

## CP2: Candidates reviewed (end of Phase 2)
Show: candidate table sorted by priority (class, location, auth needed, confidence), count by origin, anything that looks high-value, and what was NOT covered in the hunt.
Ask: "Which of these should go to triage? Anything to drop, merge, or add?"
Gate: human prunes. Dropped candidates are marked `DISMISSED` with the human's reason.

## CP3: Triage results reviewed (end of Phase 3)
Show: for each `LIKELY-TP` and `NEEDS-HUMAN`, a 3-line summary: claim, strongest evidence, strongest counter-argument. For dismissed items, only counts and the top recurring dismissal reasons (offer the full list).
Ask: "Approve these for verification? For NEEDS-HUMAN items, here are the specific questions only you can answer."
Gate: human marks candidates `APPROVED`. Any reason a human gives for dismissing goes into `dismissals.md`.

## CP4: Live-target gate (before ANY request to a live system)
Show: the PoC plan for each approved candidate: exact request(s), which account/role, expected observation, why it is non-destructive, which program rule allows it.
Ask: "Approve this specific plan against this specific target? Or should I verify against a local copy only?"
Gate: explicit approval in this conversation, logged verbatim. Absent approval, verify locally or stop at a source-level report if the program accepts those.

## Style
- Lead with what the human needs to decide, not with process narration.
- Offer a recommendation; do not just dump options.
- If the human replies with new context, apply the context-injection procedure in SKILL.md before continuing.
