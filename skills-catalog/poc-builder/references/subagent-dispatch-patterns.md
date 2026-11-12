# Sub-agent dispatch patterns

Copy-ready mandate templates for the four patterns in Stage 3 of SKILL.md. Fill in the bracketed parts from the parsed spec. Adapt to whatever sub-agent/worker mechanism the current runtime provides (e.g. Claude Code's Task tool); if none is available, use these same mandates as the labeled "branches" you work through yourself sequentially.

Every mandate should end with the same required return shape so results are easy to converge in Stage 4:

```
RETURN:
- outcome: worked | didn't work | partial
- what was tried (specific values/parameters used, not just "I tried several things")
- artifacts produced (file paths, payloads, commands)
- evidence (output, logs, crash info, response captured)
- anything the next step needs to know
```

## Pattern 1 — Parameter / payload sweep

Use when there's a candidate space (payloads, encodings, offsets, header/param combos) that's cheap to test independently.

```
MANDATE: Test [shard N of M] of the candidate space against [target].
Candidates in this shard: [list or generation rule].
Target/access: [how to reach it — URL, binary path, lab credentials].
Success condition: [exact signal that counts as a hit — specific response,
specific crash signal, specific output value].
Stop condition: stop as soon as a hit is confirmed, or once the shard is
exhausted — don't keep going past a confirmed hit "just to be thorough."
[standard RETURN block]
```

Split the candidate space into roughly equal shards across however many sub-agents are practical (don't over-fragment a small space — a 20-candidate list doesn't need 10 sub-agents).

## Pattern 2 — Timing-sensitive race

Two variants — pick based on what's actually needed.

**2a. Concurrent timing sweep** (don't know the right window yet):

```
MANDATE: Attempt the race at timing offset/interleaving [specific value or
range] against [target], repeated [N] times.
Setup: [what needs to be true before each attempt — process state, allocator
state, etc.]
Success condition: [specific crash signal / state corruption / control-flow
hijack that proves the race landed].
[standard RETURN block, plus: report the hit rate across the N attempts]
```

Assign each sub-agent a distinct offset or offset range so the sweep covers the plausible window without duplicated effort.

**2b. Synchronized complementary roles** (window is known, need precise choreography):

```
MANDATE (role: [free/revoke | use/reclaim]): You are one half of a
two-actor race against [target]. Your role is to [trigger the free /
attempt the use], synchronized against the other actor via [shared
signal/barrier mechanism — file lock, socket signal, shared counter].
Do not proceed past the sync point until [condition].
[standard RETURN block]
```

Only use 2b when the roles are genuinely asymmetric and need coordination, not just "two agents racing the same action" — that's 2a.

## Pattern 3 — Multi-component chain

Use when the exploit genuinely needs independent components (not just independent attempts at the same thing).

```
MANDATE: Build [component — e.g. "the malicious client", "the listener
server", "the firmware patch", "the privesc trigger"].
Interface contract with the other component(s): [exact format of what this
component sends/receives/produces — this is what makes integration work].
Success condition for this component alone: [what proves this piece works
in isolation, before integration].
[standard RETURN block, plus: the interface contract actually implemented,
so it can be checked against the other component(s)]
```

State the interface contract explicitly and identically in every component's mandate — mismatched assumptions here are the most common integration failure.

## Pattern 4 — Independent verification

Use once a PoC appears to work, before it goes in the report.

```
MANDATE: A PoC for [bug] has been built. You have NOT seen how it was
built. Starting from a clean/fresh instance of [target], run the PoC
artifact at [path] exactly as a third party would, with no prior
knowledge of what state it depends on.
Report whether it reproduces the claimed effect: [success condition from
Stage 1], and whether the environment needed any undocumented prior state
to work.
[standard RETURN block]
```

The point of this pattern is catching "it only worked because of leftover state from building it" — so deliberately don't give this sub-agent the build history or reasoning, only the artifact and the target.
