---
name: poc-builder
description: Turns a security bug finding, write-up, or CVE into a working, verified PoC — a runnable exploit, a documented repro procedure, or both, depending on the bug class. Splits work across parallel sub-agents wherever a PoC has independently explorable parts — payload/parameter sweeps, timing-sensitive races (e.g. a narrow use-after-free or TOCTOU window), multi-component exploit chains, independent verification — instead of guessing serially. Keeps a human in the loop at checkpoints (plan approval, a check-in after each sub-agent round, pre-report review) so it doesn't drift mid-build. Use whenever the user asks to build, weaponize, verify, or reproduce a PoC exploit; turn a write-up or CVE into working exploit code; or confirm a bug is exploitable. Any bug class — web, memory corruption/binary, hardware/embedded, mobile, crypto, logic. Trigger even on a bare CVE ID plus "can you PoC this."
compatibility: Designed for agentic coding environments with real tool/filesystem access and some sub-agent or parallel-worker mechanism (e.g. Claude Code's Task tool, or another coding agent's subagent/worker feature). Not tied to any one agent — falls back to a simulated, sequential version of the same decomposition if no sub-agent mechanism is available.
---

# PoC Builder

Turns a bug finding or CVE into a **working PoC** — a runnable exploit, a documented repro procedure, or both, depending on what the bug class calls for — and does it by decomposing the work so independent parts can run in parallel across sub-agents, rather than working one long serial chain.

This is a standalone skill. It does not depend on any other skill, and it is not scoped to one bug class — the same workflow applies whether the finding is a web auth bypass, a heap use-after-free, a firmware glitching target, or a crypto nonce reuse.

## Philosophy: decompose before you build

The single biggest lever here is **not** writing exploit code faster — it's correctly splitting the work *before* writing any code, so that whatever can be explored or attempted independently gets explored or attempted in parallel instead of guessed at one variant at a time. A PoC run that starts writing exploit code before deciding what's parallelizable is doing it backwards. Stage 4 below is the core of this skill; don't skip or rush it.

## Human-in-the-loop checkpoints

This skill runs with a human in the loop, not head-down until a deliverable appears. Checkpoints exist to catch drift early — before a sub-agent round burns time on the wrong track, and before an assembled PoC gets reported as "done" without a sanity check. Default checkpoints:

1. **After Stage 3 — plan approval.** Before any sub-agent is spawned, present the plan: what's parallel vs. direct, which pattern was chosen for each parallel branch, and each mandate. Wait for a go-ahead or an adjustment. This is the most important checkpoint — redirecting a plan is far cheaper than redirecting sub-agents already mid-flight.
2. **After each dispatch round (Stage 4).** Don't chain an unbounded sequence of sub-agent rounds autonomously. When a round of sub-agents returns, summarize what came back — worked / didn't / partial, per branch — before continuing to the next planned round or converging.
3. **On drift.** If a round comes back with no narrowing progress (a whole sweep returns "didn't work" with nothing learned, a timing sweep isn't converging toward a hit rate, sub-agent results start contradicting the plan's assumptions), stop and flag it rather than auto-launching another round of "try again, but more." State what was tried, what's been ruled out, and ask how to proceed — narrower parameters, a different pattern, more info, or stop.
4. **Before Stage 6 — report.** Show the assembled PoC and the Stage 5 verification evidence before writing it up as finished. Last chance to catch "it technically fires but isn't the right bug" before it's reported as a working PoC.

Checkpoints 1–3 only apply once sub-agents are actually in play — if Stage 3 decides everything is "direct" (no parallel branches), skip straight through them. Checkpoint 4 always applies.

---

## Workflow

### 0. Scope & authorization (one line, don't belabor it)

Note in the task log what makes this target in-scope — Deon's own bug bounty program target, a CVE being reproduced in a lab/environment he controls, a CTF, or research he has explicit permission for. This is a one-line confirmation, not an interrogation. If a request is genuinely ambiguous about whether the target is something Deon is authorized to test (e.g. it names a specific live third-party production system with no bounty/authorization context), ask before proceeding rather than assuming.

### 1. Intake — parse the spec

The spec is the contract everything else gets checked against. Write it to `spec.md` before doing anything else.

- **If Deon supplies a write-up or description**: extract the vuln class, affected component/version, preconditions, the vulnerable code path or primitive, and — critically — what **success** looks like (crash with specific signal? RCE with proof of code exec? auth bypass reaching a specific resource? info leak of a specific value? a specific output/state change?). If "success" isn't stated, infer the most natural one for the bug class and state the assumption.
- **If only a CVE ID or a short description is given**: pull the public advisory / NVD entry / vendor bulletin / existing public analysis to fill in the same fields. Ask Deon only for what can't be found publicly — usually access to a target/lab instance, a specific binary, a source checkout, or firmware image.
- Consult `references/vuln-class-playbooks.md` for what "done" typically looks like and what parameters typically matter for the bug's class — this directly feeds Stage 4's decomposition.

### 2. Environment check

Default assumption: **the lab/target already exists and is reachable** — Deon will point to it or have it running. Verify reachability (or compilability, or flashability) first.

- If it's not there and nothing in the request says to build one, ask once rather than assuming — standing up a lab can mean compiling a specific vulnerable version, pulling a container image, or flashing a device, and that's worth confirming rather than guessing at.
- If asked to build the lab: do it, and log every step (versions pinned, build flags, how it was launched) in `task-log.md` — this is also reporting on the environment half of the repro, in case someone else needs to reproduce it later.

### 3. Decompose & plan

Before writing any exploit code or repro steps, produce a short plan: a list of tasks, each tagged either **parallel** (hand to a sub-agent) or **direct** (just do it), each with one concrete mandate and a clear "done" condition.

Use the decision framework below. See `references/subagent-dispatch-patterns.md` for ready-to-use mandate templates for each pattern.

**Split across parallel sub-agents when:**

| Pattern | When it applies | Split strategy |
|---|---|---|
| **Parameter/payload sweep** | Many candidate inputs (payload variants, encodings, offsets, header/param combos, wordlists) that are cheap to test independently, with no shared mutable state between attempts | One sub-agent per shard of the space (e.g. one per encoding family, or batches of N candidates each) |
| **Timing-sensitive race** | TOCTOU, use-after-free, double-free, signal-handler races — the exploitable window is narrow and the exact timing/interleaving needed isn't known in advance | Either (a) each sub-agent tries a distinct timing offset / thread interleaving / retry cadence concurrently to raise the odds of landing in the window within one session, or (b) assign synchronized complementary roles — one sub-agent drives the "free"/revoke action, another drives the "use"/reclaim action, coordinated through a shared signal or barrier |
| **Multi-component chain** | The exploit needs several genuinely independent stages or components (malicious client + listener server; initial-foothold primitive + privesc primitive; a firmware patch + a trigger script) | One sub-agent per component, built in parallel, integrated once each is ready |
| **Independent verification** | A PoC appears to work and needs confirming | A fresh sub-agent with no knowledge of *how* it was built runs it from scratch against a clean target — catches cases where the first attempt only "worked" because of leftover state |

**Don't split — just do it directly — when:**
- There's a single, simple trigger path with no real parameter space (e.g. one unauthenticated endpoint that just returns sensitive data). Sub-agent overhead isn't worth it.
- Steps are inherently sequential and individually cheap, with nothing left to explore in parallel at any given step.

**No native sub-agent mechanism available?** Still do the decomposition — it's what keeps the work organized — but work the branches yourself sequentially, time-boxed, clearly labeled ("Branch A: ...", "Branch B: ..."), rather than silently collapsing back into one long serial attempt.

**🛑 Checkpoint 1 — plan approval.** Present the plan (branches, patterns, mandates) and get a go-ahead or adjustment before moving to Stage 4. Don't dispatch anything yet.

### 4. Dispatch & build

Dispatch in rounds rather than one unbounded wave — this is what makes Checkpoint 2 possible.

For each parallel branch in the current round, spawn a sub-agent with:
- the relevant slice of the spec (not the whole write-up — just what it needs)
- one concrete mandate and done-condition
- whatever target/lab access it needs
- a required return format: what it tried, what worked, what didn't, any artifacts produced, and evidence

**🛑 Checkpoint 2 — after each round.** When a round's sub-agents return, summarize outcomes per branch before continuing. If a round shows no narrowing progress or contradicts the plan's assumptions, that's **Checkpoint 3 (drift)**: stop, say what was tried and ruled out, and ask how to proceed rather than auto-launching another round.

Once a round confirms a working direction: converge — collect what each sub-agent returned, resolve conflicts between approaches, and assemble the actual working PoC — exploit script, payload, patched firmware image, crafted request sequence, whatever the bug class calls for.

### 5. Verify

Run the assembled PoC against the target fresh and capture **hard evidence** that it actually fires — command output, a crash dump/core file, the request/response pair, a log line, a screenshot. "It looks like it should work" is not verification.

Prefer doing this verification pass via a fresh, independent sub-agent (the verification pattern above) rather than the same context that built the PoC, since that's what actually catches a false positive.

If it doesn't reproduce reliably, note the flake rate and go back to Stage 3 — either re-split the problem or refine the approach, rather than shipping a PoC you only got to fire once.

**🛑 Checkpoint 4 — pre-report review.** Show the assembled PoC and the verification evidence before writing Stage 6's deliverables. Get confirmation this is actually the right bug and the right evidence before it's reported as done.

### 6. Report

Produce three deliverables (templates in `references/report-templates.md`):

- **`checklist.md`** — every planned task from Stage 3, ticked off as completed
- **`task-log.md`** — a chronological log of everything attempted, including dead ends and failed sub-agent branches (these are useful — they tell the next person what *not* to retry)
- **`poc-report.md`** — the actual write-up: vulnerability summary, affected target/version, preconditions, the exploit/repro steps, the evidence it works, and the PoC artifact itself (script/payload) embedded or linked

Which kind of PoC goes in the report depends on the bug class: a runnable exploit script/payload where that's natural (web, binary, most logic bugs), a fully documented step-by-step repro procedure where a script doesn't make sense or isn't the point (some hardware/physical-access bugs, some race conditions that are easier to narrate than script), or both.

---

## Reference files

- `references/vuln-class-playbooks.md` — per-vuln-class cheat sheet: what "success" typically means and what parameters typically matter (feeds Stage 1 and Stage 3)
- `references/subagent-dispatch-patterns.md` — copy-ready sub-agent mandate templates for each pattern in the Stage 3 table
- `references/report-templates.md` — skeletons for `checklist.md`, `task-log.md`, `poc-report.md`
