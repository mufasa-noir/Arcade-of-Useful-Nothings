# Master Checklist

Copy into `audit/checklist.md` at initialisation (the template in `assets/templates/checklist.md` is the same list). Tick an item only with its log reference: `- [x] P1.3 ... - log#014`. Add items freely (e.g. one per hot spot) using the next free number in the phase.

## Phase 0 Intake
- [ ] P0.1 Target path, commit/tag and deployed version recorded in scope.md
- [ ] P0.2 Program scope, exclusions and testing rules recorded in scope.md
- [ ] P0.3 Stack, prior knowledge, areas to skip recorded in human-context.md
- [ ] P0.4 Depth/budget agreed
- [ ] P0.5 **CP0** human confirmed scope

## Phase 1 Recon (attack-surface-mapper)
- [ ] P1.1 Orientation: README, manifests, framework, build, repo layout; skip-list (vendor/minified/tests) noted
- [ ] P1.2 Code acquired/complete (source maps, bundles, submodules, release tag matches deployed version)
- [ ] P1.3 Route / entry-point inventory complete
- [ ] P1.4 Auth model: authN mechanisms, roles/capabilities, session handling
- [ ] P1.5 Dangerous-capability inventory (SQL, exec, file, HTTP client, deserialize, template, eval)
- [ ] P1.6 Dependency and secrets pass
- [ ] P1.7 Git-history security signals noted (hand-off to patch-variant-hunt)
- [ ] P1.8 Hot spots ranked with reasons
- [ ] P1.9 **CP1** human reviewed map and picked priorities

## Phase 2 Hunt
- [ ] P2.1 patch-variant-hunt: security fixes mined; variant candidates created
- [ ] P2.2 Tool pass (Semgrep/CodeQL/grep seeds) imported as NEW candidates, deduplicated
- [ ] P2.3 source-sink-tracer: one item per prioritized sink/entry point (add rows P2.3a, P2.3b, ...)
- [ ] P2.4 Stored-data (second-order) flows considered for each stored-input route
- [ ] P2.5 authz-matrix-audit: one item per route group (add rows P2.5a, ...)
- [ ] P2.6 Client-side code reviewed where relevant (DOM sinks, secrets, hidden endpoints)
- [ ] P2.7 Candidates deduplicated and prioritised
- [ ] P2.8 **CP2** human pruned candidates

## Phase 3 Triage (candidate-triage; one row per candidate)
- [ ] P3.1 dismissals.md read; citations re-verified for each candidate
- [ ] P3.2 FP criteria run; verdict recorded for each candidate (add rows P3.2a, ...)
- [ ] P3.3 NEEDS-HUMAN questions compiled
- [ ] P3.4 **CP3** human approved candidates for verification

## Phase 4 Verify & report (verify-and-report; one row per approved candidate)
- [ ] P4.1 PoC plan written (non-destructive; local copy preferred)
- [ ] P4.2 **CP4** live-target approval obtained, or local-only decision logged
- [ ] P4.3 PoC executed; observation recorded
- [ ] P4.4 Impact and severity reasoned; duplicate/known-issue check done
- [ ] P4.5 Report drafted in findings/
- [ ] P4.6 Wrap-up logged: findings by status, coverage gaps, next targets
