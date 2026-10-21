# Audit Checklist

Tick an item only with its log reference: `- [x] P1.3 text - log#014`. Add rows as needed.

## Phase 0 Intake
- [ ] P0.1 Target path, commit/tag and deployed version recorded in scope.md
- [ ] P0.2 Program scope, exclusions and testing rules recorded in scope.md
- [ ] P0.3 Stack, prior knowledge, areas to skip recorded in human-context.md
- [ ] P0.4 Depth/budget agreed
- [ ] P0.5 **CP0** human confirmed scope

## Phase 1 Recon
- [ ] P1.1 Orientation done; skip-list noted
- [ ] P1.2 Code complete; release tag matches deployed version
- [ ] P1.3 Route / entry-point inventory complete
- [ ] P1.4 Auth model documented
- [ ] P1.5 Dangerous-capability inventory done
- [ ] P1.6 Dependency and secrets pass done
- [ ] P1.7 Git-history security signals noted
- [ ] P1.8 Hot spots ranked with reasons
- [ ] P1.9 **CP1** human reviewed map and picked priorities

## Phase 2 Hunt
- [ ] P2.1 Security fixes mined; variant candidates created
- [ ] P2.2 Tool pass imported as NEW candidates, deduplicated
- [ ] P2.3 Traces (one row per prioritized sink / entry point):
- [ ] P2.4 Stored-data (second-order) flows considered
- [ ] P2.5 Authz matrices (one row per route group):
- [ ] P2.6 Client-side code reviewed where relevant
- [ ] P2.7 Candidates deduplicated and prioritised
- [ ] P2.8 **CP2** human pruned candidates

## Phase 3 Triage
- [ ] P3.1 dismissals.md read; citations re-verified
- [ ] P3.2 Verdict recorded for each candidate (one row per candidate):
- [ ] P3.3 NEEDS-HUMAN questions compiled
- [ ] P3.4 **CP3** human approved candidates for verification

## Phase 4 Verify & report
- [ ] P4.1 PoC plan written (non-destructive; local copy preferred)
- [ ] P4.2 **CP4** live-target approval obtained, or local-only decision logged
- [ ] P4.3 PoC executed; observation recorded
- [ ] P4.4 Impact, severity, duplicate/known-issue check done
- [ ] P4.5 Report drafted in findings/
- [ ] P4.6 Wrap-up logged: findings by status, coverage gaps, next targets
