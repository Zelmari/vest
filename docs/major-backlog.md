# Vest Major Backlog (next 3)

**Branch:** `main` only  
**Method:** Implement one major at a time; commit at each meaningful change; keep CI green.  
**Commits:** Zelmari only — no `Co-authored-by: Cursor`.

## Why these three

Chosen as the highest-leverage product unlocks left after the A–D queue:

1. **`--resume` for real** — currently hidden + fail-closed; scans only persist at finalize, so crashes lose work.
2. **`vest policy explain`** — doctor dumps static config; operators still cannot simulate grant/deny decisions.
3. **Nuclei as a first-class scanner** — wrapper + orphaned config exist; not wired into `--scanner`.

Standing non-claims (R1–R6) remain out of scope. Memory stays unsupported/simulated only.

---

## M1 — Real scan checkpoint + `--resume`

**Goal:** Scanner-granular resume. Crash mid-scan → `vest scan --resume <SCAN_ID>` continues remaining scanners.

### Design
- Create `running` scan row + target **before** scanners (not only at finalize).
- New table `scan_scanner_checkpoints` (`scan_id`, `scanner`, `status`, `completed_at`, `error`).
- After each successful scanner: one SQLite transaction = checkpoint row + that scanner’s findings.
- `--resume SCAN_ID`: load scan/target/findings/checkpoints; skip completed scanners; run remainder; finalize via **update** (status/counts/timestamps).
- Agent phase: not resumable in M1 (re-run agent after scanners if configured, or skip if already marked done in config checkpoint phase).
- Unhide `--resume`; make `TARGET` optional when `--resume` is set.
- Reject resume of `completed` scans; optional target match if TARGET provided.

### Acceptance
- [x] Storage APIs + migration for checkpoints
- [x] Early `start_scan` + mid-scan persist + finalize update
- [x] `--resume` works; help shows the flag
- [x] Tests: storage checkpoint; CLI resume path; update soft-dead tests
- [x] Docs touch (README / product contract one-liner)

---

## M2 — `vest policy explain`

**Goal:** Operator-facing explanation of tool effects, evaluation order, CLI pre-grants, and optional simulation.

### Design
- New subcommand: `vest policy explain` (+ optional `--tool` / `--effect` / `--url` / `--path` + approve flags).
- Static sections: effect catalog, evaluation pipeline, registered tools, CLI flag → effect map, two-key active-probe consent, egress vs action.
- Simulation: build synthetic `AuthorisationContext` + `NormalisedToolCall`, call `PolicyEngine::evaluate`, print decision.
- Keep `vest doctor` for paths/config; avoid duplicating entire doctor — share a small safety/egress summary helper if cheap.

### Acceptance
- [ ] CLI wiring + `commands/policy.rs`
- [ ] Simulation path with Deny/Allow/RequireInteractive
- [ ] Tests asserting key sections + one simulated deny/allow
- [ ] README mention under diagnostics

---

## M3 — Nuclei as `--scanner nuclei`

**Goal:** First-class scanner using existing `NucleiTool`; config under `[scanner.nuclei]`.

### Design
- Promote `nuclei_*` from `WebScannerConfig` into `NucleiScannerConfig` (migrate aliases if needed).
- `vest-scanner` `NucleiScanner` implementing `Scanner`; map `NucleiFinding` → `Finding`.
- Wire `"nuclei"` arm in `run_builtin_scanners` + `known_scanner`.
- **Not** a target-type default — require `--scanner nuclei` or profile.
- Gate on active-probe consent (same two-key as web active probes).
- Fail clearly if nuclei binary / templates missing.

### Acceptance
- [ ] Config section + scanner module
- [ ] CLI wiring + consent gate
- [ ] Unit/integration tests (fake binary where practical)
- [ ] Docs: `--scanner nuclei`

---

## Housekeeping (do first)

- [x] Harden `.gitignore` (SARIF/reports, agent debris, common secrets)
- [x] Remove GitHub `cursoragent` contributor: delete stale remote branch `product/real-world-hardening` (still has `Co-authored-by: Cursor`); verify `main` has zero co-author trailers; prune
  - Note: GitHub Insights may lag; local/remote refs no longer contain Cursor co-author trailers.

## Loop prompt

```
On main only. Read docs/major-backlog.md. Take the first unchecked acceptance item
under the first incomplete major (M1→M2→M3). Implement + tests, fmt/clippy/relevant
tests, mark checkbox, commit (Zelmari only, no Co-authored-by Cursor). Continue
until all majors and housekeeping are done.
```
