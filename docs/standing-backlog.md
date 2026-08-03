# Standing Backlog

**Branch:** `main` only.  
**Queue status:** A–D (`docs/next-backlog.md`) and M1–M3 (`docs/major-backlog.md`) are complete. **This file is the only place to take work from.**  
**Method:** Take the first unchecked item; code + tests; fmt/clippy/relevant tests; update docs; commit (Zelmari only, no `Co-authored-by: Cursor`).  
**Standing non-claims (R1–R6):** do not "clear" them by claiming more than is true.

## Items

- [x] Sync stale docs (resume/policy-explain claims) — done in the resume-ready tightening pass (`f1fbf3e`)
- [x] Acceptance scenarios for resume / nuclei / policy explain — rows added to `docs/acceptance-scenarios.md`
- [x] `rust-toolchain.toml` pin (1.96.1) — added, matches ledger + CI
- [x] Decide `vest-payloads/` — documented as intentional non-workspace orphan (README + AGENTS); delete remains an option
- [x] K14 residual: typed exits for all non-scan subcommands — done (`0f047c5`); legacy string fallback removed; unicode byte-slice panics fixed
- [x] D2 residual: stringly `ToolError::Handler` retired — done (`e639536`); typed `MissingParameter`/`PathNotFound`/`Io`/`Client`/`Egress` variants, `Handler` is last resort only
- [x] Provider embeddings decision — documented as a non-goal in `docs/product-contract.md`; OpenAI-compat `/embeddings` wrapper kept, Anthropic/Google keep explicit “not implemented” errors, no product callers
- [ ] R3 (optional, hard): connect-time socket pin for `ScopedHttpClient` when `deny_private_targets` is on — standing residual otherwise, do not claim as fixed

## Loop prompt

```
On main only. Read AGENTS.md, then docs/CURRENT.md, then docs/standing-backlog.md.
Take the first unchecked item. Implement + tests as needed, fmt/clippy/relevant tests,
update docs, commit (Zelmari only, no Co-authored-by Cursor). Continue until queue empty.
Do not invent scope beyond the standing backlog.
```
