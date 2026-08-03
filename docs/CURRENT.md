# CURRENT — one-screen status

**HEAD:** `b64612a` — docs: embeddings non-goal. Standing-backlog items K14 + D2 + embeddings decided; last open item is the parked R3 residual (optional).

**Last shipped majors:**

- A–D queue complete (`6656021`)
- M1 real `--resume` + SQLite per-scanner checkpoints (`8e7fd3e`, `7f3d216`)
- M2 `vest policy explain` with decision simulation (`169b11d`)
- M3 nuclei as `--scanner nuclei` behind two-key active-probe consent (`9148199`)

**Open (standing only — take work from `docs/standing-backlog.md`):**

- R residuals (documented, not queued): DNS-rebinding TOCTOU (R3), no OS sandbox (R2), simulation-only memory (R4), no external audit (R6)
- K17 honesty: keep docs/ledger honest; close wiring gaps — ongoing
- K14: typed exits for all subcommands done (`0f047c5`) — legacy string fallback removed, unknown errors exit 1
- D2: stringly `ToolError::Handler` retired (`e639536`); `Handler` is last-resort only
- Provider embeddings: documented non-goal (contract); OpenAI-compat wrapper kept, Anthropic/Google keep honest "not implemented" errors, no product callers
- `vest-payloads/`: intentional non-workspace orphan (kept); deletion still an option

**Working rule:** do not invent scope from stale backlog prose. Take work only from `docs/standing-backlog.md`.
