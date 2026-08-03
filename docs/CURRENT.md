# CURRENT — one-screen status

**HEAD:** `936e564` — docs: acceptance rows for resume, policy explain, nuclei (M1–M3). Product tip: `9148199` (M3 `--scanner nuclei`).

**Last shipped majors:**

- A–D queue complete (`6656021`)
- M1 real `--resume` + SQLite per-scanner checkpoints (`8e7fd3e`, `7f3d216`)
- M2 `vest policy explain` with decision simulation (`169b11d`)
- M3 nuclei as `--scanner nuclei` behind two-key active-probe consent (`9148199`)

**Open (standing only — take work from `docs/standing-backlog.md`):**

- R residuals (documented, not queued): DNS-rebinding TOCTOU (R3), no OS sandbox (R2), simulation-only memory (R4), no external audit (R6)
- K17 honesty: keep docs/ledger honest; close wiring gaps — ongoing
- K14 residual: typed exits cover scan/completions; other subcommands still hit the string-match fallback
- D2 residual: stringly `ToolError::Handler(String)` in agent tool handler bodies
- Provider embeddings: OpenAI-compat implemented; Anthropic/Google are honest "not implemented" stubs — decide wire-or-reject
- `vest-payloads/`: intentional non-workspace orphan (kept); deletion still an option

**Working rule:** do not invent scope from stale backlog prose. Take work only from `docs/standing-backlog.md`.
