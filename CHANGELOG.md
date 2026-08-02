# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
where practical for a pre-1.0 experimental toolkit.

## [Unreleased]

### Security (hardening / verified security pass)

- Central **policy engine** gates every agent tool call by explicit `ToolEffect`, filesystem/network scope, and argument digest. Registry `requires_approval` is not a bypass.
- **Unknown tools and unknown effects are denied** (fail closed).
- **Filesystem and network scopes** use canonical path / parsed origin checks; web crawler disables auto-redirects and re-authorises URLs; `robots.txt` can be enforced.
- **Model egress boundary**: tool results and validator findings use `DataEgressClass`, size bounds, redaction, and allowlisted DTOs. Local file content and process memory are not sent to remote models by default.
- **Memory scanner** defaults to unsupported; opt-in simulation only via `--allow-memory-simulation` (explicitly tagged, not live PID memory).
- **API keys**: `providers set-key` never echoes secrets; prefer environment variables. `.env` is documented as plaintext on disk, not an OS credential store.
- **Config fail-closed** when a present `vest.toml` is malformed or has invalid safety/scanner sections.
- Provider fallback `TryAllParallel` uses real concurrency (`FuturesUnordered`) with timeouts/cancel-on-first-success semantics.
- Validator preserves local findings on provider/parse failure; severity uses `severity_score_estimate` metadata rather than claiming real CVSS.

### Documentation

- README aligned with verified behaviour; experimental warning; migration notes; correct clone/install paths (`https://github.com/Zelmari/vest`, `cargo install --path vest-cli`).
- Added `SECURITY.md`, `docs/agent-tool-policy.md`, `docs/model-data-boundary.md`, `LICENSE` (MIT), and this changelog.
- Workspace `repository` metadata points at `https://github.com/Zelmari/vest`.

### Breaking changes

See README **Migration notes** for operator-facing breaks (`set-key` output, unknown-tool deny, memory simulation flag, config fail-closed, egress defaults).
