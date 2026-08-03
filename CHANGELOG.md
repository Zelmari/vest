# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
where practical for a pre-1.0 experimental toolkit.

## [Unreleased]

### Security / product hardening (on `main`)

- **`--no-approval`** means non-interactive deny for approval-required ops. It no longer installs a permissive safety checker.
- **`ExecutionSession`** carries FS/net scopes per run (replaces process-global tool scope OnceLocks).
- **`ScopedHttpClient`** foundations for scanner HTTP; web client construction fails closed (no silent `Client::default()` fallback).
- Opaque **`ApprovedToolCall`** capability: `execute_authorised` requires a policy-minted token with SHA-256 argument binding (not a forgeable public `Allow`).
- Invalid explicit **`--target-type`** is rejected instead of guessed.
- Typed **`VestError::cli_exit_code()`** preferred for exits (legacy string matching remains as fallback on some paths).
- `.env` loading allowlists Vest/provider keys.
- Safe Unicode **`truncate_chars`** helper in `vest-core`.

### Still open (honest)

- No interactive approval prompt (`RequireInteractive` → deny).
- CLI agent HTTP tools still use `ureq` in places (not fully on `ScopedHttpClient`).
- CLI `vest scan --scanner web` still enables active probes by default.
- Some scanners still populate heuristic `cvss_score` values.
- No `vest doctor` / `--offline` yet.

### Security (earlier verified hardening pass)

- Central **policy engine** gates every agent tool call by explicit `ToolEffect`, filesystem/network scope, and argument digest. Registry `requires_approval` is not a bypass.
- **Unknown tools and unknown effects are denied** (fail closed).
- **Filesystem and network scopes** use canonical path / parsed origin checks; web crawler disables auto-redirects and re-authorises URLs; `robots.txt` can be enforced.
- **Model egress boundary**: tool results and validator findings use `DataEgressClass`, size bounds, redaction, and allowlisted DTOs. Local file content and process memory are not sent to remote models by default.
- **Memory scanner** defaults to unsupported; opt-in simulation only via `--allow-memory-simulation` (explicitly tagged, not live PID memory).
- **API keys**: `providers set-key` never echoes secrets; prefer environment variables. `.env` is documented as plaintext on disk, not an OS credential store.
- **Config fail-closed** when a present `vest.toml` is malformed or has invalid safety/scanner sections.
- Provider fallback `TryAllParallel` uses real concurrency (`FuturesUnordered`) with timeouts/cancel-on-first-success semantics.
- Validator preserves local findings on provider/parse failure; severity uses estimate metadata rather than claiming real CVSS.

### Documentation

- README states experimental status, AI-assisted authorship, and known gaps.
- Added `SECURITY.md`, product contract / ledger / data-flow docs, `LICENSE` (MIT), and this changelog.
- `docs/security-hardening-audit.md` is a **historical** audit snapshot from the first hardening branch — check the ledger for current status.

### Breaking / operator-facing behaviour

- Present but malformed `vest.toml` fails closed (no silent defaults).
- Unknown / unregistered tools are denied.
- Memory scanning requires `--allow-memory-simulation` and is tagged as simulation.
- `providers set-key` prints setup instructions only (never echoes the secret).
- Model egress defaults block local file content and process memory toward remote providers.
- `--no-approval` denies approval-required operations (does not allow everything).
