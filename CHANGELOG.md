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
- Typed **`VestError::cli_exit_code()`** for scan/completions exits; legacy string matching is last-resort for remaining untyped subcommands.
- `.env` loading allowlists Vest/provider keys.
- Safe Unicode **`truncate_chars`** helper in `vest-core`.

### Cleared recently (on `main`)

- **N5:** CLI web scan is passive by default; active probes opt-in via config or `--allow-active-probes`.
- **K3 / K3b:** Agent `http_get` / `http_post` use `ScopedHttpClient`; `web_scan` uses `WebScanner::inspect_url` with the same probe gating (no bare `ureq` for those tools).
- **K2:** `--approve-writes` / `--approve-exploits` / `--approve-effect` mint effect+session grants; TTY one-shot Allow when interactive; `--no-approval` and non-TTY without grants remain fail-closed deny.
- **N4:** `--offline` / `--no-ai` force `--provider none`; when no provider is configured the safer default is `none` (not ollama).
- **N3:** `vest doctor` prints config path/validity, `VEST_HOME`, sqlite path, provider env key presence (not values), online/offline posture, and a policy summary; fail-closed on bad config.
- **K14 / CLI-EXIT-7 / CLI-PARTIAL:** typed scan/completions exits; provider soft-fail → exit 7 with findings preserved; any scanner fatal → exit 5 after preserving successful scanner findings (`exit_codes_strict.rs`).
- **CFG-1:** agent/provider/network zero budgets rejected at config load; deny_unknown on those sections.
- **PROV-3 / PROV-4:** provider `timeout_seconds` wired into clients + sequential fallback; Google `list_models` fail-closed on HTTP errors.

### Still open (honest)

- `WebScanner` not yet fully on `ScopedHttpClient` — **WEB-1**.
- Some scanners still populate heuristic `cvss_score` values.

See [docs/clearance-plan.md](docs/clearance-plan.md) for the ordered remaining list.

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
