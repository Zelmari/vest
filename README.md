# VEST

> **EXPERIMENTAL.** Vest is under active development. It is **not** production-grade, fully sandboxed, or guaranteed secure. Treat model output as untrusted. See [docs/security-model.md](docs/security-model.md), [SECURITY.md](SECURITY.md), and the trust/policy docs under `docs/`.

**V**ulnerability **E**xploitation & **S**canning **T**oolkit. An offline-first, multi-provider security scanner that uses LLM agents to detect vulnerabilities across files, web applications, binaries, memory (simulation only by default), network services, and browsers. Built in Rust.

## Demo

```
$ cargo run -p vest-cli -- scan ./examples/demo-target/vulnerable-files --target-type file --scanner files

  files        32 finding(s)
  Duration:    0.1s
  Findings:    22 classified

  Summary:
    hardcoded_credentials  17
    sql_injection           1
    unknown                 4
```

The scanner found AWS keys, GitHub tokens, hardcoded passwords, SSH private keys, JWT secrets, backup files, and exposed git configuration — all from a directory of deliberately-vulnerable fixture files. Findings are classified by vulnerability class; severity uses a **heuristic severity-score estimate** (not a real CVSS vector calculation).

For a live web demo, start the Flask target and scan it:

```
$ python3 examples/demo-target/webapp/app.py &
$ cargo run -p vest-cli -- scan http://localhost:5555 --target-type web --scanner web
```

## Architecture

VEST is a Cargo workspace of **11 crates** with a layered dependency graph — `vest-core` stays lean, and each layer builds on the one below it.

```
vest-core        shared types, traits, IDs, errors, auth/egress enums
  vest-config      TOML config parsing with validation (fail-closed when present)
  vest-providers   7 LLM backends behind a common trait + fallback chain
  vest-scanner     6 scanner modules (files, web, binary, memory, network, browser)
  vest-storage     SQLite persistence
  vest-report      terminal / JSON / markdown reporters
  vest-payloads    attack payload libraries
  vest-tools       external tool integration (nuclei)
  vest-test-utils  shared test helpers

  vest-agent       agent orchestration: patterns, policy engine, validator, egress
    vest-cli         clap CLI binary (`vest`)
```

The agent layer sits on top of providers and scanners. The orchestrator selects an execution pattern; the pipeline feeds scanner findings through classification and validation. A **policy engine** gates every tool invocation by explicit `ToolEffect`, filesystem/network scope, and egress class. This is **not** an OS sandbox.

## Features

- **6 scanner modules** covering files, web apps, binaries (ELF/PE/Mach-O), process memory (unsupported by default; opt-in simulation), network services, and browser targets (CDP)
- **4 agent orchestration patterns:** Pipeline, Swarm, Tool-Use, Hierarchical
- **7 LLM providers** with automatic fallback: OpenAI, Anthropic, DeepSeek, Google Gemini, Ollama (local), Groq, OpenRouter
- **3 report formats:** terminal, JSON, Markdown
- **Heuristic enrichment:** vulnerability class + severity-score estimate without requiring an LLM
- **Policy engine:** effect-based tool gating, scoped approvals, egress filtering — not OS isolation
- **SQLite persistence:** scan history, finding lifecycle, scan comparison
- **Hundreds of tests** across unit, property-based, concurrency, and integration suites

## Quickstart

```bash
git clone https://github.com/Zelmari/vest
cd vest
cargo build --release -p vest-cli

# Keys from the environment (or a local plaintext .env — see below)
export DEEPSEEK_API_KEY=sk-your-key

# Run the file scanner against the demo target
cargo run --release -p vest-cli -- scan ./examples/demo-target/vulnerable-files \
  --target-type file --scanner files
```

Install the `vest` binary from this workspace:

```bash
cargo install --path vest-cli
```

No API key? Set `provider = "none"` (or use Ollama / heuristic-only paths) in `vest.toml` and enrichment can still run without a remote LLM.

## Scan Modes

| Mode | Behaviour |
|------|-----------|
| `pipeline` | Sequential phases: Reconnaissance → Surface Analysis → Vulnerability Hunting → Validation → Reporting |
| `swarm` | Parallel specialist agents with merge strategies (voting, union, strict) |
| `tool-use` | Single agent loop over registered tools; every call goes through the policy engine |
| `hierarchical` | Orchestrator decomposes tasks, spawns specialist children, merges results |

Set the default in `vest.toml` (`agent.default_pattern`) or override with `--mode`.

## Scanners

| Scanner | Target | Detects |
|---------|--------|---------|
| `files` | directory path | Secrets, dangerous file types, backup files, sensitive config (.env, id_rsa, Docker config, git exposure). Traversal is depth/size/symlink-bounded. |
| `web` | URL | XSS, SQL injection signals, path traversal, SSRF probes, misconfiguration. Redirects are not auto-followed; robots.txt can be respected. |
| `binary` | ELF/PE/Mach-O | Dangerous sinks, mitigations (NX/ASLR/canaries), ROP gadget discovery |
| `memory` | PID (real acquisition **unsupported** by default) | Opt-in **simulation only** with `--allow-memory-simulation` (fabricated regions/bytes; not live PID memory). Without the flag: unsupported / fail closed. |
| `network` | host:port | Dangerous ports, TLS analysis, basic DNS misconfiguration signals |
| `browser` | URL (CDP) | Storage secrets, WebSocket URLs, WASM imports, headers via Chrome DevTools Protocol |

## Provider Support

| Provider | Config Key | Env Variable | Notes |
|----------|-----------|-------------|-------|
| OpenAI | `openai` | `OPENAI_API_KEY` | |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | Custom API implementation (not OpenAI-compatible) |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` | |
| Google Gemini | `google` | `GOOGLE_API_KEY` | Custom Gemini generateContent API |
| Ollama | `ollama` | (none) | Local inference, no key needed |
| Groq | `groq` | `GROQ_API_KEY` | |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | |

### API keys

- Keys are read from **environment variables** (and optionally a local `.env` loaded into the process environment).
- A `.env` file is **plaintext on disk**, not an OS credential store. Protect it accordingly; keep it gitignored.
- Vest does **not** store API keys in its SQLite database.
- Vest **never prints** API key values (`providers set-key` prints setup instructions only).
- Prefer `export PROVIDER_API_KEY=...` over passing `--key` on the command line (argv is visible in process lists / shell history).

## Safety model (short)

- **Policy engine** evaluates every tool call (`ToolEffect`, path/URL scope, arg digest, egress class).
- Registry `requires_approval` is **UX metadata**, not a bypass.
- Unknown tools / unknown effects are **denied** (fail closed).
- Local file content and process memory are **not** sent to remote models by default.
- Optional Docker helpers (`vest sandbox`) are convenience wrappers — **not** a verified OS sandbox for agent tools. See [docs/security-model.md](docs/security-model.md), [docs/agent-tool-policy.md](docs/agent-tool-policy.md), and [docs/model-data-boundary.md](docs/model-data-boundary.md).

## Example Output

**Terminal** (default `-f terminal`):
```
+----------------------------------------------------+
|                     VEST SCAN                       |
+----------------------------------------------------+
| Target:      ./examples/demo-target/vulnerable-files|
| Scanners:    files                                  |
+----------------------------------------------------+
| files        32 finding(s)                          |
| Duration:    0.1s                                   |
| Findings:    22                                     |
+----------------------------------------------------+
```

**JSON** (`-f json -o report.json`): structured findings with severity, optional `severity_score_estimate` metadata, CWE/CVE fields when present. Do not treat numeric severity estimates as CVSS.

**Markdown** (`-f markdown -o report.md`): severity table, collapsible evidence, remediation advice.

## Installation

```bash
git clone https://github.com/Zelmari/vest
cd vest
cargo install --path vest-cli
```

Requirements:
- Rust stable (recent 1.75+ recommended)
- Optional: Docker (for experimental `vest sandbox` helpers), Ollama (local LLM), Python 3 + Flask (web demo), gcc (binary demo)

## Project Structure

```
vest/
  vest-core/         shared domain types, traits, auth/egress, secrets helper
  vest-config/       TOML config parsing, validation, defaults
  vest-providers/    LLM provider implementations + fallback chain
  vest-agent/        orchestration, policy engine, egress, validator
  vest-scanner/      scanner modules
  vest-storage/      SQLite persistence
  vest-report/       reporters
  vest-payloads/     payload libraries
  vest-tools/        external tool integration (nuclei)
  vest-test-utils/   test helpers
  vest-cli/          clap CLI binary (`vest`)
  examples/          demo targets (vulnerable files, Flask webapp, C binary)
  docs/              security model, policy, egress, hardening audit
  sinks/             binary scanner function catalogs
  vest.toml          default configuration
```

## Commands

```
vest scan <TARGET>           run a vulnerability scan
vest config                  manage vest.toml configuration
vest providers               manage LLM providers, test connectivity
vest targets                 manage scan targets
vest scans                   view scan history
vest findings                query and export findings
vest report                  generate and compare scan reports
vest tools                   manage external tools (nuclei, sqlmap, etc.)
vest sandbox                 experimental Docker helper (build/start/clean)
vest completions <shell>     generate shell completions (bash/zsh/fish)
```

Useful scan flags:
- `--allow-memory-simulation` — opt into fabricated memory-scan harness (not real PID memory)
- `--mode`, `--scanner`, `--target-type`, `--provider`

## Testing

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check --all
```

Coverage includes property-based serialization, concurrency stress tests, edge cases, integration cycles, pattern-scan cross-checks, validator enrichment, and security-invariant tests added during the hardening pass. Exact counts change frequently.

## Migration notes (breaking / behaviour changes)

These changes land with the verified security-hardening pass:

1. **`providers set-key` never echoes the key.** Passing `--key` is deprecated; Vest prints `export …=<your-key-here>` instructions only.
2. **Unknown tools are denied.** Tools must be registered with an explicit `ToolEffect`; unknown / unregistered names fail closed.
3. **Memory scanner defaults to unsupported.** Real OS memory acquisition is not implemented. Use `--allow-memory-simulation` only for the explicit simulation harness (results are tagged as simulation).
4. **Config fail-closed.** A present but malformed `vest.toml` (or invalid safety/scanner sections) is a hard error — no silent default fallback for a broken file. Missing file may still use built-in defaults.
5. **Egress defaults are restrictive.** Local file content and process memory are not sent to remote models by default; evidence in validator prompts uses allowlisted DTOs / redacted excerpts when enabled. See [docs/model-data-boundary.md](docs/model-data-boundary.md).
6. **Severity scores are estimates**, not CVSS. Prefer `severity` + `metadata.severity_score_estimate` over treating `cvss_score` as a real vector.
7. **`requires_approval: false` is not a policy bypass.** Every tool invocation is evaluated by the policy engine.

## Documentation

| Doc | Topic |
|-----|--------|
| [docs/security-model.md](docs/security-model.md) | Trust principals and boundaries |
| [docs/agent-tool-policy.md](docs/agent-tool-policy.md) | ToolEffect, approval, non-bypass |
| [docs/model-data-boundary.md](docs/model-data-boundary.md) | Egress classes and defaults |
| [docs/security-hardening-audit.md](docs/security-hardening-audit.md) | Hardening issue matrix |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [LICENSE](LICENSE) | MIT |
