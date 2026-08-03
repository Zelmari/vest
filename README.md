# VEST

**V**ulnerability **E**xploitation & **S**canning **T**oolkit — an offline-first security scanner written in Rust. It runs local scanners (files, web, binaries, network, browser, and an opt-in memory *simulation*) and can optionally drive LLM agents to help classify and hunt findings across multiple providers.

> **Experimental.** Vest is not production-grade, not a full sandbox, and not “fully secure.” Model output is untrusted. Read [docs/security-model.md](docs/security-model.md), [docs/product-contract.md](docs/product-contract.md), and [SECURITY.md](SECURITY.md) before relying on it for anything serious.

Honest progress ledger (what is fixed vs still open): [docs/product-hardening-ledger.md](docs/product-hardening-ledger.md). Clearance order: [docs/clearance-plan.md](docs/clearance-plan.md).

## How this repo was built

A lot of this codebase — scaffolding, scanners, agent orchestration, docs, the security-hardening pass, and much of the test suite — was written **with AI coding agents** (including Cursor agents), under human direction. That is intentional and not hidden.

What that means in practice:

- Agents proposed and edited large amounts of code; humans steered goals, reviewed critical paths, and decided what shipped.
- The “verified security hardening” work and the human-style / adversarial tests were also agent-assisted. Treat claims as **implemented-and-tested in this tree**, not as an audited commercial product.
- Bugs, overconfident comments, and uneven design can still exist. Prefer running the tests and reading the security docs over trusting marketing language.

If you fork or contribute: agent-written patches are fine here, as long as they are honest about behaviour and come with tests where it matters.

## What it does

```text
User picks a target
  → scanners collect local findings (bounded FS / origin-scoped HTTP, etc.)
  → optional LLM agents classify / hunt (gated by a policy engine)
  → results go to terminal / JSON / Markdown + SQLite history
```

- **Scanners** can run without an LLM (`--provider none`, `--offline`, or `--no-ai`).
- **Agents** sit on top of providers + tools. Every tool call is supposed to go through an effect/scope/egress policy — this is **application policy**, not an OS sandbox.
- **Memory scanning** is unsupported by default. `--allow-memory-simulation` runs a fabricated harness and tags results as simulation (not live PID memory).

## Quickstart

```bash
git clone https://github.com/Zelmari/vest
cd vest
cargo build --release -p vest-cli

# Optional: provider key in the environment (plaintext .env is also supported — protect it)
export DEEPSEEK_API_KEY=sk-your-key

cargo run --release -p vest-cli -- scan ./examples/demo-target/vulnerable-files \
  --target-type file --scanner files --provider none
```

Install the binary:

```bash
cargo install --path vest-cli
```

Live web demo (separate Flask target):

```bash
python3 examples/demo-target/webapp/app.py &
cargo run --release -p vest-cli -- scan http://127.0.0.1:5555 \
  --target-type web --scanner web --provider none
```

## Workspace layout

Eleven crates. Dependency direction is downward; `vest-cli` is the binary.

| Crate | Role |
|-------|------|
| `vest-core` | Types, traits, IDs, errors, `ToolEffect` / egress / secrets |
| `vest-config` | `vest.toml` load + validation (fail-closed when a file is present but bad) |
| `vest-providers` | OpenAI, Anthropic, DeepSeek, Gemini, Ollama, Groq, OpenRouter + fallback |
| `vest-scanner` | files, web, binary, memory, network, browser |
| `vest-agent` | Orchestration patterns, policy engine, validator, model egress |
| `vest-storage` | SQLite persistence |
| `vest-report` | terminal / JSON / Markdown |
| `vest-payloads` | Payload libraries |
| `vest-tools` | External tools (e.g. nuclei) |
| `vest-test-utils` | Shared test helpers |
| `vest-cli` | `vest` CLI |

Also: `examples/` (deliberately vulnerable targets), `docs/` (security model / policy / egress / audit), `sinks/` (binary catalogs), `vest.toml`.

## Scan modes

| Mode | Behaviour |
|------|-----------|
| `pipeline` | Sequential recon → hunt → validate → report |
| `swarm` | Parallel specialists + merge strategies |
| `tool-use` | Single agent loop; tools go through the policy engine |
| `hierarchical` | Orchestrator decomposes work to child agents |

Default: `agent.default_pattern` in `vest.toml`, overridable with `--mode`.

## Scanners

| Scanner | Target | Notes |
|---------|--------|--------|
| `files` | path | Secrets / sensitive files; depth, size, symlink limits |
| `web` | URL | Crawl + probes; no auto off-origin redirects; robots optional |
| `binary` | ELF/PE/Mach-O | Sinks, mitigations, ROP gadgets |
| `memory` | PID | Real acquisition **not implemented**; simulation only with flag |
| `network` | host:port | Ports / TLS / basic DNS signals |
| `browser` | URL | CDP (Chrome) storage / WS / WASM / headers |

Severity numbers in reports are **heuristic estimates** on `severity_score_estimate`, not real CVSS vectors.

### Web scan honesty

CLI web scans are **passive by default** (`scanner.web.allow_active_probes = false`). Opt in with config or `--allow-active-probes`.

## Providers & keys

| Provider | Env var |
|----------|---------|
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |
| Google Gemini | `GOOGLE_API_KEY` |
| Ollama | (none — local) |
| Groq | `GROQ_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |

Keys come from the environment (or a local `.env` loaded into the process; Vest allowlists Vest/provider keys). Vest does not store keys in SQLite and must not print them (`providers set-key` only prints setup instructions). Prefer `export …=…` over `--key` on the command line.

## Safety (short version)

What is real today:

- Policy engine: explicit `ToolEffect`, FS/net scope, SHA-256 arg digest, egress class.
- Unknown tools / unknown effects → **deny**.
- `requires_approval` on a tool definition is **not** a bypass.
- Execution uses an opaque `ApprovedToolCall` minted by the policy engine (callers cannot forge `Allow`).
- Local file content and process memory are **not** sent to remote models by default.
- CLI web scans are passive by default; active probes are opt-in (**N5**).
- Agent `http_get` / `http_post` use `ScopedHttpClient` (redirect re-auth). `web_scan` goes through `WebScanner::inspect_url` with the same active-probe gating as CLI web scans (**K3**/**K3b**).
- JSON/Markdown reports omit evidence and PoC by default; opt in with `--include-evidence` (still redacted best-effort) (**REP-1**).
- Approval-required tools: exact CLI pre-grant (`--approve-writes` / `--approve-exploits` / `--approve-effect`) or TTY one-shot Allow; non-TTY without grants and `--no-approval` deny (**K2**).
- Agent/provider/network zero budgets are rejected at config load (**CFG-1**).
- `vest sandbox` Docker helpers are convenience only — not verified OS isolation.
- Optional `safety.deny_private_targets` (default **false**) rejects loopback / RFC1918 / link-local / known metadata hosts for scan targets and scoped URLs (**R3-lite**). Private targets remain allowed unless you opt in.

What is **not** finished:

- Full multi-step interactive approval UX (K2 is CLI grants + TTY one-shot only).
- DNS rebinding / connection-time IP binding is incomplete (literal private/metadata deny is optional via R3-lite above).

Details: [docs/security-model.md](docs/security-model.md), [docs/agent-tool-policy.md](docs/agent-tool-policy.md), [docs/model-data-boundary.md](docs/model-data-boundary.md), [docs/data-flow.md](docs/data-flow.md).  
Clearance order: [docs/clearance-plan.md](docs/clearance-plan.md).  
Historical snapshot (do not treat as current status): [docs/security-hardening-audit.md](docs/security-hardening-audit.md).

## CLI

```text
vest scan <TARGET>
vest doctor
vest config | providers | targets | scans | findings | report | tools | sandbox
vest completions <bash|zsh|fish>
```

Useful flags: `--scanner`, `--target-type`, `--provider`, `--offline` / `--no-ai`, `--mode`, `--format`, `--output`, `--include-evidence`, `--allow-memory-simulation`, `-c` / `--config`, `--no-approval`, `--approve-writes`, `--approve-exploits`, `--approve-effect`.

When no provider is configured and `--provider` is omitted, the scan default is **`none`** (scanner-only). `--offline` and `--no-ai` force the same.

`--no-approval` means **do not prompt; deny approval-required operations**. It is not “allow everything.” Approve flags mint effect+session grants (scopes still apply).

Exit codes: `0` ok · `2` bad input · `3` config · `4` authorisation · `5` scanner (including partial scanner fatal) · `6` persistence · `7` provider/agent soft failure with preserved findings. Scan/completions use typed `VestError::cli_exit_code()`; other subcommands may still hit a last-resort string fallback.

## Testing

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
cargo fmt --all -- --check
```

Suites include unit tests, concurrency stress, scanner edge cases, CLI workflows, and adversarial policy/egress/FS/network checks. Counts change; CI is the source of truth.

## Behaviour people trip over

1. Present but broken `vest.toml` → hard fail (no silent “just use defaults”).
2. Memory scan without `--allow-memory-simulation` → fail closed / unsupported.
3. Non-`http`/`https` web targets (e.g. `file://`) → rejected.
4. Missing scan id on `report generate` → non-zero exit.
5. Agent/tool path: model suggestions never equal authorisation.
6. Invalid `--target-type` → rejected (not guessed).
7. Approval-required tool without CLI pre-grant or TTY Allow → denied (fail closed).

## Docs & license

| | |
|--|--|
| [SECURITY.md](SECURITY.md) | How to report vulnerabilities |
| [CHANGELOG.md](CHANGELOG.md) | Notable changes |
| [docs/product-contract.md](docs/product-contract.md) | Intended product scenarios + gaps |
| [LICENSE](LICENSE) | MIT |

Repo: [github.com/Zelmari/vest](https://github.com/Zelmari/vest)
