# VEST

**V**ulnerability **E**xploitation & **S**canning **T**oolkit. An offline-first, multi-provider security scanner that uses LLM agents to detect vulnerabilities across files, web applications, binaries, memory, network services, and browsers. Built in Rust.

## Demo

```
$ vest scan ./examples/demo-target/vulnerable-files --target-type file --scanner files

  files        32 finding(s)
  Duration:    0.1s
  Findings:    22 classified, 0 null CVSS

  Summary:
    hardcoded_credentials  17
    sql_injection           1
    unknown                 4
```

The scanner found AWS keys, GitHub tokens, hardcoded passwords, SSH private keys, JWT secrets, backup files, and exposed git configuration — all from a directory of 10 deliberately-vulnerable fixture files. Every finding is classified by vulnerability class and scored with a CVSS rating by the validation pipeline.

For a live web demo, start the Flask target and scan it:

```
$ python3 examples/demo-target/webapp/app.py &
$ vest scan http://localhost:5555 --target-type web --scanner web

  Findings:    10
  Summary:
    xss:                 2   (reflected in 'q' and 'filename' parameters)
    sql_injection:       2   (error-based in username/password form fields)
    path_traversal:      1   (../../etc/passwd via filename parameter)
    cors:                5   (wildcard origin on all endpoints + missing 7 security headers)
```

## Architecture

VEST is a workspace of 10 crates with a strict dependency graph — `vest-core` has zero external dependencies, and each layer builds on the one below it.

```
vest-core        shared types, traits, IDs, errors
  vest-config      TOML config parsing with validation
  vest-providers   7 LLM backends behind a common trait + fallback chain
  vest-scanner     6 scanner modules (files, web, binary, memory, network, browser)
  vest-storage     SQLite persistence (6 tables, 18 indexes)
  vest-report      terminal / JSON / markdown reporters
  vest-payloads    attack payload libraries
  vest-tools       external tool integration (nuclei)

  vest-agent       agent orchestration: 4 patterns, safety system, validator
    vest-cli         clap CLI (11 subcommands)
```

The agent layer sits on top of providers and scanners. The orchestrator selects an execution pattern, the pipeline feeds scanner findings through classification and validation phases, and the safety checker gates every tool invocation with rate limiting and capability approval.

## Features

- **6 scanner modules** covering files, web apps, binaries (ELF/PE/Mach-O), process memory, network services, and browser targets (CDP)
- **4 agent orchestration patterns:** Pipeline (sequential phases), Swarm (parallel specialists with voting), Tool-Use (single agent loop), Hierarchical (parent/child delegation)
- **7 LLM providers** with automatic fallback: OpenAI, Anthropic, DeepSeek, Google Gemini, Ollama (local), Groq, OpenRouter — all behind a single `LlmProvider` trait
- **3 report formats:** Unicode box-drawn terminal output, structured JSON, collapsible Markdown with severity tables
- **Heuristic enrichment pipeline:** findings classified by vulnerability class and scored with CVSS even without an LLM
- **Safety system:** token-bucket rate limiter, 6 tool capability categories, target allow/block lists, approval gates
- **SQLite persistence:** scan history, finding lifecycle (open/confirmed/false-positive), scan comparison diffing
- **618 tests, 0 failures** across 38 test suites with property-based, concurrency, edge case, and integration coverage
- **25,668 lines of Rust**

## Quickstart

```bash
git clone https://github.com/vest/vest
cd vest
cargo build --release

# Set your LLM keys in a .env file (gitignored)
echo 'DEEPSEEK_API_KEY=sk-your-key' > .env

# Run the file scanner against the demo target
cargo run -- scan ./examples/demo-target/vulnerable-files --target-type file --scanner files
```

No API key? Set `provider = "none"` in `vest.toml` and the heuristic enrichment pipeline runs without an LLM.

## Scan Modes

| Mode | Behaviour |
|------|-----------|
| `pipeline` | Sequential 5-phase flow: Reconnaissance -> Surface Analysis -> Vulnerability Hunting -> Validation -> Reporting |
| `swarm` | Parallel specialist agents (memory/web/binary/auth-logic) with 3 merge strategies: voting (40% threshold), union, strict (70%) |
| `tool-use` | Single agent with access to all registered tools: web scan, file scan, HTTP fetch, browser inspect, secret scanning |
| `hierarchical` | Orchestrator decomposes tasks via LLM, spawns specialist child agents, collects and merges results |

Set the default in `vest.toml` (`agent.default_pattern`) or override with `--mode`.

## Scanners

| Scanner | Target | Detects |
|---------|--------|---------|
| `files` | directory path | Secrets (AWS/GitHub/Stripe/Slack/JWT keys, passwords), dangerous file types, backup files, sensitive config files (.env, id_rsa, Docker config, git exposure) |
| `web` | URL | XSS (reflected, form-based, URL param), SQL injection (error-based, status 500), path traversal, SSRF, command injection, misconfiguration (missing headers, CORS wildcard, .git/.env exposure) |
| `binary` | ELF/PE/Mach-O binary | Dangerous sink functions (gets/strcpy/system/printf), security mitigations (NX/ASLR/stack canaries), ROP gadget discovery |
| `memory` | PID or simulated | Pattern scanning (brute-force + Boyer-Moore-Horspool), hook detection (JMP/PUSH-RET/MOV-RAX-RET), shellcode patterns, suspicious RWX region detection |
| `network` | host:port | Dangerous service ports, TLS analysis (deprecated versions, weak ciphers), DNS misconfiguration (SPF +all) |
| `browser` | URL (CDP) | localStorage/sessionStorage secrets, WebSocket URLs, WASM module imports, security headers via Chrome DevTools Protocol |

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

API keys are read from environment variables only — never stored on disk. Create a `.env` file in the project root (gitignored) or set them in your shell profile. Keys already in the environment take priority over `.env` values.

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

**JSON** (`-f json -o report.json`):
```json
{
  "summary": { "total": 22, "critical": 14, "high": 5, "medium": 3 },
  "findings": [
    {
      "title": "AWS Access Key ID found in file",
      "vulnerability_class": "hardcoded_credentials",
      "severity": "critical",
      "cvss_score": 9.0,
      "cwe_id": "CWE-798",
      "evidence": { "file": ".env", "pattern": "AWS Access Key ID" },
      "location": { "file": "./examples/demo-target/vulnerable-files/.env" }
    }
  ]
}
```

**Markdown** (`-f markdown -o report.md`): severity table with icons, collapsible evidence sections, CVSS/CWE/CVE fields, remediation advice, PoC blocks.

## Installation

```bash
cargo install --path .
```

Requirements:
- Rust 1.75+ (stable toolchain)
- Optional: Docker (for sandbox commands), Ollama (for local LLM), Python 3 + Flask (for web demo target), gcc (for binary demo target)

## Project Structure

```
vest/
  vest-core/         shared domain types, traits, error handling
  vest-config/       TOML config parsing, validation, defaults
  vest-providers/    7 LLM provider implementations + fallback chain
  vest-agent/        orchestration engine, 4 patterns, safety, validator
  vest-scanner/      6 scanner modules with 70+ detection patterns
  vest-storage/      SQLite persistence layer (6 tables, full CRUD)
  vest-report/       terminal box-drawn, JSON, and Markdown reporters
  vest-payloads/     XSS, SQLi, ROP, shellcode, and fuzzing payloads
  vest-tools/        external tool integration (nuclei)
  vest-cli/          clap CLI, 11 subcommands, 1068-line scan orchestrator
  examples/          demo targets (vulnerable files, Flask webapp, C binary)
  sinks/             binary scanner function catalogs (C/C++/Rust)
  vest.toml          default configuration with provider+scanner settings
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
vest sandbox                 manage Docker sandbox environment
vest completions <shell>     generate shell completions (bash/zsh/fish)
```

## Testing

```bash
cargo test --workspace              # 618 tests across 38 suites
cargo clippy --workspace            # 0 warnings
cargo fmt --check --all             # clean
```

Test categories: property-based serialization roundtrips, concurrency stress tests (10K findings, 10K rate-limiter bursts), edge case coverage (null bytes, 100K-char values, nested JSON), integration tests (full scan -> storage -> report cycle), pattern scanning cross-checks (brute-force vs fast algorithm equivalence), validator enrichment boundary tests, and chaos mode robustness checks.
