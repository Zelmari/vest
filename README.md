# VEST

**V**ulnerability **E**xploitation **S**canning **T**oolkit. Multi-provider, multi-modal
offensive security scanner driven by LLM agents.

## Quickstart

```bash
# Clone and build
git clone https://github.com/vest/vest
cd vest
cargo build --release

# Initialize configuration
cargo run -- config init

# Run a demo scan against the example target
vest scan ./examples/demo-target/vulnerable-files --target-type file --scanner files
```

The demo target contains `.env`, `credentials.ini`, `id_rsa`, `backup.sql.bak`, and other
files that look suspicious -- the file scanner will flag them immediately.

## Features

- Multi-provider LLM with fallback chains (7 providers)
- 6 scanner types: `web`, `binary`, `memory`, `network`, `browser`, `files`
- 4 agent patterns: Pipeline, Swarm, Tool-Use, Hierarchical
- 3 report formats: terminal (box-drawn), JSON, Markdown
- Safety gates with approval steps, rate limiting, and Docker sandboxing
- SQLite-backed scan history, finding lifecycle management, and diff comparisons

## Scan Modes

Use `--mode` to select one of four agent patterns: `pipeline` (sequential recon-analyze-exploit), `swarm` (parallel specialist agents), `tool-use` (single agent with all tools), or `hierarchical` (orchestrator with specialist subtasks). Set the default in `vest.toml` via `agent.default_pattern`.

## Provider Support

| Provider    | Config Key   | Environment Variable     |
|-------------|-------------|--------------------------|
| OpenAI      | `openai`    | `OPENAI_API_KEY`         |
| Anthropic   | `anthropic` | `ANTHROPIC_API_KEY`      |
| DeepSeek    | `deepseek`  | `DEEPSEEK_API_KEY`       |
| Gemini      | `google`    | `GOOGLE_API_KEY`         |
| Ollama      | `ollama`    | (local, no key needed)   |
| Groq        | `groq`      | `GROQ_API_KEY`           |
| OpenRouter  | `openrouter`| `OPENROUTER_API_KEY`     |

Store keys with `vest providers set-key <provider>` or set the env var directly.

## Example Output

**Terminal** (default): box-drawn UI with severity bars and per-finding details.

```json
// -f json
{
  "summary": { "total": 7, "critical": 2, "high": 3 },
  "findings": [
    { "title": "Hardcoded AWS Secret Access Key",
      "severity": "critical",
      "confidence": 0.95,
      "location": { "file": "credentials.ini", "line": 3 } }
  ]
}
```

```markdown
<!-- -f markdown -->

# VEST Scan Report

| Severity | Count |
|----------|-------|
| Critical | 2     |
| High     | 3     |
```

## Requirements

- Rust 1.75+ (stable)
- Ollama (optional, for local LLM inference)

Install with `cargo install --path .`.

## Contributing

Planning documents live in `.plan/` (gitignored). Open an issue or PR for discussion.
