# AGENTS.md — Vest wake-up doc

Read this first, then `docs/CURRENT.md` (one-screen status), then `docs/standing-backlog.md` (the only queue to take work from).

## What Vest is

Vulnerability Exploration & Scanning Toolkit — an offline-first security scanner CLI written in Rust (Cargo workspace, binary `vest-cli`). Local scanners (files, web, binary, network, browser, nuclei) run without any LLM; optional LLM agents classify/hunt behind a policy engine. **Experimental** — not production-grade, no OS sandbox, model output is untrusted.

## Build / test baseline (keep green on every commit)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Toolchain pinned in `rust-toolchain.toml` (1.96.1, matches the ledger). CI runs the same gates on `ubuntu-latest`.

## Doc map (in order)

1. `README.md` — overview, quickstart, CLI, safety summary, exit codes
2. `docs/product-contract.md` — intended scenarios A–H and what is actually true
3. `docs/product-hardening-ledger.md` — authoritative fix ledger (K*/N*) + standing limitations
4. Security reading: `docs/security-model.md`, `docs/agent-tool-policy.md`, `docs/model-data-boundary.md`, `docs/data-flow.md`
5. Historical records (do not treat as current): `docs/clearance-plan.md`, `docs/major-backlog.md`, `docs/next-backlog.md`, `docs/security-hardening-audit.md`

## Queue status

- A–D queue and majors M1–M3 are **complete** on `main`.
- Next work: `docs/standing-backlog.md` only. **Do not invent scope from stale backlog prose** — those docs are historical records.
- Open items are listed in `docs/CURRENT.md`.

## Standing non-claims (document, don't "fix" into fake guarantees)

- Experimental; not production-grade, not independently audited.
- No OS sandbox; `vest sandbox` Docker helpers are convenience only.
- Process-memory acquisition is **simulation-only** (`--allow-memory-simulation`, tagged as simulation).
- DNS-rebinding protection is partial: `deny_private_targets` ships resolve-and-deny + reqwest DNS pin; connect-time TOCTOU (R3) remains.
- Regex redaction is best-effort.

## Commit rules

- `main` only, no feature branches.
- Author: Zelmari. **No `Co-authored-by:` trailers** (no Cursor, no tool names).
- Commit after each meaningful change with `git add` / `git status` / `git commit`.

## Workspace

Ten crates: `vest-core`, `vest-cli` (binary), `vest-config`, `vest-providers`, `vest-agent`, `vest-scanner`, `vest-storage`, `vest-report`, `vest-tools`, `vest-test-utils`. Dependency direction is downward; `vest-cli` is the binary. `vest-payloads/` is **on disk but not a workspace member** (intentional orphan; scanners use inline payload lists — see the standing backlog item).

## 5-minute verification

```bash
cargo build --release -p vest-cli
cargo run --release -p vest-cli -- doctor
cargo run --release -p vest-cli -- scan ./examples/demo-target/vulnerable-files \
  --target-type file --scanner files --provider none
```
