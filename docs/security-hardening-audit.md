# Security Hardening Audit

> **Historical snapshot.** This file records the first verified security-hardening
> pass (branch `hardening/verified-security-pass`, 2026-08-02). Several rows marked
> “Addressed” here are **not** fully closed on current `main` (notably CLI active
> probes, agent `ureq` HTTP, interactive approval UX, heuristic severity estimates).
>
> For current status, use [product-hardening-ledger.md](product-hardening-ledger.md)
> and [product-contract.md](product-contract.md). Do not cite this audit alone as
> proof that every issue remains fixed.

Branch: `hardening/verified-security-pass` (historical)  
Baseline commit: `593ecce904cb4616fcea0619121a53bb124934df` (`main`)  
Date: 2026-08-02

## Baseline command results

| Command | Result |
|---------|--------|
| `cargo fmt --all -- --check` | Pass |
| `cargo check --workspace --all-targets` | Pass (requires non-sandbox for `capstone-sys` build) |
| `cargo test --workspace` | Pass (0 failures) |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass |

## Issue verification matrix

| ID | Reported issue | Relevant files/functions | Verification evidence | Initial classification | Planned correction | Regression tests | Final status | Commit |
|----|----------------|--------------------------|----------------------|------------------------|--------------------|------------------|--------------|--------|
| A | Arbitrary local file access via agent tools | `vest-cli/.../scan.rs` `build_tool_registry`; `fs_scope.rs`; `policy.rs` | Tools previously called `std::fs::read` with model paths | Confirmed | Capability FS resolver + scope from scan target; policy on every call | Adversarial path tests | **Addressed** — `ApprovedFilesystemScope` + `resolve_read_path` in policy | |
| B | Bypass SafetyChecker when `requires_approval=false` | `patterns/tooluse.rs`; `tool_registry.rs` | Safety gate previously only when flag true | Confirmed | Always route through policy; registry flag is not a bypass | No-bypass integration test | **Addressed** — every call evaluates policy regardless of flag | |
| C | HTTP POST / active scan as read-only | `scan.rs` tool registration; `ToolEffect` | `http_post`/`web_scan` misclassified | Confirmed | Explicit `ToolEffect` (state-changing / active probe) | POST ≠ passive; probe ≠ crawl | **Addressed** — `StateChangingNetworkRequest` / `ActiveNetworkProbe` | |
| D | Safety via tool-name substring | `safety.rs` legacy categorize | `name.contains("read")` heuristics | Confirmed | Registry effect enum + policy table | Classification unit tests | **Addressed** — explicit effects; substring path removed from authorisation | |
| E | Unknown tools default permissive | `safety.rs` / policy | Unknown → ReadOnly / allow | Confirmed | Unknown → deny | Unknown denied | **Addressed** — `ToolEffect::Unknown` denied | |
| F | Safety ignores tool arguments | `NormalisedToolCall`, `arg_digest` | Args previously unused | Confirmed | Normalised args + digest in approval | Arg mutation invalidates | **Addressed** — digest in `ApprovalToken` | |
| G | Target allowlist substring | `safety.rs` `is_target_allowed` | Previously `contains` | Confirmed | Exact host/path / parsed origin | Prefix-collision tests | **Addressed** for allow/block lists (exact / `host_equals`); network tools also use `ApprovedNetworkScope` | |
| H | Approvals cached too broadly | `ApprovalToken` in `policy.rs` | Cache by category string | Confirmed | Scoped token (tool, effect, target, arg digest, session, expiry) | Scoped approval tests | **Addressed** — broad `grant_approval` is a no-op | |
| I | Web scanner string URL join/prefix | `web.rs` | `starts_with` / string concat | Confirmed | `url::Url` join + origin compare | Hostname/userinfo/port tests | **Addressed** | |
| J | Redirects/links escape scope | `web.rs` Client | Auto-follow redirects | Confirmed | Disable auto-redirect; re-auth each hop | Redirect escape tests | **Addressed** — `redirect::Policy::none()` + scoped fetch | |
| K | Active probes without distinct auth | `web.rs`; tools `web_scan` | Probes mixed with read-only | Confirmed | `ActiveNetworkProbe` effect + approval | Passive crawl ≠ probes | **Addressed** at tool-policy layer; scanner still runs probes when user requests a web scan | |
| L | Missing body/redirect/timeout/concurrency limits | `web.rs` | Unbounded body; redirects 10 | Confirmed | Enforce body/redirect/timeout/concurrency/request/depth | Limit enforcement tests | **Addressed** for core limits (body cap, no auto-redirect, budgets); revisit edge cases as needed | |
| M | `respect_robots_txt` without enforcement | `web.rs` | Field unused | Confirmed | Implement or reject unsupported | Robots behaviour tests | **Addressed** — fetch/parse/enforce when enabled | |
| N | API keys via CLI printed in export | `providers.rs` SetKey | `export KEY={actual}` | Confirmed | Remove key echo; deprecate CLI key arg | Sentinel stdout tests | **Addressed** — instructions only; `--key` deprecated warning | |
| O | Secrets in Debug/logs | providers; validator | Full response / key Debug | Partially confirmed | Secret wrappers, redacted Debug, safe logging | Sentinel Debug/log tests | **Partially addressed** — `SecretString`; OpenAI-compat Debug redacts; validator logs sanitised. Remaining: some provider structs (e.g. Google) still hold bare `api_key: String` without custom Debug; redaction is best-effort | |
| P | Config fields parsed but not wired | robots, limits, sandbox | Unused fields | Confirmed | Wire or reject/deprecate | Config→behaviour tests | **Partially addressed** — robots + many scanner limits wired. Docker `sandbox_*` safety fields remain convenience/optional, not a verified agent sandbox | |
| Q | Malformed config silent fallback | `vest-config` load paths | Silent defaults on error | Partially confirmed | Present+malformed → hard error | Malformed fails closed | **Addressed** — `load_config` / `load_config_or_default`; CLI providers refuse silent defaults for present files | |
| R | Validator severity/confidence not applied | `validator.rs` | Downgrade not applied | Confirmed | Apply to returned finding | Downgrade/confidence E2E | **Addressed** | |
| S | Fake CVSS | enrichment / scanners | Severity→number labelled CVSS | Confirmed | Rename to severity estimate; stop claiming CVSS | Naming/docs + tests | **Addressed** (K16) — field/`reports` use `severity_score_estimate`; SQLite column `cvss_score` mapped in storage | |
| T | Validator failures abort batch | `validator.rs` | `?` on llm_validate | Confirmed | Preserve local findings | Failure preserves locals | **Addressed** | |
| U | Malformed model responses logged in full | `validator.rs` | `tracing::warn!(..., response)` | Confirmed | Log metadata + sanitised error only | No raw response in logs | **Addressed** | |
| V | Evidence sent without egress boundary | validator prompts | Full evidence JSON | Confirmed | Allowlist DTO + bounded redacted excerpt + consent | Sentinel absent from payload | **Addressed** — `FindingEgressDto`; evidence gated by `allow_evidence_egress` | |
| W | Tool results to model without egress approval | `tooluse` / `egress.rs` | Full result string | Confirmed | Egress gate + size cap | File content default blocked from remote | **Addressed** — `filter_for_model` | |
| X | Process-memory simulated as real | `memory.rs` `MemoryScanMode` | Simulated data presented as real | Confirmed | Clear simulation/unsupported mode | PID/simulation honesty tests | **Addressed** — default `Unsupported`; simulation only with `--allow-memory-simulation` | |
| Y | Recursive file scan lacks limits | `files.rs` | Unbounded recursion | Confirmed | Enforce configurable limits | Limit tests | **Addressed** — depth/count/size/symlink policy | |
| Z | Sync FS blocks async / double reads | scanners | Blocking on async runtime | Partially confirmed | `spawn_blocking` / sync boundary | Non-duplicate read tests | **Partially addressed** — file scanner uses `spawn_blocking`; not every sync FS path audited | |
| AA | TryAllParallel sequential | `fallback.rs` | Lazy futures in `for` loop | Confirmed | Real concurrency + cancel | Overlap proof test | **Addressed** — `FuturesUnordered` | |
| AB | Fallback lacks cancel/timeout | `fallback.rs` | No timeouts | Confirmed | Timeouts + cancel remaining | Timeout/cancel tests | **Addressed** — per-provider timeout + optional overall; drop cancels remaining | |
| AC | Fatal failures exit 0 | CLI handlers | Soft `Ok(())` after errors | Partially confirmed | Exit-code policy + assert_cmd | Exit code matrix | **Partially addressed** — `exit_code_for_error` mapping exists; not all command paths proven to surface fatal errors as non-zero | |
| AD | README/metadata inaccurate | README, Cargo.toml | Wrong URL, CVSS, sandbox claims | Confirmed | Align docs/metadata; experimental warning | Doc review | **Addressed** this pass — README/SECURITY/LICENSE/CHANGELOG/docs + `workspace.repository` | |
| AE | Tests don’t prove security invariants | test suite | Structural tests dominate | Confirmed gap | Add invariant-focused suite | Security invariant suite | **Partially addressed** — policy/egress/scope/memory/robots tests added; coverage still not exhaustive against all adversarial cases | |

## Remaining risks (honest)

- Not an OS sandbox; Docker CLI helpers are optional and unverified as isolation for agent tools.
- Secret redaction and regex-based detection are incomplete by nature.
- SSRF / DNS-rebinding prevention is not claimed complete without connection-time IP binding.
- Real process-memory acquisition is not implemented.
- Heuristic numbers live on `severity_score_estimate` (SQLite still stores column `cvss_score`).
- Provider Debug hygiene is incomplete for all backends.
- Exit-code consistency across every CLI subcommand is not fully proven.
- Experimental project — no production-grade or “guaranteed secure” claim.

## Configuration field inventory (initial)

See Phase 7 updates in this file after enforcement work. Hotspots addressed in code: `safety` validation, `scanner.web.respect_robots_txt`, crawl/body limits, memory scanner mode, file traversal limits. Sandbox config fields remain decorative unless a Dockerfile-based helper path is used explicitly.

## Notes

- Network tests must use loopback / in-process servers only.
- No real API keys in tests; use sentinels and mocks.
- Breaking changes for unsafe interfaces are acceptable and must be documented in migration notes (see README / CHANGELOG).
