# Product Hardening Ledger

**Branch / tip:** `main` @ current HEAD (product-hardening commits landed; do not treat old branch names as required)  
**Baseline commit:** `37733b1` (main after merge of verified security pass + README)  
**Toolchain:** rustc/cargo 1.96.1 (as recorded at start of this pass)  
**Started:** 2026-08-03  

This file is the authoritative progress ledger. Status below is honest against what shipped.

## Baseline commands

| Command | Result |
|---------|--------|
| `cargo fmt --all -- --check` | Pass (at hardening checkpoints) |
| `cargo check --workspace --all-targets --all-features` | Pass (at hardening checkpoints) |
| `cargo test --workspace --all-features` | Re-run after further edits before release claims |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Re-run after further edits |

## Workspace

Members: vest-core, vest-cli, vest-config, vest-providers, vest-agent, vest-scanner, vest-storage, vest-report, vest-tools, vest-payloads, vest-test-utils.  
Binary: `vest` (`vest-cli`). Feature: `browser` (default).

## Product use cases (summary)

See [product-contract.md](product-contract.md): A offline local, B passive web, C active (no prompt UI), D AI egress, E tool-use, F CI, G degraded, H large target.

## Threat boundaries

- Model output is untrusted and grants no authority.
- Authorised use only; tests use loopback / temp dirs / fake providers.
- Action approval ≠ model egress approval.
- Fail closed on unknown effects, bad config, missing approval / interactive requirement.

---

## Known-issue matrix (K1–K18)

| ID | Status | Evidence | Planned / done | Tests | Commit |
|----|--------|----------|----------------|-------|--------|
| K1 | **Fixed** | Was calling `SafetyChecker::permissive()` | `--no-approval` = non-interactive deny; no permissive path | CLI tests | `17d2232`+session |
| K2 | **Open** | `RequireInteractive` → deny; no stdin prompt; `--approve-*` flips legacy booleans | Interactive prompt + opaque grant | acceptance 3–4 | pending |
| K3 | **Fixed** | Agent tools used `ureq` in `scan.rs` | `http_get`/`http_post` via `ScopedHttpClient`; redirect re-auth | `agent_http_scoped_client.rs` | `5a5fc2c` |
| K3b | **Fixed** | `web_scan` reimplemented probes via `ureq` | `WebScanner::inspect_url`; probes gated like CLI | `agent_http_scoped_client.rs` | `5a5fc2c` |
| K4 | **Fixed** | TargetContent/PotentiallySecretBearing were redact-only | Default stub/metadata; flags for opt-in egress | `target_content_egress_tests.rs` | `dbd5e0c` |
| K5 | **Fixed** | Was forgeable `ApprovalDecision::Allow` | Opaque `ApprovedToolCall` | policy/approved tests | `1951cd2` |
| K5b | **Fixed** | tool-use used evaluate+invoke; `execute_authorised` skipped egress | Live path `authorise`→`execute_authorised`→`filter_for_model`; `invoke` thin wrapper | `authorise_execute_hot_path_tests.rs` | (this commit) |
| K6 | **Fixed** | Was `DefaultHasher` on selected keys | SHA-256 over material args | policy tests | `1951cd2` |
| K7 | **Fixed** | Was `TOOL_FS_SCOPE` OnceLock | `ExecutionSession` Arc captured by tools | session unit test | `0f76c32` |
| K8 | **Fixed** | Was `std::fs::read` entire file then truncate | Cap via `Read::take` + `spawn_blocking` | `agent_read_file_bounded.rs` | `b7a0744` |
| K9 | **Fixed** | follow=true had no root containment | Resolved paths must stay under canonical root else skip OutsideRoot | `files_adversarial` follow=true + unit | `02dc51e` |
| K10 | **Fixed** (web client) | `unwrap_or_default()` on Client | fail-closed + `ScopedHttpClient::try_new` | http_client tests | `0f76c32` |
| K11 | **Fixed** | form submit always POSTed | Honour GET/POST (allowlist); GET→query; missing method→GET | web form method tests | (this commit) |
| K12 | **Fixed** | invalid `--target-type` guessed | Reject invalid explicit type | CLI | `17d2232` |
| K13 | **Fixed** (util) | byte-index risk | `truncate_chars` in vest-core | unit | `17d2232` |
| K14 | **Partial** | string match still as legacy fallback | Prefer `VestError::cli_exit_code()` | unit | `17d2232` |
| K15 | **Fixed** | all keys loaded | Allowlist Vest/provider keys | unit | `17d2232` |
| K16 | **Open** | `Finding.cvss_score` + scanner heuristics | Rename to severity_estimate / metadata | types+report | pending |
| K17 | **Open** | prior audit “addressed” while CLI bypasses remain | Keep docs/ledger honest; close wiring gaps | ledger | ongoing |
| K18 | **Ongoing** | prior pass merged | Regression suite | workspace tests | ongoing |

## Newly discovered issues

| ID | Issue | Status |
|----|-------|--------|
| N1 | Dry-run returns before config load / scope display | **Fixed** — load/validate config, detect target, resolve scopes, print plan (scanners/probes/provider/scopes); no DB/network/scanner side effects; invalid type/config → non-zero; `dry_run_contract.rs` |
| N2 | `config validate` historically soft-failed (fixed on prior branch; re-verify) | verify |
| N3 | No `vest doctor` / `policy explain` | open |
| N4 | No explicit `--offline` / `--no-ai` flags (provider none only) | open |
| N5 | CLI web scan forces `with_allow_active_probes(true)` | **Fixed** — default off; config OR `--allow-active-probes`; `scan_web_cli` probe-hit tests |
| PROV-1 | Google API key in URL query (`?key=`) | **Fixed** — `x-goog-api-key` header for generateContent/list_models; transport/HTTP errors scrub key; sentinel tests in `vest-providers/src/google.rs` |
| REP-1 | JSON/MD reports embed raw evidence/PoC (incl. `match_preview` secrets) by default | **Fixed** — omit evidence/PoC by default; `--include-evidence` / `general.include_report_evidence` opt-in with best-effort redaction; `vest-report/tests/secret_redaction.rs` |
| POL-1 | Missing/non-string path/url skipped FS/net scope checks for scoped effects | **Fixed** — deny before handler when material target absent or wrong type; `adversarial_policy_tests.rs` + policy unit tests | `f918a47` |

## Phase status

| Phase | Status | Notes |
|-------|--------|-------|
| 0 Baseline | done | ledger + baseline check/fmt |
| 1 Product contract | done | docs; honesty pass ongoing |
| 2 ExecutionSession | done | session.rs + CLI wiring |
| 3 Interactive approval | **pending** | RequireInteractive still no prompt |
| 4 Opaque capabilities | **done** | `ApprovedToolCall` + SHA-256 digests; K5b hot path unified |
| 5 ScopedHttpClient | **done** (agent tools) | agent `http_get`/`http_post` on ScopedHttpClient; WebScanner still has its own client (WEB-1) |
| 6 Filesystem tools | pending | |
| 7 Egress | **done** (K4) | TargetContent/PSB gated; LocalContent/ProcessMemory unchanged |
| 8 Config/.env | done | allowlist |
| 9–20 | pending / partial | docs + acceptance updated; many code phases open |

## Remaining limitations (standing)

- Experimental product; not production-grade / fully sandboxed.
- DNS rebinding / connection-time IP binding incomplete.
- Process memory: simulation/unsupported only.
- Regex redaction is best-effort.
- No independent external audit.
- Interactive approval (K2) remains the loudest operator-facing control-plane gap.
