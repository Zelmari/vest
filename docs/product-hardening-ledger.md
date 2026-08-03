# Product Hardening Ledger

**Branch:** `product/real-world-hardening`  
**Baseline commit:** `37733b1` (main after merge of verified security pass + README)  
**Toolchain:** rustc/cargo 1.96.1  
**Started:** 2026-08-03  

This file is the authoritative progress ledger. Update continuously.

## Baseline commands

| Command | Result |
|---------|--------|
| `cargo fmt --all -- --check` | Pass |
| `cargo check --workspace --all-targets --all-features` | Pass |
| `cargo test --workspace --all-features` | Pending re-run after phase commits |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Pending |

## Workspace

Members: vest-core, vest-cli, vest-config, vest-providers, vest-agent, vest-scanner, vest-storage, vest-report, vest-tools, vest-payloads, vest-test-utils.  
Binary: `vest` (`vest-cli`). Feature: `browser` (default).

## Product use cases (summary)

See [product-contract.md](product-contract.md): A offline local, B passive web, C active (approval), D AI egress, E tool-use, F CI, G degraded, H large target.

## Threat boundaries

- Model output is untrusted and grants no authority.
- Authorised use only; tests use loopback / temp dirs / fake providers.
- Action approval ≠ model egress approval.
- Fail closed on unknown effects, bad config, missing approval.

---

## Known-issue matrix (K1–K18)

| ID | Status | Evidence | Planned / done | Tests | Commit |
|----|--------|----------|----------------|-------|--------|
| K1 | **Fixed** | Was calling `SafetyChecker::permissive()` | `--no-approval` = non-interactive deny; no permissive path | CLI tests | `17d2232`+session |
| K2 | **Confirmed** | `RequireInteractive` → deny/false; no stdin prompt; `--approve-*` flips legacy booleans | Interactive prompt + opaque grant | acceptance 3–4 | pending |
| K3 | **Confirmed** | Agent tools use `ureq` in `scan.rs` (~646+) | Migrate to ScopedHttpClient | web/agent tests | HTTP agent + follow-up |
| K4 | **Partially confirmed** | LocalContent/ProcessMemory blocked; TargetContent may redact-only | Align filter_for_model with contract | egress tests | pending |
| K5 | **Confirmed** | `execute_authorised` accepts public `ApprovalDecision::Allow` | Opaque `ApprovedToolCall` capability | policy tests | pending |
| K6 | **Confirmed** | `DefaultHasher` + selected keys in `policy.rs` `material_args` | SHA-256 over canonical JSON of all args | property tests | pending |
| K7 | **Fixed** | Was `TOOL_FS_SCOPE` OnceLock | `ExecutionSession` Arc captured by tools | session unit test | this commit |
| K8 | **Confirmed** (hypothesis) | read_file likely full read | Bound + spawn_blocking | FS tests | pending |
| K9 | **Partial** | follow_symlinks exists; need prove containment | Contain or disable | adversarial FS | pending |
| K10 | **Fixed** (web) | `unwrap_or_default()` on Client | `expect` fail-closed + `ScopedHttpClient::try_new` Result | http_client tests | this commit |
| K11 | **Investigate** | form submit method | Honour GET/POST | web tests | pending |
| K12 | **Fixed** | invalid `--target-type` guessed | Reject invalid explicit type | CLI | `17d2232` |
| K13 | **Fixed** (util) | byte-index risk | `truncate_chars` in vest-core | unit | `17d2232` |
| K14 | **Partial** | string match still as legacy fallback | Prefer `VestError::cli_exit_code()` | unit | `17d2232` |
| K15 | **Fixed** | all keys loaded | Allowlist Vest/provider keys | unit | `17d2232` |
| K16 | **Confirmed** | `Finding.cvss_score` + scanner `Some(7.8)` heuristics | Rename to severity_estimate / metadata | types+report | pending |
| K17 | **Confirmed** | prior audit “addressed” while CLI bypasses remain | Re-evaluate after wiring | ledger | ongoing |
| K18 | **Re-verify** | prior pass merged | Regression suite | workspace tests | ongoing |

## Newly discovered issues

| ID | Issue | Status |
|----|-------|--------|
| N1 | Dry-run returns before config load / scope display | open |
| N2 | `config validate` historically soft-failed (fixed on prior branch; re-verify) | verify |
| N3 | No `vest doctor` / `policy explain` | open |
| N4 | No explicit `--offline` / `--no-ai` flags (provider none only) | open |

## Phase status

| Phase | Status | Notes |
|-------|--------|-------|
| 0 Baseline | done | branch + ledger + baseline check/fmt |
| 1 Product contract | in progress | docs/product-contract.md |
| 2 ExecutionSession | done | session.rs + CLI wiring |
| 3 Interactive approval | pending | RequireInteractive still no prompt |
| 4 Opaque capabilities | pending | execute_authorised still forgeable |
| 5 ScopedHttpClient | partial | module + tests; agent ureq not migrated |
| 6 Filesystem tools | pending | |
| 7 Egress | pending | |
| 8 Config/.env | done | allowlist |
| 9–20 | pending | |

## Remaining limitations (standing)

- Experimental product; not production-grade / fully sandboxed.
- DNS rebinding / connection-time IP binding incomplete.
- Process memory: simulation/unsupported only.
- Regex redaction is best-effort.
- No independent external audit.
