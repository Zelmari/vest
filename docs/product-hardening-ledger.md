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

See [product-contract.md](product-contract.md): A offline local, B passive web, C active (TTY one-shot / CLI pre-grants), D AI egress, E tool-use, F CI, G degraded, H large target.

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
| K2 | **Fixed** | Was deny-only; `--approve-*` discarded | Effect+session grants + TTY one-shot prompt | `interactive_approval_tests` + `no_approval_cli` | `78d4447` |
| K3 | **Fixed** | Agent tools used `ureq` in `scan.rs` | `http_get`/`http_post` via `ScopedHttpClient`; redirect re-auth | `agent_http_scoped_client.rs` | `5a5fc2c` |
| K3b | **Fixed** | `web_scan` reimplemented probes via `ureq` | `WebScanner::inspect_url`; probes gated like CLI | `agent_http_scoped_client.rs` | `5a5fc2c` |
| K4 | **Fixed** | TargetContent/PotentiallySecretBearing were redact-only | Default stub/metadata; flags for opt-in egress | `target_content_egress_tests.rs` | `dbd5e0c` |
| K5 | **Fixed** | Was forgeable `ApprovalDecision::Allow` | Opaque `ApprovedToolCall` | policy/approved tests | `1951cd2` |
| K5b | **Fixed** | tool-use used evaluate+invoke; `execute_authorised` skipped egress | Live path `authorise`→`execute_authorised`→`filter_for_model`; `invoke` thin wrapper | `authorise_execute_hot_path_tests.rs` | `8324002` |
| K6 | **Fixed** | Was `DefaultHasher` on selected keys | SHA-256 over material args | policy tests | `1951cd2` |
| K7 | **Fixed** | Was `TOOL_FS_SCOPE` OnceLock | `ExecutionSession` Arc captured by tools | session unit test | `0f76c32` |
| K8 | **Fixed** | Was `std::fs::read` entire file then truncate | Cap via `Read::take` + `spawn_blocking` | `agent_read_file_bounded.rs` | `b7a0744` |
| K9 | **Fixed** | follow=true had no root containment | Resolved paths must stay under canonical root else skip OutsideRoot | `files_adversarial` follow=true + unit | `5975b22` |
| K10 | **Fixed** (web client) | `unwrap_or_default()` on Client | fail-closed + `ScopedHttpClient::try_new` | http_client tests | `0f76c32` |
| K11 | **Fixed** | form submit always POSTed | Honour GET/POST (allowlist); GET→query; missing method→GET | web form method tests | `a43df3f` |
| K12 | **Fixed** | invalid `--target-type` guessed | Reject invalid explicit type | CLI | `17d2232` |
| K13 | **Fixed** (util) | byte-index risk | `truncate_chars` in vest-core | unit | `17d2232` |
| K14 | **Fixed** | string match still as legacy fallback | Scan/completions typed; legacy fallback last-resort for other cmds | `exit_codes_strict.rs` | `f83e640` |
| K15 | **Fixed** | all keys loaded | Allowlist Vest/provider keys | unit | `17d2232` |
| K16 | **Fixed** | `Finding.cvss_score` + scanner heuristics labelled CVSS | Renamed to `severity_score_estimate`; reports never say CVSS for heuristics; SQLite column `cvss_score` dual-mapped | `severity_estimate_rename.rs` + report unit | 91ceff1 |
| K17 | **Open** | prior audit “addressed” while CLI bypasses remain | Keep docs/ledger honest; close wiring gaps | ledger | ongoing |
| K18 | **Ongoing** | prior pass merged | Regression suite | workspace tests | ongoing |

## Newly discovered issues

| ID | Issue | Status |
|----|-------|--------|
| N1 | Dry-run returns before config load / scope display | **Fixed** — load/validate config, detect target, resolve scopes, print plan (scanners/probes/provider/scopes); no DB/network/scanner side effects; invalid type/config → non-zero; `dry_run_contract.rs` | `02dc51e` |
| N2 | `config validate` historically soft-failed | **Verified** — fail-closed: malformed / invalid safety → non-zero (exit 3); valid config → 0; `config show` refuses silent defaults on present bad file | `config_cli.rs` (`validate_rejects_malformed_config_with_nonzero_exit`, `validate_rejects_invalid_safety_bounds`, `show_fails_closed_on_present_malformed_file`) | re-verified after `1a03661` |
| N3 | No `vest doctor` / `policy explain` | **Fixed** — `vest doctor` prints config/VEST_HOME/sqlite/provider-key presence/posture/policy; fail-closed on bad config; `policy explain` still optional | `doctor_cli.rs` | `f83e640` |
| N4 | No explicit `--offline` / `--no-ai` flags (provider none only) | **Fixed** — `--offline` / `--no-ai` force provider `none`; safer default is `none` when no provider configured | `offline_cli.rs` | `f83e640` |
| N5 | CLI web scan forces `with_allow_active_probes(true)` | **Fixed** — default off; config OR `--allow-active-probes`; `scan_web_cli` probe-hit tests |
| CLI-EXIT-7 | Provider/agent soft fail exited 0 | **Fixed** — preserve findings/report then exit 7 (`VestError::Provider`/`Agent`) | `exit_codes_strict.rs` | `f83e640` |
| CLI-PARTIAL | Partial scanner fatals exited 0 | **Fixed** — preserve successful scanner findings then exit 5; total fail stays hard error | `exit_codes_strict.rs` | `f83e640` |
| PROV-1 | Google API key in URL query (`?key=`) | **Fixed** — `x-goog-api-key` header for generateContent/list_models; transport/HTTP errors scrub key; sentinel tests in `vest-providers/src/google.rs` |
| PROV-2 | Provider API keys stored as bare `String` (Debug/log leak risk) | **Fixed** — OpenAI-compat/`Option<SecretString>`, Anthropic/Google `SecretString`; redacted Debug; `expose()` only at header construction; sentinel Debug/error tests |
| CFG-1 | Agent/provider/network zero budgets accepted | **Fixed** — `load_config`/`validate_config` reject zeros; deny_unknown on agent/provider/network | `c426801` |
| PROV-3 | Provider timeout_seconds unused; sequential fallback unbounded | **Fixed** — reqwest clients use timeout; NextOnFailure/NextOnRateLimit wrap per-provider timeout | `a05b291` |
| PROV-4 | Google list_models returns Ok(default) on HTTP errors | **Fixed** — fail-closed Err on non-2xx; sentinel scrub test | `a05b291` |
| STOR-1 | Row mappers panic on bad datetime; silent JSON default | **Fixed** — `StorageError` via conversion failure; no silent evidence wipe | `storage_edge_cases` | `5b8758b` |
| STOR-2 | `open_pool` fell back to `:memory:` on non-UTF8 path | **Fixed** — hard error via `db_path_as_str` | db.rs unit | `5b8758b` |
| STOR-3 | Non-atomic scan persist; updates ignore missing rows | **Fixed** — transactional finalize; `rows_affected==0` → NotFound | scan + storage | `5b8758b` |
| NUC-1 | Nuclei cwd binary hijack; ignored exit; no timeout; open `-t` | **Fixed** — absolute `~/.vest/tools/nuclei` or `which`; exit+timeout kill; templates under `~/.vest/tools/nuclei-templates` | vest-tools nuclei fake-binary tests | `bfb3bbf` |
| REP-1 | JSON/MD reports embed raw evidence/PoC (incl. `match_preview` secrets) by default | **Fixed** — omit evidence/PoC by default; `--include-evidence` / `general.include_report_evidence` opt-in with best-effort redaction; `vest-report/tests/secret_redaction.rs` |
| REP-2 | Untrusted PoC/evidence can break markdown code fences via ` ``` ` | **Fixed** — escape triple backticks in evidence/PoC when rendering Markdown; `vest-report/tests/markdown_fence_escape.rs` | `5f397eb` |
| CLI-SANDBOX | `vest sandbox start` passes through dangerous docker flags | **Fixed** — reject `--privileged`, host namespaces, root/sensitive binds; keep experimental warning | sandbox unit tests |
| POL-1 | Missing/non-string path/url skipped FS/net scope checks for scoped effects | **Fixed** — deny before handler when material target absent or wrong type; `adversarial_policy_tests.rs` + policy unit tests | `f918a47` |

| BRW-1 | Browser path walk unbounded; CDP navigate/`json/version` loosely bounded; handler dropped | **Fixed** — `collect_files_bounded` + symlink-off defaults; reject `file://` navigate; cap CDP version body; keep handler task alive; `browser_adversarial.rs` | `04c161e` |

## Phase status

| Phase | Status | Notes |
|-------|--------|-------|
| 0 Baseline | done | ledger + baseline check/fmt |
| 1 Product contract | done | docs; honesty pass ongoing |
| 2 ExecutionSession | done | session.rs + CLI wiring |
| 3 Interactive approval | **done** (pragmatic) | Exact CLI pre-grants + TTY one-shot; non-TTY/`--no-approval` deny |
| 4 Opaque capabilities | **done** | `ApprovedToolCall` + SHA-256 digests; K5b hot path unified |
| 5 ScopedHttpClient | **done** | agent tools + WebScanner crawl/fetch on ScopedHttpClient (WEB-1); stream-cap bodies (HTTP-1); 302/303→GET + robots on hops (WEB-2 practical) |
| 6 Filesystem tools | **done** (K8/K9) | bounded `read_file`; symlink follow contained under root |
| 7 Egress | **done** (K4) | TargetContent/PSB gated; LocalContent/ProcessMemory unchanged |
| 8 Config/.env | **done** | key allowlist + CFG-1 zero-budget reject |
| 9–20 | partial | exits/doctor/offline/providers/NUC-1/STOR/K16 landed; WEB-1/HTTP-1/WEB-2 practical cleared; standing gaps remain (DNS rebinding / connect-time IP pin, etc.) |

## Remaining limitations (standing)

- Experimental product; not production-grade / fully sandboxed.
- DNS rebinding / connection-time IP binding incomplete.
- Process memory: simulation/unsupported only.
- Regex redaction is best-effort.
- No independent external audit.
- Full multi-step interactive approval UX is still minimal (TTY one-shot + exact CLI pre-grants cover K2).
