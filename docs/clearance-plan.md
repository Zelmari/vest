# Vest Clearance Plan

**Branch:** `main` only (no feature branches)  
**Baseline tip when plan written:** `fe1d041`  
**Last cleared tip:** `5b8758b` (STOR-1/2/3; after NUC-1 / PROV-2)
**Method:** Clear items one-by-one; each item gets code + regression tests + ledger update; keep CI green.  
**Living suite:** extend tests as behaviour changes (see Wave T).  
**Loop:** agent clearance loop continues until the open queue is empty and CI is green.

This plan merges: product ledger (K*/N*), docs honesty gaps (R*/D*), and full-repo scans of CLI / agent / scanner / providers / storage / report / tools / tests (2026-08-03).

---

## Operating rules

1. Stay on `main`. Commit + push after each cleared item (or tight batch of related files).
2. Prefer fail-closed, honest docs, and exact exit codes.
3. Every fix ships with at least one regression test that would have failed before.
4. Update `docs/product-hardening-ledger.md` status when an ID moves.
5. Do not mark acceptance 3–4 done without a real prompt or exact pre-auth grant path.
6. Re-run: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` before claiming a wave done.
7. Subagents: `cursor-grok-4.5-high-fast` for parallel implementation/review where useful.

---

## Severity legend

| Sev | Meaning |
|-----|---------|
| P0 | Contract/security hole operators can hit today |
| P1 | Real defect / soft-fail / incomplete control plane |
| P2 | Hardening, honesty, UX, or incomplete proofs |
| R* | Standing non-claims — document, don’t “fix” into fake guarantees |

---

## Wave 0 — Operator honesty & network boundary (do first)

| Order | ID | Item | Done when | Primary tests |
|------:|----|------|-----------|---------------|
| 1 | **N5** | CLI web scan must not force active probes; honour config / explicit flag | **Done** — CLI default probes off; opt-in enables | `passive_web_cli.rs` / extend `scan_web_cli.rs` |
| 2 | **K3** | Migrate CLI agent HTTP (`http_get`/`http_post`/`web_scan`) off `ureq` onto `ScopedHttpClient` | **Done** — no bare ureq for those tools; redirect re-auth | `agent_http_scoped_client.rs` |
| 3 | **K3b** | `web_scan` tool must not reimplement active probes via ureq | **Done** — single WebScanner path; probes gated | agent/web tool tests |
| 4 | **REP-1** | Reports must not dump raw secret evidence by default | **Done** — JSON/MD omit by default; opt-in + redaction | report secret sentinel tests |
| 5 | **PROV-1** | Google API key must not live in URL query string | **Done** — header auth; scrub errors | provider sentinel tests |
| 6 | **K4** | Gate `TargetContent` / `PotentiallySecretBearing` in `filter_for_model` | **Done** — default deny/stub or metadata-only | `target_content_egress_tests.rs` |

---

## Wave 1 — Approval, FS tools, scanner correctness

| Order | ID | Item | Done when | Primary tests |
|------:|----|------|-----------|---------------|
| 7 | **K2** | Interactive approval prompt OR exact CLI pre-grants; wire `--approve-*` | **Done** — TTY one-shot; non-TTY/`--no-approval` deny; CLI effect grants | interactive + `no_approval_cli.rs` |
| 8 | **K5b** | Unify hot path: `authorise` → `execute_authorised` → `filter_for_model` | **Done** — live path unified; `invoke` thin wrapper | `authorise_execute_hot_path_tests.rs` |
| 9 | **K8** | Bound `read_file` + `spawn_blocking` | **Done** — cap bytes; no full-file absorb | FS size/DoS tests |
| 10 | **POL-1** | Fail closed when path/url missing or non-string for scoped effects | **Done** — deny before handler | adversarial policy |
| 11 | **K11** | Honour form GET/POST in web probes | **Done** — correct method + query/body | web form method tests |
| 12 | **K9** | Symlink follow containment (or disable follow) | **Done** — escape impossible when follow=true | files_adversarial follow=true |
| 13 | **BRW-1** | Browser path walk: bounds, symlink policy, scoped navigate | **Done** — bounded walk + CDP basics | browser adversarial |
| 14 | **N1** | Dry-run validates config/target/scopes; no side effects | **Done** — invalid dry-run non-zero; plan printed | `dry_run_contract.rs` |

---

## Wave 2 — Exit codes, defaults, config, secrets

| Order | ID | Item | Done when | Primary tests |
|------:|----|------|-----------|---------------|
| 15 | **K14** | Prefer typed `VestError` everywhere; shrink string fallback | **Done** — scan/completions typed; strict matrix | `exit_codes_strict.rs` |
| 16 | **CLI-EXIT-7** | Provider/agent soft failure → exit 7 while preserving findings | **Done** — finalize then exit 7 | `exit_codes_strict.rs` |
| 17 | **CLI-PARTIAL** | Partial scanner failure policy (non-zero or explicit degraded) | **Done** — any scanner fatal → exit 5 after preserve | `exit_codes_strict.rs` |
| 18 | **N4** | `--offline` / `--no-ai` (and/or safer default than ollama) | **Done** — flags force `none`; no-provider default is `none` | `offline_cli.rs` |
| 19 | **N3** | `vest doctor` (+ optional `policy explain`) | **Done** — diagnostics + fail-closed bad config (`policy explain` still optional) | `doctor_cli.rs` |
| 20 | **CFG-1** | Validate agent/provider/network zeros; tighten unknown fields | **Done** — `load_config` rejects zeros; deny_unknown on sections | config torture |
| 21 | **PROV-2** | `SecretString` for provider keys; redacted Debug all backends | **Done** — OpenAI-compat/Anthropic/Google store `SecretString`; expose only at headers | provider secret sentinel tests |
| 22 | **PROV-3** | Apply `timeout_seconds` to clients + sequential fallback | **Done** — Hang → Timeout; fallback wraps per-provider timeout | fallback timeout tests |
| 23 | **PROV-4** | Google `list_models` fail-closed on HTTP errors | **Done** — Err not Ok(default) | google provider tests |

---

## Wave 3 — Persistence, tools, CVSS honesty

| Order | ID | Item | Done when | Primary tests |
|------:|----|------|-----------|---------------|
| 24 | **STOR-1** | No panic on corrupt rows; no silent JSON wipe | **Done** — datetime/JSON map to `StorageError` | storage edge |
| 25 | **STOR-2** | Never fall back to `:memory:` on bad path encoding | **Done** — hard UTF-8 path error | db path test |
| 26 | **STOR-3** | Transactional scan finalize; `rows_affected==0` → NotFound | **Done** — tx finalize + NotFound updates | storage + CLI |
| 27 | **NUC-1** | Nuclei: no cwd binary hijack; check exit; timeout; template root | **Done** — absolute `~/.vest/tools` / PATH only; exit+timeout; `-t` under allowlisted root | vest-tools nuclei fake-binary tests |
| 28 | **K16** | Rename heuristic score away from CVSS in types/reports/scanners | **Done** — `severity_score_estimate` + report labels; SQLite `cvss_score` mapped | severity rename + report |
| 29 | **REP-2** | Markdown fence escape for untrusted PoC/evidence | Safe MD | report injection |
| 30 | **CLI-SANDBOX** | Deny dangerous docker passthrough flags | Reject `--privileged` etc. | sandbox tests |

---

## Wave 4 — Depth, SSRF, remaining P2

| Order | ID | Item | Done when | Primary tests |
|------:|----|------|-----------|---------------|
| 31 | **HTTP-1** | Stream-cap bodies in ScopedHttpClient (don’t buffer full then truncate) | Memory bounded | http_client |
| 32 | **WEB-1** | Align WebScanner on ScopedHttpClient (delete duplicate client drift) | One HTTP path | web redirect/robots |
| 33 | **WEB-2** | Redirect method/body semantics (303→GET); robots on hops | Spec + tests | web |
| 34 | **R3-lite** | Optional deny of link-local/metadata IPs for scan targets | Config + docs | network scope |
| 35 | **BIN-1** | Binary scanner size cap + spawn_blocking | Bounded | binary |
| 36 | **POL-2** | Shrink public permissive APIs to test-only | `#[cfg(test)]` / test-utils | compile/lint |
| 37 | **CLI-SOFT** | Soft-ok subcommands (findings/config/tools) → proper exits | **Done** — findings missing / unknown config key / unknown tools → exit 2 | `cli_soft_dead.rs` |
| 38 | **CLI-DEAD** | `--resume` / approve flags: implement or error “unimplemented” | **Done** — `--resume` errors unimplemented (approve flags already wired) | `cli_soft_dead.rs` |
| 39 | **N2** | Re-verify config validate fail-closed → mark verified | **Done** — ledger N2 verified via `config_cli.rs` | `config_cli.rs` |
| 40 | **ACCEPT-12/13** | Storage failure + cancellation acceptance | **Done** — storage fail → exit 6; parallel drop cancels in-flight | `acceptance_storage_cancel.rs` + fallback cancel test |

---

## Wave T — Living test suite (continuous)

Add/update as waves land (do not wait for all waves):

| Module | Purpose |
|--------|---------|
| `vest-cli/tests/passive_web_cli.rs` | Contract B / N5 |
| `vest-cli/tests/no_approval_cli.rs` | K1 regression + acceptance 5 |
| `vest-cli/tests/agent_http_scoped_client.rs` | K3 |
| `vest-cli/tests/dry_run_contract.rs` | N1 |
| `vest-cli/tests/exit_codes_strict.rs` | K14 |
| `vest-cli/tests/doctor_cli.rs` | N3 |
| `vest-cli/tests/offline_cli.rs` | N4 |
| `vest-cli/tests/cli_soft_dead.rs` | CLI-SOFT / CLI-DEAD |
| `vest-cli/tests/acceptance_storage_cancel.rs` | ACCEPT-12 |
| `vest-cli/tests/config_cli.rs` | N2 |
| `vest-cli/tests/interactive_approval_cli.rs` | K2 (after UX) |
| `vest-agent/tests/target_content_egress_tests.rs` | K4 |
| `vest-agent/tests/interactive_approval_tests.rs` | K2 |
| `vest-report/tests/secret_redaction.rs` | REP-1 |
| `vest-core/tests/severity_estimate_rename.rs` | K16 |
| Tighten soft asserts in `scan_web_cli`, `exit_codes`, concurrency bands | quality |

---

## Standing non-claims (do not “clear” by lying)

Keep documented forever unless architecture truly changes:

- **R1** Experimental / not production-grade  
- **R2** Not an OS sandbox  
- **R3** Full DNS-rebinding prevention incomplete (partial mitigation = R3-lite)  
- **R4** No real process-memory forensics  
- **R5** Regex redaction best-effort  
- **R6** No independent external audit  
- **R19–R22** Model untrusted; non-goals (exploit/shell/credential theft/certification)

---

## Clearance queue (open at plan start)

```
N5 ✓ → K3 ✓ → K3b ✓ → REP-1 ✓ → PROV-1 ✓ → K4 ✓ → K2 ✓ → K5b ✓ → K8 ✓ → POL-1 ✓ → K11 ✓ → K9 ✓
→ BRW-1 ✓ → N1 ✓ → K14 ✓ → CLI-EXIT-7 ✓ → CLI-PARTIAL ✓ → N4 ✓ → N3 ✓ → CFG-1 ✓
→ PROV-2 ✓ → PROV-3 ✓ → PROV-4 ✓ → STOR-1 ✓ → STOR-2 ✓ → STOR-3 ✓ → NUC-1 ✓ → K16 ✓ → REP-2 ✓
→ CLI-SANDBOX ✓ → HTTP-1 → WEB-1 → WEB-2 → R3-lite → BIN-1 → POL-2
→ CLI-SOFT ✓ → CLI-DEAD ✓ → N2 ✓ → ACCEPT-12/13 ✓
```

**Next open:** HTTP-1 (then WEB-1…).

**Progress tracking:** update the table in `docs/product-hardening-ledger.md` and the checkbox section below after each clear.

### Progress checkboxes

- [x] N5 CLI web probes default off
- [x] K3 agent HTTP → ScopedHttpClient
- [x] K3b web_scan tool unified
- [x] REP-1 report secret redaction
- [x] PROV-1 Google key not in URL
- [x] K4 TargetContent egress gate
- [x] K2 interactive / exact grants
- [x] K5b authorise→execute_authorised→filter
- [x] K8 bounded read_file
- [x] POL-1 material target fail-closed
- [x] K11 form method
- [x] K9 symlink containment
- [x] BRW-1 browser FS/CDP bounds
- [x] N1 dry-run contract
- [x] K14 typed exits
- [x] CLI-EXIT-7 provider soft exit
- [x] CLI-PARTIAL scanner policy
- [x] N4 offline flag/default
- [x] N3 doctor
- [x] CFG-1 config validate zeros
- [x] PROV-2 SecretString providers
- [x] PROV-3 timeouts wired
- [x] PROV-4 google list_models
- [x] STOR-1/2/3 persistence
- [x] NUC-1 nuclei safety
- [x] K16 severity rename
- [x] REP-2 markdown escape
- [x] CLI-SANDBOX docker deny
- [ ] HTTP-1/WEB-1/WEB-2 client unify
- [ ] R3-lite IP deny option
- [x] BIN-1 binary bounds
- [x] POL-2 permissive API hygiene
- [x] CLI-SOFT / CLI-DEAD
- [x] N2 verified
- [x] ACCEPT-12/13

---

## Loop prompt (for agent wakeups)

```
On main only. Read docs/clearance-plan.md and docs/product-hardening-ledger.md.
Take the first unchecked Progress checkbox. Implement the fix, add/update tests,
run fmt/clippy/test for affected crates (full workspace when touching auth/HTTP),
update ledger + checkbox, commit and push to main. Then stop if queue empty and
CI green; else continue to next item until turn budget, then re-arm the loop.
Use cursor-grok-4.5-high-fast subagents for parallel impl/review when helpful.
```
