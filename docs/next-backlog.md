# Vest Next Backlog

**Branch:** `main` only  
**Started tip:** `2afc753`  
**Completed tip:** `6656021` — all A/B/C/D checkboxes cleared  
**Status:** Queue complete; post-queue majors M1–M3 shipped @ `9148199`. Next open queue: `docs/standing-backlog.md`.  
**Method:** Clear items one-by-one; commit at each meaningful change; keep CI green.  
**Standing non-claims (R1–R6):** not in this queue.

## Queue order

### Wave A — Honesty & operator UX (fast)
| # | ID | Item | Status |
|---|----|------|--------|
| 1 | A1 | JSON-clean stdout (banners/progress → stderr when `-f json`) | done |
| 2 | A2 | Docs sync (WEB-1 / passive web / ledger drift) | done |
| 3 | A3 | Reject unknown `--profile` / invalid `--mode` | done |
| 4 | A4 | Wire or delete unused profile `safety` overrides | done |
| 5 | A5 | CI: `--locked` + `--all-features`; smarter flake strategy | done |

### Wave B — Security residuals
| # | ID | Item | Status |
|---|----|------|--------|
| 6 | B1 | Connect-time IP pin when `deny_private_targets` | done |
| 7 | B2 | Provider HTTP: no auto-redirect | done |
| 8 | B3 | CDP WS loopback pin + browser_inspect effect honesty | done |
| 9 | B4 | Nuclei: always constrain `-t` / disable update-check | done |
| 10 | B5 | CLI active-probe consent parity with agent path | done |

### Wave C — Product unlocks
| # | ID | Item | Status |
|---|----|------|--------|
| 11 | C1 | CI baseline / fail-on-new (compare + exit) | done |
| 12 | C2 | Finish or hide `--resume` | done — superseded by M1: real `--resume` + SQLite checkpoints shipped (`docs/major-backlog.md`) |
| 13 | C3 | SARIF export | done |
| 14 | C4 | Profile discovery (`--list-profiles` / dry-run clarity) | done |

### Wave D — Codebase health (as time allows)
| # | ID | Item | Status |
|---|----|------|--------|
| 15 | D1 | Extract agent tools out of `scan.rs` | done |
| 16 | D2 | Typed tool errors (retire string handlers where practical) | done (partial: `ToolError`→`VestError`; approval→exit 4; residual stringly `Handler`) |
| 17 | D3 | Drop unused disasm deps or wire them; payloads crate triage | done |

## Progress checkboxes

- [x] A1 JSON stdout
- [x] A2 Docs sync
- [x] A3 Profile/mode reject
- [x] A4 Profile safety wire/delete
- [x] A5 CI locked/all-features
- [x] B1 Connect-time IP pin
- [x] B2 Provider redirect-none
- [x] B3 CDP loopback pin
- [x] B4 Nuclei template constraint
- [x] B5 Active probe consent
- [x] C1 Fail-on-new baseline (`--fail-on-severity` / `--fail-on-new`, exit 8)
- [x] C2 Resume (superseded by M1 — real `--resume` + SQLite checkpoints shipped; flag visible in scan help)
- [x] C3 SARIF
- [x] C4 Profile discovery (`vest scan --list-profiles`; dry-run names selected profile)
- [x] D1 Tool extraction
- [x] D2 Typed tool errors (`ToolError` on registry + CLI helpers; approval denials exit 4; residual: many handler bodies still `ToolError::Handler(String)`)
- [x] D3 Dead deps/payloads (dropped unused capstone/iced-x86 + dead `disassembler` config; `vest-payloads` removed from workspace members, directory kept)

## Loop prompt

```
On main only. Read docs/next-backlog.md. Take the first unchecked checkbox.
Implement + tests, fmt/clippy/relevant tests, update checkbox, commit (Zelmari only,
no Co-authored-by Cursor). Push when a wave batch is green. Continue until queue empty.
```
