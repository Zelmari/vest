# Vest Next Backlog

**Branch:** `main` only  
**Started tip:** `2afc753`  
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
| 6 | B1 | Connect-time IP pin when `deny_private_targets` | pending |
| 7 | B2 | Provider HTTP: no auto-redirect | done |
| 8 | B3 | CDP WS loopback pin + browser_inspect effect honesty | done |
| 9 | B4 | Nuclei: always constrain `-t` / disable update-check | pending |
| 10 | B5 | CLI active-probe consent parity with agent path | pending |

### Wave C — Product unlocks
| # | ID | Item | Status |
|---|----|------|--------|
| 11 | C1 | CI baseline / fail-on-new (compare + exit) | pending |
| 12 | C2 | Finish or hide `--resume` | pending |
| 13 | C3 | SARIF export | pending |
| 14 | C4 | Profile discovery (`--list-profiles` / dry-run clarity) | pending |

### Wave D — Codebase health (as time allows)
| # | ID | Item | Status |
|---|----|------|--------|
| 15 | D1 | Extract agent tools out of `scan.rs` | pending |
| 16 | D2 | Typed tool errors (retire string handlers where practical) | pending |
| 17 | D3 | Drop unused disasm deps or wire them; payloads crate triage | pending |

## Progress checkboxes

- [x] A1 JSON stdout
- [x] A2 Docs sync
- [x] A3 Profile/mode reject
- [x] A4 Profile safety wire/delete
- [x] A5 CI locked/all-features
- [ ] B1 Connect-time IP pin
- [x] B2 Provider redirect-none
- [x] B3 CDP loopback pin
- [ ] B4 Nuclei template constraint
- [ ] B5 Active probe consent
- [ ] C1 Fail-on-new baseline
- [ ] C2 Resume
- [ ] C3 SARIF
- [ ] C4 Profile discovery
- [ ] D1 Tool extraction
- [ ] D2 Typed tool errors
- [ ] D3 Dead deps/payloads

## Loop prompt

```
On main only. Read docs/next-backlog.md. Take the first unchecked checkbox.
Implement + tests, fmt/clippy/relevant tests, update checkbox, commit (Zelmari only,
no Co-authored-by Cursor). Push when a wave batch is green. Continue until queue empty.
```
