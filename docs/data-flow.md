# Vest Data Flow

**Status:** Describes current `main`. Gaps are called out explicitly.

## Happy path

```
User CLI intent
  → config (validated; present+bad = error)
  → ExecutionSession (scopes, budgets, interactive?, egress flags)
  → scanners (bounded FS / scoped HTTP where wired)
  → local Findings
  → optional agent / provider
       → tool proposal (untrusted)
       → NormalisedToolCall
       → PolicyEngine
       → opaque ApprovedToolCall (if allowed)
       → tool execution
       → DataEgressClass filter → allowlisted DTO
       → provider
  → report (stdout / file) + optional SQLite
```

## Where data can leave the machine

1. **Remote LLM providers** — only after egress filtering on the agent/validator paths that use it.
2. **HTTP to scan target** — web scanner and CLI agent HTTP tools (`http_get` / `http_post` / `web_scan`) use `ScopedHttpClient` (redirect re-auth). `WebScanner` crawl/fetch is on that same client (**WEB-1** cleared).
3. **External tools** (e.g. nuclei) — subprocess against authorised targets.
4. **User-selected report paths** — local disk.
5. **SQLite under VEST_HOME** — local persistence.
6. **Logs (stderr)** — metadata only by intent; no secrets / raw evidence by default (best-effort).

## What stays local by default

- File contents from the target tree.
- Process memory (and simulation bytes).
- Raw HTTP response bodies (unless TargetContent egress is approved / allowed).
- API keys / cookies / Authorization headers.
- Full provider error bodies (sanitised on the validator path).

## Action vs egress

Authorising `read_file` does **not** authorise sending that content to a model.
Egress is a second gate (`DataEgressClass` + session flags / approvals).

## Known mismatches vs the diagram

| Claim people might assume | Reality on `main` |
|---------------------------|-------------------|
| All HTTP goes through `ScopedHttpClient` | Agent CLI `http_get`/`http_post`/`web_scan`: yes. `WebScanner` crawl/fetch: yes (**WEB-1**). Provider transports remain separate. |
| Interactive approval step always exists | Exact CLI pre-grants + optional TTY one-shot; non-TTY/`--no-approval` deny (**K2**). |
| CLI web scan is passive | Default off; two-key consent (allow + confirm/approve-exploits) (**N5**/**B5**). |

Clearance order / remaining work: [clearance-plan.md](clearance-plan.md).
