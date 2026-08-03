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
2. **HTTP to scan target** — web scanner uses scoped client construction; **CLI agent HTTP tools (`http_get` / `http_post` / related helpers) still call `ureq` directly** in `vest-cli/src/commands/scan.rs`. Those are not “scoped client only.”
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
| All HTTP goes through `ScopedHttpClient` | Scanner web client: yes foundations. Agent CLI tools: still `ureq`. |
| Interactive approval step always exists | No prompt UI; `RequireInteractive` → deny. |
| CLI web scan is passive | CLI enables active probes today. |
