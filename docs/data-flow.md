# Vest Data Flow

## Happy path

```
User CLI intent
  → config (validated; present+bad = error)
  → ExecutionSession (scopes, budgets, interactive?, egress flags)
  → scanners (bounded FS / scoped HTTP)
  → local Findings
  → optional agent / provider
       → tool proposal (untrusted)
       → NormalisedToolCall
       → PolicyEngine
       → opaque approval (if required)
       → tool execution
       → DataEgressClass filter → allowlisted DTO
       → provider
  → report (stdout / file) + optional SQLite
```

## Where data can leave the machine

1. **Remote LLM providers** — only after egress filtering.
2. **HTTP to scan target** — scoped client only; authorised origin.
3. **External tools** (e.g. nuclei) — subprocess against authorised targets.
4. **User-selected report paths** — local disk.
5. **SQLite under VEST_HOME** — local persistence.
6. **Logs (stderr)** — metadata only; no secrets / raw evidence by default.

## What stays local by default

- File contents from the target tree.
- Process memory (and simulation bytes).
- Raw HTTP response bodies (unless TargetContent egress approved).
- API keys / cookies / Authorization headers.
- Full provider error bodies.

## Action vs egress

Authorising `read_file` does **not** authorise sending that content to a model.
Egress is a second gate (`DataEgressClass` + session flags / approvals).
