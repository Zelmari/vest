# Agent Tool Policy

**Status:** Experimental. Describes the policy engine as implemented on current `main`.

## Central rule

**Model output is untrusted data. It does not grant authority.**

An LLM may propose tool names and arguments. Those proposals are normalised into a `NormalisedToolCall` and evaluated by `PolicyEngine::evaluate` before any side effect. Registry metadata never replaces that evaluation.

## ToolEffect

Every registered tool declares an explicit [`ToolEffect`](../vest-core/src/auth/mod.rs) — never inferred from name substrings.

| Effect | Meaning (summary) |
|--------|-------------------|
| `PureComputation` | No FS/network/process side effects |
| `LocalMetadataRead` | List/stat under authorised roots |
| `LocalFileContentRead` | Read file bytes under authorised roots |
| `LocalWrite` | Mutate local filesystem |
| `NetworkMetadataRead` | DNS/TLS/port metadata within scope |
| `PassiveNetworkRequest` | Non-mutating HTTP (e.g. GET) within scope |
| `ActiveNetworkProbe` | Vulnerability probes / active scanning |
| `StateChangingNetworkRequest` | Mutating HTTP (POST/PUT/PATCH/DELETE/…) |
| `ProcessMetadataRead` | Process listing / metadata |
| `ProcessMemoryRead` | Raw process memory (stronger than metadata) |
| `CommandExecution` | Subprocess / shell |
| `CredentialAccess` | Credential material access |
| `Unknown` | Fail closed — always denied |

Stronger effects are **not** implied by weaker approvals (e.g. GET ≠ POST; metadata ≠ memory; path A ≠ path B).

## Evaluation flow

```
model proposes tool call
  -> look up registered ToolDefinition (effect + egress_class)
     (missing tool → ToolEffect::Unknown → deny)
  -> NormalisedToolCall::from_parts (path/url/method/pid + SHA-256 arg_digest)
  -> PolicyEngine::authorise(AuthorisationContext, call)
       - evaluate (empty tool id / unknown effect / material target / FS+net scope / grants / interactive)
       - on Allow: mint opaque ApprovedToolCall (forgeable public Allow is not accepted)
  -> ToolRegistry::execute_authorised(handler, ApprovedToolCall, ctx)
       - capability must match tool id, args digest, session
       - run handler
       - classify + filter_for_model (egress always applied before model sees results)
  -> ToolRegistry::invoke is a thin wrapper over the same hot path
```

## Opaque approval capability

`ToolRegistry::execute_authorised` takes an [`ApprovedToolCall`](../vest-agent/src/approved.rs), not a public `ApprovalDecision::Allow`. Fields are private; only the policy engine mints the capability after a successful evaluation. Argument digests are SHA-256 over canonical material args.

## `requires_approval` is not a bypass

`ToolDefinition.requires_approval` is **UX / risk metadata** derived from effect strength. It must **never** skip the policy engine.

In the tool-use pattern, every parsed tool call is evaluated regardless of that flag.

## Interactive approval / CLI pre-grants (K2)

Exact **effect + session** pre-grants are the primary production path:

- `--approve-writes` → `LocalWrite` for the session
- `--approve-exploits` → `ActiveNetworkProbe`, `StateChangingNetworkRequest`, `CommandExecution`
- `--approve-effect <snake_case>` (repeatable) → exact `ToolEffect` (e.g. `local_file_content_read`)
- Grants never bypass filesystem/network scope checks and never imply a stronger effect.

TTY one-shot prompt: when `interactive=true` (stdin is a TTY and not `--no-approval`) and policy returns `RequireInteractive`, Vest may prompt `Allow once? [y/N]` on stderr and mint a one-shot `ApprovalToken` on yes.

Fail-closed:

- `--no-approval` → non-interactive deny; conflicts with approve flags; not a permissive bypass
- Non-TTY without approve flags → deny (no prompt)
- Broad string `grant_approval("write")` remains a no-op; use effect/session grants
- Argument mutation invalidates exact call tokens (digest mismatch)

## Authorisation context

`AuthorisationContext` / `ExecutionSession` are derived from user intent for the session:

- `ApprovedFilesystemScope` from the scan target (and any explicitly authorised roots)
- `ApprovedNetworkScope` from the authorised URL/host origin
- Egress flags (`allow_local_content_egress`, `allow_process_memory_egress`, `allow_target_content_egress`, `allow_potentially_secret_bearing_egress`, `allow_evidence_egress`) — default restrictive
- `permissive_effects` — test/escape hatch only; unknown effects still deny

## Unknown tools

Unregistered tool names map to `ToolEffect::Unknown` / `DataEgressClass::Prohibited` and are denied. There is no permissive default for mystery tools.

## Related HTTP status

CLI-registered agent HTTP tools (`http_get` / `http_post` / `web_scan`) use `ScopedHttpClient` / `WebScanner::inspect_url` with redirect re-auth and the same active-probe gating as CLI web scans (**K3**/**K3b** cleared). Remaining unify work: `WebScanner` itself is not fully on `ScopedHttpClient` (**WEB-1**). See [data-flow.md](data-flow.md) and [clearance-plan.md](clearance-plan.md).

## Related

- [security-model.md](security-model.md)
- [model-data-boundary.md](model-data-boundary.md)
- [product-hardening-ledger.md](product-hardening-ledger.md)
- [clearance-plan.md](clearance-plan.md)
