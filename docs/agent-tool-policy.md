# Agent Tool Policy

**Status:** Experimental. Describes the intended and implemented policy engine after the verified security-hardening pass.

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
  -> NormalisedToolCall::from_parts (path/url/method/pid + arg_digest)
  -> PolicyEngine::evaluate(AuthorisationContext, call)
       - empty tool id → deny
       - unknown effect → deny
       - filesystem scope check (canonical path under ApprovedFilesystemScope)
       - network scope check (parsed origin under ApprovedNetworkScope)
       - matching ApprovalToken (tool, effect, target, arg digest, session, TTL)
       - interactive / non-interactive rules for high-impact effects
  -> on Allow: execute handler
  -> classify + filter result for model egress (see model-data-boundary.md)
```

## `requires_approval` is not a bypass

`ToolDefinition.requires_approval` is **UX / risk metadata** derived from effect strength. It must **never** skip the policy engine.

In the tool-use pattern, every parsed tool call is evaluated regardless of that flag. `ToolRegistry::invoke` / `execute_authorised` likewise require an `Allow` decision.

## Approvals

- Approvals are scoped `ApprovalToken`s: tool id, effect, normalised target, **arg digest**, session id, expiry (and optional one-shot).
- Broad category grants (`grant_approval("write")`) are intentionally no-ops and do not bypass policy.
- Argument mutation produces a different digest and invalidates a prior token.
- Non-interactive sessions fail closed for effects that require interactive approval.

## Authorisation context

`AuthorisationContext` is derived from user intent for the session:

- `ApprovedFilesystemScope` from the scan target (and any explicitly authorised roots)
- `ApprovedNetworkScope` from the authorised URL/host origin
- Egress flags (`allow_local_content_egress`, `allow_process_memory_egress`, `allow_evidence_egress`) — default restrictive
- `permissive_effects` — test/escape hatch only; unknown effects still deny

## Unknown tools

Unregistered tool names map to `ToolEffect::Unknown` / `DataEgressClass::Prohibited` and are denied. There is no permissive default for mystery tools.

## Related

- [security-model.md](security-model.md)
- [model-data-boundary.md](model-data-boundary.md)
