# Model Data Boundary

**Status:** Experimental. Authorising a tool action is **not** authorising data to leave the machine toward a remote model.

## Principle

Action authorisation (filesystem/network scope + `ToolEffect`) and **model egress** are separate decisions. Tool results and findings are classified with `DataEgressClass`, then filtered, bounded, and redacted before insertion into provider request payloads.

Regex redaction is **best-effort** and will miss novel secret formats. Prefer allowlisted DTOs and explicit egress flags over hoping patterns catch everything.

## DataEgressClass

| Class | Typical source | Default toward remote models |
|-------|----------------|------------------------------|
| `PublicNonSensitive` | Pure computation | Allowed (still bounded) |
| `UserAuthored` | User-provided prompts | Allowed |
| `LocalMetadata` | Paths, sizes, file counts | Allowed (metadata only) |
| `LocalContent` | File bytes / full file-scan content | **Denied** unless `allow_local_content_egress` |
| `TargetMetadata` | Host/port/header names | Allowed (metadata) |
| `TargetContent` | HTTP bodies / crawl content | **Denied** (metadata stub: status, content-type, length, hash) unless `allow_target_content_egress` |
| `PotentiallySecretBearing` | Writes / command output | **Denied** (stub) unless `allow_potentially_secret_bearing_egress` |
| `CredentialMaterial` | Keys, tokens | **Prohibited** |
| `ProcessMemory` | Memory scan output | **Denied** unless `allow_process_memory_egress` |
| `Prohibited` | Unknown tools / unsafe classes | **Denied** |

`requires_explicit_egress_approval` is true for local content, target content, potentially secret-bearing data, credentials, process memory, and prohibited classes.

## Defaults (fail closed for sensitive classes)

In a normal `AuthorisationContext`:

- `allow_local_content_egress = false`
- `allow_process_memory_egress = false`
- `allow_target_content_egress = false`
- `allow_potentially_secret_bearing_egress = false`
- `allow_evidence_egress = false`

When a class that `requires_explicit_egress_approval` would otherwise be returned to the model without its flag, Vest substitutes an `egress_denied` JSON stub (reason + class + limited metadata) instead of raw bytes. TargetContent stubs include status, content-type, length, and a body hash.

## Tool-result path

1. Classify from `ToolEffect` (`classify_tool_result`) and take the more restrictive of registry `egress_class` vs effect-derived class.
2. `filter_for_model` — deny prohibited/credentials; gate local content / process memory / target content / potentially secret-bearing; bound size (default ~8 KiB chars); redact known secrets and common patterns when a flag allows egress.
3. Only the filtered value may enter conversation history / provider messages.

## Validator / finding path

Remote validation uses an allowlisted `FindingEgressDto`:

- id, title, vulnerability class, severity, description, confidence, optional CWE
- raw evidence is **omitted** unless `allow_evidence_egress` is enabled, in which case a short redacted excerpt may be included

This prevents dumping full evidence JSON into remote prompts by default.

## Where data can leave the process

See [security-model.md](security-model.md) for the full list. Primary remote egress surfaces:

1. LLM provider HTTP APIs (`vest-providers`)
2. Scanner/tool HTTP to user-authorised targets (`ScopedHttpClient` for agent HTTP tools and `WebScanner` crawl/fetch)
3. External tools (e.g. nuclei subprocesses)
4. User-selected report output paths
5. Local SQLite under the workspace directory
6. Logs/tracing (metadata only — no raw secrets)

## Non-claims

- Redaction does not guarantee secret removal.
- Allowing a scan of a directory does not allow shipping file contents to a provider.
- Allowing process metadata does not allow memory egress.
- Vest is not a DLP product.
- `Finding.severity_score_estimate` may carry heuristic numbers from scanners; that is not a CVSS vector.

## Related

- [security-model.md](security-model.md)
- [agent-tool-policy.md](agent-tool-policy.md)
- Implementation: `vest-agent/src/egress.rs`, `vest-core/src/auth/mod.rs`
