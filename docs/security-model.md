# Vest Security Model

**Status:** Experimental. This document describes intended and implemented trust boundaries after the verified security-hardening pass. It does not claim production-grade security or a complete sandbox.

## Central rule

**Model output is untrusted data. It does not grant authority.**

Authority comes only from explicit user intent for a command/session (target, config, CLI flags, interactive approval). An LLM may propose tool calls and arguments; those proposals must be normalised and evaluated by the policy engine before any side effect or data egress.

## Trust principals

| Principal | Trust | Notes |
|-----------|-------|-------|
| Trusted local user | Trusted for intent | Owns the terminal/session; selects target and config |
| Untrusted model output | Untrusted | Tool names, arguments, plans, severity judgements |
| Untrusted tool arguments | Untrusted | Paths, URLs, PIDs, HTTP methods/bodies |
| Untrusted scanned files | Untrusted | Content may contain secrets or malicious payloads |
| Untrusted URLs / HTTP responses | Untrusted | Headers, bodies, redirects, links, forms |
| Untrusted configuration files | Untrusted until validated | Malformed/present safety config must fail closed |
| Remote providers | Untrusted remote party | Receive only allowlisted DTOs after egress checks |

## Boundaries

### Filesystem boundary

Agent tools and scanners that read local content operate only within an `ApprovedFilesystemScope` derived from the user-selected scan target (and any explicitly authorised extra roots). Paths are resolved with canonical component comparison. Symlinks that escape the root are rejected by default (do-not-follow policy).

### Network boundary

Network tools and crawlers operate only within an `ApprovedNetworkScope` (scheme, host, effective port / origin, optional IP policy). Comparisons use parsed `url::Url` origins, not substring matching. Redirects and discovered links are re-authorised before request.

### Process-memory boundary

Process-memory access is a distinct effect from process metadata. Raw memory is never sent to a remote model by default. If genuine OS memory acquisition is unavailable, the feature must report simulation/unsupported status rather than fabricate live PID results as real.

### Secret boundary

API keys and credential material must not appear in stdout, stderr, Debug output, logs, reports, or provider payloads. Prefer environment variables or interactive prompts; command-line key arguments must not echo the secret.

### Model-egress boundary

Authorising an action is not authorising data to leave the machine. Tool results and findings are classified (`DataEgressClass`) and filtered/redacted/bounded before insertion into provider request DTOs.

### Persistence boundary

SQLite and report writers receive local findings. Persistence failures must surface as errors (non-zero exit when fatal). Reports must not embed raw secrets by default.

## Data flow

```
User command
  -> configuration (validated; fail closed if malformed safety section present)
  -> scan target (defines authorised filesystem/network scope)
  -> scanner (bounded traversal / network policy)
  -> finding (local)
  -> agent / provider (egress allowlist DTOs only)
  -> tool call (NormalisedToolCall)
  -> policy engine (effect + scope + args + egress)
  -> tool result (bounded, classified)
  -> provider (redacted allowlist payload)
  -> report / storage (local)
```

## Where data can leave the process

1. **Remote LLM providers** (`vest-providers/*`): chat, stream, embed requests built from agent context / validator prompts.
2. **HTTP clients in scanners and tools** (`vest-scanner` web/network/browser; CLI `http_get`/`http_post`/`web_scan`): outbound requests to user-authorised targets (and must not follow unauthorised redirects).
3. **External tools** (`vest-tools` nuclei): subprocess invocation against authorised targets.
4. **Reports / files written by the CLI**: user-selected output paths.
5. **SQLite storage** under the workspace directory: local persistence only.
6. **Logs / tracing**: must carry metadata only, never raw secrets or full provider payloads containing evidence.

## Effect model (summary)

Tools are classified by explicit `ToolEffect` (not name substrings). Unknown tools and unknown effects are denied. Stronger effects are not implied by weaker approvals (e.g. GET ≠ POST; file A ≠ file B; metadata ≠ memory).

## Non-claims

Vest must **not** be described as:

- Production-grade or “fully secure”
- OS-level sandboxed (Docker sandbox helpers are optional/experimental)
- Guaranteed secret detection via regex
- Complete SSRF / DNS-rebinding prevention without connection-time IP binding
- Real process-memory forensics unless a platform-specific real reader is enabled and tested
