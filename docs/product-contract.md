# Vest Product Contract

**Status:** Experimental. This contract describes intended behaviour and marks
what is actually true on current `main`. Features not listed here are non-goals
or unsupported.

## Who it is for

Technically competent users scanning systems they **own** or are **explicitly
authorised** to assess. Vest is local-first: scanners should be useful without
an AI provider.

## Supported scenarios

### A — Local offline scan — **works**

- Scan a file or directory with `--provider none`, `--offline`, `--no-ai`, or no provider configured (defaults to `none`).
- No LLM network for the scan itself.
- Bounded traversal (depth, files, bytes, no symlink follow by default).
- Terminal and/or JSON report.
- Unreadable files skip with warnings; do not erase other findings.

### B — Passive authorised web scan — **works** (N5 cleared)

**Intended:**

- Explicit `http`/`https` URL.
- Origin-scoped crawl; redirects re-authorised; no auto off-origin follow.
- Active probes **off** unless explicitly enabled and authorised.
- Useful without a model.

**Actual today:** CLI web scan is passive-by-default. Active probes require
`scanner.web.allow_active_probes = true` and/or `--allow-active-probes`.
Remaining related work: `WebScanner` not fully on `ScopedHttpClient` (**WEB-1**).

### C — Active authorised checks — **partial**

**Intended:**

- Separately classified from passive crawl.
- Require interactive approval or exact pre-authorisation.
- Non-destructive, budgeted, same-origin only.
- Audit what was attempted.

**Actual today:** active probes are a distinct `ToolEffect`. Operator can
pre-grant via `--approve-exploits` / `--approve-effect active_network_probe`, or
allow once on a TTY. Non-TTY without grants → deny. Builtin scanner probes
opted in via config/flag still run without a separate approval step.

### D — AI-assisted interpretation — **mostly works**

- Explicit provider + model.
- Structured allowlisted payloads only (validator path).
- Local content / process memory / raw evidence not sent by default.
- Provider failure preserves local scanner findings.

### E — Agent tool use — **policy works; UX incomplete**

- Model proposals carry **no** authority.
- Every call: normalise → policy → mint opaque `ApprovedToolCall` → execute → egress filter.
- Approvals bind exact session + tool + effect + canonical args (SHA-256 digest).
- Tool-loop and size limits prevent runaway use.
- Agent `http_get` / `http_post` use `ScopedHttpClient`; `web_scan` uses `WebScanner::inspect_url` with the same probe gating as CLI (**K3**/**K3b** cleared).
- Exact CLI effect+session pre-grants and TTY one-shot Allow (**K2** cleared; not a full approval UX).
- **Gap:** `WebScanner` client stack not fully unified on `ScopedHttpClient` (**WEB-1**).

### F — CI / non-interactive — **mostly works**

- No prompts when non-TTY / `--no-approval`.
- Sensitive / approval-required ops denied unless already authorised by effect/session grants.
- Exit codes: typed `VestError::cli_exit_code()` on scan/completions; legacy string fallback is last-resort for remaining untyped subcommands.
- JSON on stdout is the intended machine path; keep diagnostics on stderr.

### G — Degraded operation — **mostly works** (scan path)

- Provider / agent soft failure: scanner findings preserved, report/DB written, process exits **7**.
- Partial scanner failure: successful scanner findings preserved, report/DB written, process exits **5**.
- Total scanner failure remains a hard non-zero error (no false success).
- Not every non-scan subcommand path is proven to the same matrix.

### H — Large targets — **partial**

- Enforced budgets on file/web scanners; truncation / budget-exhaustion status.
- “No unbounded memory growth by design” is an intent, not a formal proof.

## Default safety posture

| Question | Default / reality |
|----------|-------------------|
| AI enabled? | Only if provider configured / selected |
| Active web probes (library)? | Off unless enabled |
| Active web probes (CLI `scan --scanner web`)? | Off unless config / `--allow-active-probes` |
| Symlink follow? | Off |
| Local content → model? | Denied |
| Process memory → model? | Denied |
| Missing interactive approval? | **Deny** unless CLI pre-grant or TTY one-shot Allow |
| `--no-approval` meaning? | **Do not prompt; deny approval-required** (not “allow all”) |
| Malformed present config? | Fail closed |

## Explicit non-goals

- Automatic exploitation or privilege escalation.
- Arbitrary shell execution for the model.
- Credential theft / stealth / unauthorised access features.
- Full OS sandbox for agent tools.
- Production process-memory forensics (unless genuinely implemented).
- Comprehensive vulnerability certification.
- Autonomous scanning of arbitrary internet targets.
- Claiming “production-grade” or “fully secure.”

## Installation (contract)

```bash
git clone https://github.com/Zelmari/vest
cd vest
cargo install --path vest-cli
vest --version
vest scan ./examples/demo-target/vulnerable-files --target-type file --scanner files --provider none
```

## Related docs

- [security-model.md](security-model.md)
- [data-flow.md](data-flow.md)
- [agent-tool-policy.md](agent-tool-policy.md)
- [model-data-boundary.md](model-data-boundary.md)
- [product-hardening-ledger.md](product-hardening-ledger.md)
- [clearance-plan.md](clearance-plan.md)
