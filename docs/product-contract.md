# Vest Product Contract

**Status:** Experimental. This contract describes intended behaviour after the
product-hardening pass. Features not listed here are non-goals or unsupported.

## Who it is for

Technically competent users scanning systems they **own** or are **explicitly
authorised** to assess. Vest is local-first: scanners should be useful without
an AI provider.

## Supported scenarios

### A — Local offline scan

- Scan a file or directory with `--provider none` (or no provider).
- No network access for the scan itself.
- Bounded traversal (depth, files, bytes, no symlink follow by default).
- Terminal and/or JSON report.
- Unreadable files skip with warnings; do not erase other findings.

### B — Passive authorised web scan

- Explicit `http`/`https` URL.
- Origin-scoped crawl; redirects re-authorised; no auto off-origin follow.
- Active probes **off** unless explicitly enabled and authorised.
- Useful without a model.

### C — Active authorised checks

- Separately classified from passive crawl.
- Require interactive approval or exact pre-authorisation.
- Non-destructive, budgeted, same-origin only.
- Audit what was attempted.

### D — AI-assisted interpretation

- Explicit provider + model.
- Structured allowlisted payloads only.
- Local content / process memory / raw target bodies not sent by default.
- Provider failure preserves local scanner findings.

### E — Agent tool use

- Model proposals carry **no** authority.
- Every call: normalise → policy → (approve) → execute → egress filter.
- Approvals bind exact session + tool + effect + canonical args.
- Tool-loop and size limits prevent runaway use.

### F — CI / non-interactive

- No prompts.
- Sensitive ops denied unless exact pre-auth.
- Stable exit codes; JSON on stdout only; diagnostics on stderr.

### G — Degraded operation

- Provider / storage / single-file failures reported explicitly.
- Partial results preserved where possible.
- Exit status reflects severity of failure (not “success” when nothing ran).

### H — Large targets

- Enforced budgets; truncation / budget-exhaustion status.
- No unbounded memory growth by design.

## Default safety posture

| Question | Default |
|----------|---------|
| AI enabled? | Only if provider configured / selected |
| Active web probes? | Off (CLI web scan currently enables probes — hardening must align docs or gate) |
| Symlink follow? | Off |
| Local content → model? | Denied |
| Process memory → model? | Denied |
| Missing approval (non-interactive)? | Deny |
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
