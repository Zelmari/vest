# Security Policy

## Reporting a vulnerability

If you believe you have found a security issue in Vest:

1. **Prefer private disclosure.** Open a GitHub security advisory on [Zelmari/vest](https://github.com/Zelmari/vest) if available, or contact the repository owner via GitHub.
2. Include a clear description, reproduction steps, affected commit/branch if known, and impact assessment.
3. Do **not** open a public issue for vulnerabilities that could enable data exfiltration, arbitrary file access, or secret leakage until a fix or coordinated disclosure is agreed.

We will acknowledge reports as capacity allows. This is an experimental project; response SLAs are best-effort.

## Trust model

Vest treats **model output as untrusted data**. Authority comes from explicit user intent (CLI flags, config, session scopes), not from LLM proposals.

Approval-required tools need an exact CLI pre-grant (`--approve-writes` / `--approve-exploits` / `--approve-effect`) or a TTY one-shot Allow when interactive. Non-TTY without grants and `--no-approval` deny approval-required ops (fail closed; not a permissive bypass).

Read the full trust and boundary model:

- **[docs/security-model.md](docs/security-model.md)** — principals, boundaries, non-claims
- **[docs/agent-tool-policy.md](docs/agent-tool-policy.md)** — tool effects and approval (as implemented)
- **[docs/model-data-boundary.md](docs/model-data-boundary.md)** — what may leave the process toward a model
- **[docs/product-hardening-ledger.md](docs/product-hardening-ledger.md)** — known open gaps

## Non-claims

Vest is **experimental**. Do not treat it as:

- Production-grade or “guaranteed secure”
- An OS-level sandbox for agent tools (optional Docker helpers are convenience only)
- A complete secret-detection or SSRF-prevention product
- Real process-memory forensics unless a platform-specific real reader is implemented, enabled, and tested
- A full multi-step interactive approval product (K2 provides exact CLI pre-grants + TTY one-shot only)

CLI web scanning **is** passive by default; active probes require allow (config / `--allow-active-probes`) **and** `--confirm-active-probes` or `--approve-exploits`. Remaining gaps: [docs/clearance-plan.md](docs/clearance-plan.md).
