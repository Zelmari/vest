# Security Policy

## Reporting a vulnerability

If you believe you have found a security issue in Vest:

1. **Prefer private disclosure.** Open a GitHub security advisory on [Zelmari/vest](https://github.com/Zelmari/vest) if available, or contact the repository owner via GitHub.
2. Include a clear description, reproduction steps, affected commit/branch if known, and impact assessment.
3. Do **not** open a public issue for vulnerabilities that could enable data exfiltration, arbitrary file access, or secret leakage until a fix or coordinated disclosure is agreed.

We will acknowledge reports as capacity allows. This is an experimental project; response SLAs are best-effort.

## Trust model

Vest treats **model output as untrusted data**. Authority comes from explicit user intent (CLI flags, config, interactive approval), not from LLM proposals.

Read the full trust and boundary model:

- **[docs/security-model.md](docs/security-model.md)** — principals, boundaries, non-claims
- **[docs/agent-tool-policy.md](docs/agent-tool-policy.md)** — tool effects and approval
- **[docs/model-data-boundary.md](docs/model-data-boundary.md)** — what may leave the process toward a model

## Non-claims

Vest is **experimental**. Do not treat it as:

- Production-grade or “guaranteed secure”
- An OS-level sandbox for agent tools (optional Docker helpers are convenience only)
- A complete secret-detection or SSRF-prevention product
- Real process-memory forensics unless a platform-specific real reader is implemented, enabled, and tested
