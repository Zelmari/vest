# Acceptance Scenarios

Automate as many of these as possible under `vest-cli/tests/` and crate tests.
Network: loopback only. Filesystem: temp dirs. Providers: fakes / `none`.

| # | Scenario | Automation status |
|---|----------|-------------------|
| 1 | Local offline scan (`--provider none`) | `human_workflows` / `scan_cli` |
| 2 | Passive local web scan | `scan_web_cli` |
| 3 | Interactive file-content approval | pending (approval UI) |
| 4 | Interactive active web deny/allow | pending |
| 5 | Non-interactive CI JSON, deny sensitive | partial (`--no-approval` fail-closed) |
| 6 | Provider unavailable preserves findings | library validator tests |
| 7 | Malformed provider response | validator unit tests |
| 8 | Malformed project config | `config_cli` / `exit_codes` |
| 9 | Budget exhaustion | file depth/size tests |
| 10 | Unicode paths/bodies | `truncate_chars` + FS unicode |
| 11 | Concurrent sessions | `ExecutionSession` unit test |
| 12 | Storage failure | pending |
| 13 | Cancellation | pending |
| 14 | Secret sentinels | egress + set-key tests |
| 15 | Install smoke (`cargo install --path vest-cli`) | manual / CI |

Exact commands for scenario 1:

```bash
vest scan "$TMP/repo" --target-type file --scanner files --provider none -f json -o "$TMP/out.json"
# expect exit 0, valid JSON, no network
```

Scenario 5:

```bash
vest scan ... --no-approval --provider none -f json
# stdout: JSON only; approval-required agent tools denied if agent path used
```
