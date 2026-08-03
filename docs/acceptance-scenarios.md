# Acceptance Scenarios

Automate as many of these as possible under `vest-cli/tests/` and crate tests.
Network: loopback only. Filesystem: temp dirs. Providers: fakes / `none`.

| # | Scenario | Automation status |
|---|----------|-------------------|
| 1 | Local offline scan (`--provider none`) | `human_workflows` / `scan_cli` |
| 2 | Passive local web scan | covered — CLI web scan passive by default; active probes opt-in (`--allow-active-probes` / config) (**N5**) |
| 3 | Interactive file-content approval | **partial** — exact `--approve-effect local_file_content_read` pre-grant works; TTY one-shot prompt when interactive+TTY (not full multi-step UI) |
| 4 | Interactive active web deny/allow | **partial** — `--approve-exploits` / `--approve-effect active_network_probe` pre-grant; TTY one-shot; non-TTY deny |
| 5 | Non-interactive CI JSON, deny sensitive | covered (`--no-approval` fail-closed; `no_approval_cli`) |
| 6 | Provider unavailable preserves findings | library validator tests |
| 7 | Malformed provider response | validator unit tests |
| 8 | Malformed project config | `config_cli` / `exit_codes` |
| 9 | Budget exhaustion | file depth/size tests |
| 10 | Unicode paths/bodies | `truncate_chars` + FS unicode |
| 11 | Concurrent sessions | `ExecutionSession` unit test |
| 12 | Storage failure | covered — `acceptance_storage_cancel.rs` (unwritable `VEST_HOME` / bad DB path → exit 6) |
| 13 | Cancellation | covered (library) — `vest-providers` parallel fallback drop cancels in-flight provider |
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

Scenarios 3–4: exact pre-auth grant path is tested; TTY one-shot exists but is not a full multi-step approval UI — keep status **partial**.
