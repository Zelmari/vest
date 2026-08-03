//! N4: `--offline` / `--no-ai` and safer default when no provider configured.

mod common;

use common::*;
use std::fs;

#[test]
fn offline_flag_forces_provider_none() {
    let root = temp_root("offline-flag");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    // Config that would otherwise select ollama
    fs::write(
        &cfg,
        r#"
[general]
workspace_dir = "~/.vest"
log_level = "info"

[providers.default]
provider = "ollama"
model = "llama3.2"

[agent]
default_pattern = "pipeline"
max_concurrent_agents = 2
max_llm_iterations = 10
token_budget_per_scan = 10000
thinking_enabled = false

[scanner.memory]
enabled = true
max_memory_per_scan_mb = 64

[scanner.binary]
enabled = true

[scanner.web]
enabled = true
crawl_depth = 2
crawl_max_urls = 20
max_response_bytes = 1048576
max_redirects = 3
connect_timeout_ms = 2000
request_timeout_seconds = 5
max_concurrent_requests = 4

[scanner.browser]
enabled = false

[scanner.network]
enabled = true

[scanner.files]
enabled = true
max_file_size_mb = 8
max_depth = 8
max_files = 200
max_total_bytes = 33554432
follow_symlinks = false

[safety]
write_approval = true
exploit_approval = true
network_write_approval = true
rate_limit_enabled = true
rate_limit_requests_per_second = 10
rate_limit_burst = 30
sandbox_enabled = false
sandbox_image = "vest-sandbox:latest"
max_scan_duration_seconds = 600
max_concurrent_exploits = 1
"#,
    )
    .unwrap();
    fs::write(&fixture, "password = \"test-only-secret\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--offline")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(out.contains("none"), "provider should be none:\n{out}");
    assert!(
        !out.contains("ollama"),
        "--offline must override config ollama:\n{out}"
    );
}

#[test]
fn no_ai_flag_forces_provider_none() {
    let root = temp_root("no-ai-flag");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "x\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--no-ai")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(out.contains("none"), "provider should be none:\n{out}");
}

#[test]
fn offline_conflicts_with_non_none_provider() {
    let root = temp_root("offline-conflict");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "x\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--offline")
        .arg("--provider")
        .arg("ollama")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 2); // INVALID_INPUT
    let err = stderr(&output);
    assert!(
        err.contains("conflicts") || err.contains("offline") || err.contains("Invalid"),
        "stderr:\n{err}"
    );
}

#[test]
fn no_provider_configured_defaults_to_none() {
    let root = temp_root("default-none");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    // write_minimal_config has no [providers] section
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"test-only-secret\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(
        out.contains("none"),
        "safer default when no provider configured should be none:\n{out}"
    );
    assert!(
        !out.contains("ollama"),
        "must not default to ollama without config:\n{out}"
    );
}
