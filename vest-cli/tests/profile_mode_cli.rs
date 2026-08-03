//! A3: unknown `--profile` / invalid `--mode` fail closed (exit 2).

mod common;

use common::*;
use std::fs;

#[test]
fn unknown_profile_exits_invalid_input() {
    let root = temp_root("unknown-profile");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
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
        .arg("--provider")
        .arg("none")
        .arg("--profile")
        .arg("does-not-exist")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
    let err = combined(&output);
    assert!(
        err.contains("Unknown profile") && err.contains("does-not-exist"),
        "stderr/stdout should name the unknown profile:\n{err}"
    );
}

#[test]
fn invalid_mode_exits_invalid_input() {
    let root = temp_root("invalid-mode");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
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
        .arg("--provider")
        .arg("none")
        .arg("--mode")
        .arg("not-a-real-mode")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
    let err = combined(&output);
    assert!(
        err.contains("Invalid scan mode") && err.contains("not-a-real-mode"),
        "stderr/stdout should name the invalid mode:\n{err}"
    );
}

#[test]
fn known_profile_and_valid_mode_still_dry_run() {
    let root = temp_root("valid-profile-mode");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    fs::write(
        &cfg,
        r#"
[general]
workspace_dir = "~/.vest"
log_level = "info"

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

[profiles.quick]
description = "Quick scan"
pattern = "pipeline"
scanners = ["files"]
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
        .arg("--provider")
        .arg("none")
        .arg("--profile")
        .arg("quick")
        .arg("--mode")
        .arg("pipeline")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = combined(&output);
    assert!(out.contains("DRY RUN"), "expected dry-run plan:\n{out}");
}
