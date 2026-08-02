//! Shared helpers for vest CLI integration tests (human-workflow style).

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn vest_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vest")
}

pub fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vest-cli-{name}-{}-{nanos}", std::process::id()))
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn assert_exit_code(output: &Output, expected: i32) {
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        expected,
        "expected exit {expected}, got {code}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn combined(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

pub fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// Minimal valid config for isolated CLI runs (no network providers).
pub fn write_minimal_config(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(
        path,
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
"#,
    )
    .unwrap();
}

pub fn vest_cmd(vest_home: &Path) -> Command {
    let mut cmd = Command::new(vest_bin());
    cmd.env("VEST_HOME", vest_home)
        .env_remove("VEST_DB_PATH")
        .env("RUST_LOG", "error");
    cmd
}
