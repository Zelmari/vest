//! Config subcommand workflows — validate/show/path as a human would use them.

mod common;

use common::*;
use std::fs;

#[test]
fn validate_accepts_minimal_valid_config() {
    let root = temp_root("cfg-ok");
    let vest_home = root.join("home");
    let cfg = root.join("good.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("validate")
        .output()
        .unwrap();

    assert_success(&output);
    assert!(
        stdout(&output).contains("Configuration is valid"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn validate_rejects_malformed_config_with_nonzero_exit() {
    let root = temp_root("cfg-bad");
    let vest_home = root.join("home");
    let cfg = root.join("bad.toml");
    fs::create_dir_all(&vest_home).unwrap();
    fs::write(&cfg, "[[[broken").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("validate")
        .output()
        .unwrap();

    assert_exit_code(&output, 3);
    assert!(
        combined(&output).to_lowercase().contains("config"),
        "{}",
        combined(&output)
    );
}

#[test]
fn validate_rejects_invalid_safety_bounds() {
    let root = temp_root("cfg-safety");
    let vest_home = root.join("home");
    let cfg = root.join("safety.toml");
    fs::create_dir_all(&vest_home).unwrap();
    fs::write(
        &cfg,
        r#"
[general]
[agent]
[scanner.files]
enabled = true
max_file_size_mb = 1
max_depth = 1
max_files = 1
max_total_bytes = 1024
[scanner.web]
enabled = true
[scanner.memory]
enabled = true
max_memory_per_scan_mb = 64
[scanner.binary]
enabled = false
[scanner.browser]
enabled = false
[scanner.network]
enabled = false
[safety]
rate_limit_enabled = true
rate_limit_requests_per_second = 0
rate_limit_burst = 30
"#,
    )
    .unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("validate")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "invalid safety must fail closed\n{}",
        combined(&output)
    );
}

#[test]
fn show_fails_closed_on_present_malformed_file() {
    let root = temp_root("cfg-show-bad");
    let vest_home = root.join("home");
    let cfg = root.join("bad.toml");
    fs::create_dir_all(&vest_home).unwrap();
    fs::write(&cfg, "not toml {{{").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("show")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "present malformed config must not silently show defaults\n{}",
        combined(&output)
    );
}

#[test]
fn path_reports_explicit_config_flag() {
    let root = temp_root("cfg-path");
    let vest_home = root.join("home");
    let cfg = root.join("named.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("path")
        .output()
        .unwrap();

    assert_success(&output);
    assert!(
        stdout(&output).contains(cfg.to_string_lossy().as_ref()),
        "{}",
        stdout(&output)
    );
}

#[test]
fn set_updates_value_via_c_flag() {
    let root = temp_root("cfg-set");
    let vest_home = root.join("home");
    let cfg = root.join("set.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("set")
        .arg("agent.default_pattern")
        .arg("swarm")
        .output()
        .unwrap();

    assert_success(&output);
    let body = fs::read_to_string(&cfg).unwrap();
    assert!(
        body.contains("swarm"),
        "config file should contain updated value:\n{body}"
    );
}
