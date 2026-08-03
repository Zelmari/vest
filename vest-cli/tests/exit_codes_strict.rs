//! Strict exit-code matrix (K14 / CLI-EXIT-7 / CLI-PARTIAL).
//! Exact codes only — no soft `code == 3 || code == 5` asserts.

mod common;

use common::*;
use std::fs;
use std::process::Command;
use vest_core::VestError;

#[test]
fn typed_matrix_unit_codes() {
    assert_eq!(VestError::InvalidInput("x".into()).cli_exit_code(), 2);
    assert_eq!(VestError::Config("x".into()).cli_exit_code(), 3);
    assert_eq!(VestError::ApprovalDenied("x".into()).cli_exit_code(), 4);
    assert_eq!(VestError::Scan("x".into()).cli_exit_code(), 5);
    assert_eq!(VestError::Storage("x".into()).cli_exit_code(), 6);
    assert_eq!(VestError::Provider("x".into()).cli_exit_code(), 7);
    assert_eq!(VestError::Agent("x".into()).cli_exit_code(), 7);
    assert_eq!(VestError::FindingsGate("x".into()).cli_exit_code(), 8);
}

#[test]
fn success_exits_0() {
    let root = temp_root("strict-ok");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"ok-secret\"\n").unwrap();

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
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
}

#[test]
fn unsupported_shell_exits_2() {
    let output = Command::new(vest_bin())
        .arg("completions")
        .arg("not-a-shell")
        .output()
        .unwrap();
    assert_exit_code(&output, 2);
}

#[test]
fn invalid_target_type_exits_2() {
    let root = temp_root("strict-type");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("anything")
        .arg("--target-type")
        .arg("not-a-real-type")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
}

#[test]
fn malformed_config_exits_3() {
    let root = temp_root("strict-config");
    let vest_home = root.join("home");
    let bad = root.join("bad.toml");
    fs::create_dir_all(&vest_home).unwrap();
    fs::write(&bad, "not = {{{ toml\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&bad)
        .arg("scan")
        .arg("ignored")
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert_exit_code(&output, 3);
}

#[test]
fn unknown_scanner_exits_3() {
    let root = temp_root("strict-unknown-scanner");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"x\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("definitely-not-a-scanner")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert_exit_code(&output, 3);
}

#[test]
fn total_scanner_failure_exits_5() {
    let root = temp_root("strict-scanner-total");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("1")
        .arg("--target-type")
        .arg("process")
        .arg("--scanner")
        .arg("memory")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert_exit_code(&output, 5);
}

#[test]
fn partial_scanner_failure_preserves_findings_exits_5() {
    let root = temp_root("strict-scanner-partial");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("secrets.env");
    let out = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"partial-fail-secret\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files,memory")
        .arg("--provider")
        .arg("none")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();

    assert_exit_code(&output, 5);
    let combined = combined(&output);
    assert!(
        combined.to_lowercase().contains("degraded")
            || combined.to_lowercase().contains("failed")
            || combined.to_lowercase().contains("scanner"),
        "partial failure should be visible: {combined}"
    );
    assert!(
        out.exists(),
        "partial scanner failure must still write the report (findings preserved)"
    );
    let report = fs::read_to_string(&out).unwrap();
    assert!(
        report.contains("finding") || report.contains("password") || report.contains("secret"),
        "report should retain scanner findings: {report}"
    );
}

#[test]
fn provider_soft_failure_preserves_findings_exits_7() {
    let root = temp_root("strict-provider-soft");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("secrets.env");
    let out = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"provider-soft-secret\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .env_remove("OPENAI_API_KEY")
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("openai")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();

    assert_exit_code(&output, 7);
    let combined = combined(&output);
    assert!(
        combined.to_lowercase().contains("skipped")
            || combined.to_lowercase().contains("degraded")
            || combined.to_lowercase().contains("preserved"),
        "soft provider failure should be explicit: {combined}"
    );
    assert!(
        out.exists(),
        "provider soft failure must still write the report (findings preserved)"
    );
    let report = fs::read_to_string(&out).unwrap();
    assert!(
        report.contains("finding") || report.contains("password") || report.contains("secret"),
        "report should retain scanner findings: {report}"
    );
}
