//! Exit-code contract tests — behave like a human checking `echo $?`.

mod common;

use common::*;
use std::fs;
use std::process::Command;

#[test]
fn malformed_config_exits_config_code() {
    let root = temp_root("exit-config");
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

    assert_exit_code(&output, 3); // CONFIG
}

#[test]
fn unsupported_shell_exits_invalid_input() {
    let output = Command::new(vest_bin())
        .arg("completions")
        .arg("not-a-shell")
        .output()
        .unwrap();
    assert_exit_code(&output, 2); // INVALID_INPUT
}

#[test]
fn memory_unsupported_exits_scanner_code() {
    let root = temp_root("exit-scanner");
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

    assert_exit_code(&output, 5); // SCANNER
}

#[test]
fn unknown_scanner_exits_config_or_scanner() {
    let root = temp_root("exit-unknown-scanner");
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

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 3 || code == 5 || code == 1,
        "unknown scanner should fail closed, got {code}\n{}",
        combined(&output)
    );
}

#[test]
fn successful_file_scan_exits_zero() {
    let root = temp_root("exit-ok");
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
