//! C1: CI gates — `--fail-on-severity` and `--fail-on-new`.

mod common;

use common::*;
use std::fs;

#[test]
fn fail_on_severity_high_exits_eight_on_critical_finding() {
    let root = temp_root("fail-sev-hit");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("secrets.txt");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"correct-horse-battery-staple\"\n").unwrap();

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
        .arg("--fail-on-severity")
        .arg("high")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();

    assert_exit_code(&output, 8);
}

#[test]
fn fail_on_severity_high_exits_zero_without_high_findings() {
    let root = temp_root("fail-sev-clean");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("clean.txt");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "hello world, nothing sensitive here\n").unwrap();

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
        .arg("--fail-on-severity")
        .arg("high")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
}

#[test]
fn fail_on_severity_invalid_exits_invalid_input() {
    let root = temp_root("fail-sev-bad");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
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
        .arg("--provider")
        .arg("none")
        .arg("--fail-on-severity")
        .arg("extreme")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
}

#[test]
fn fail_on_new_baseline_then_detects_new_title() {
    let root = temp_root("fail-new");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("app.txt");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    fs::write(&fixture, "hello baseline\n").unwrap();
    let baseline = vest_cmd(&vest_home)
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
        .arg("--fail-on-new")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();
    assert_exit_code(&baseline, 0);

    fs::write(&fixture, "password = \"correct-horse-battery-staple\"\n").unwrap();
    let with_new = vest_cmd(&vest_home)
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
        .arg("--fail-on-new")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();
    assert_exit_code(&with_new, 8);

    let stable = vest_cmd(&vest_home)
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
        .arg("--fail-on-new")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();
    assert_exit_code(&stable, 0);
}
