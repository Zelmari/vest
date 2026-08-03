//! CLI-SOFT / CLI-DEAD: soft-ok paths and dead flags must fail closed.

mod common;

use common::*;
use std::fs;

#[test]
fn findings_show_missing_exits_invalid_input() {
    let root = temp_root("soft-findings-missing");
    let vest_home = root.join("home");
    fs::create_dir_all(&vest_home).unwrap();

    let output = vest_cmd(&vest_home)
        .arg("findings")
        .arg("show")
        .arg("00000000-0000-0000-0000-000000000000")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
    assert!(
        combined(&output).to_lowercase().contains("not found"),
        "{}",
        combined(&output)
    );
}

#[test]
fn config_set_unknown_key_exits_invalid_input() {
    let root = temp_root("soft-config-unknown");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("config")
        .arg("set")
        .arg("totally.unknown.key")
        .arg("1")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
    assert!(
        combined(&output).to_lowercase().contains("unknown"),
        "{}",
        combined(&output)
    );
}

#[test]
fn tools_install_unknown_exits_invalid_input() {
    let root = temp_root("soft-tools-unknown");
    let vest_home = root.join("home");
    fs::create_dir_all(&vest_home).unwrap();

    let output = vest_cmd(&vest_home)
        .arg("tools")
        .arg("install")
        .arg("not-a-real-tool-xyz")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
    assert!(
        combined(&output).to_lowercase().contains("unknown tool"),
        "{}",
        combined(&output)
    );
}

#[test]
fn resume_flag_errors_unimplemented() {
    let root = temp_root("dead-resume");
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
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--resume")
        .arg("some-scan-id")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        " --resume must not silently succeed\n{}",
        combined(&output)
    );
    let text = combined(&output).to_lowercase();
    assert!(
        text.contains("not implemented") || text.contains("unimplemented"),
        "expected unimplemented error, got:\n{}",
        combined(&output)
    );
}
