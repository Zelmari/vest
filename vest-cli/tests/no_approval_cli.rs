//! K1/K2 CLI approval flags: `--no-approval` fail-closed; approve flags conflict / parse.

mod common;

use common::*;
use std::fs;

#[test]
fn no_approval_scan_succeeds_fail_closed() {
    let root = temp_root("no-approval");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("repo");
    fs::create_dir_all(&vest_home).unwrap();
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("note.txt"), "hello\n").unwrap();
    write_minimal_config(&cfg);

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
        .arg("--no-approval")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();

    assert_success(&output);
}

#[test]
fn no_approval_conflicts_with_approve_writes() {
    let root = temp_root("no-approval-conflict");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&root)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--no-approval")
        .arg("--approve-writes")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "clap should reject --no-approval with --approve-writes"
    );
    let err = combined(&output);
    assert!(
        err.contains("cannot be used with") || err.contains("conflict"),
        "unexpected stderr/stdout: {err}"
    );
}

#[test]
fn approve_effect_unknown_exits_config() {
    let root = temp_root("approve-effect-bad");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("repo");
    fs::create_dir_all(&vest_home).unwrap();
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("a.txt"), "a\n").unwrap();
    write_minimal_config(&cfg);

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
        .arg("--approve-effect")
        .arg("not_a_real_effect")
        .output()
        .unwrap();

    assert_exit_code(&output, 3); // CONFIG
    let err = combined(&output);
    assert!(
        err.contains("unknown tool effect") || err.contains("not_a_real_effect"),
        "unexpected error text: {err}"
    );
}

#[test]
fn approve_writes_accepted_non_interactive() {
    let root = temp_root("approve-writes");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("repo");
    fs::create_dir_all(&vest_home).unwrap();
    fs::create_dir_all(&fixture).unwrap();
    fs::write(fixture.join("note.txt"), "hello\n").unwrap();
    write_minimal_config(&cfg);

    // Non-TTY CI: --approve-writes must mint grants without prompting.
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
        .arg("--approve-writes")
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();

    assert_success(&output);
}
