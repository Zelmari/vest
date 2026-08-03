//! Unicode-safe CLI paths: no byte-slice panics on multi-byte UTF-8 targets (K14 / K13).

mod common;

use common::*;
use std::fs;
use std::process::Command;

/// Multi-byte target: 15 CJK chars = 45 bytes — old `&s[..min(20)]` slicing panicked.
const CJK_TARGET: &str = "安安安安安安安安安安安安安安安";

#[test]
fn dry_run_with_unicode_target_does_not_panic() {
    let root = temp_root("unicode-dryrun");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let target = root.join(CJK_TARGET);
    fs::create_dir_all(&vest_home).unwrap();
    fs::create_dir_all(&target).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&target)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let text = combined(&output);
    assert!(
        text.contains("Would scan"),
        "dry-run banner expected: {text}"
    );
}

#[test]
fn targets_list_with_unicode_name_does_not_panic() {
    let root = temp_root("unicode-targets");
    let vest_home = root.join("home");
    fs::create_dir_all(&vest_home).unwrap();

    let add = vest_cmd(&vest_home)
        .arg("targets")
        .arg("add")
        .arg(CJK_TARGET)
        .output()
        .unwrap();
    assert_success(&add);

    let list = Command::new(vest_bin())
        .env("VEST_HOME", &vest_home)
        .env_remove("VEST_DB_PATH")
        .env("RUST_LOG", "error")
        .arg("targets")
        .arg("list")
        .output()
        .unwrap();

    assert_exit_code(&list, 0);
}
