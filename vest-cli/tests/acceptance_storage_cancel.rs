//! ACCEPT-12: storage failure → non-zero exit (prefer 6).
//! ACCEPT-13 CLI cancellation is hard; library-level coverage lives in vest-providers.

mod common;

use common::*;
use std::fs;

#[test]
fn storage_failure_unwritable_vest_home_exits_persistence() {
    let root = temp_root("accept12-home");
    // VEST_HOME as a regular file: create_dir_all for the DB parent must fail closed.
    let vest_home = root.join("home-as-file");
    fs::create_dir_all(&root).unwrap();
    fs::write(&vest_home, "not-a-directory").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("findings")
        .arg("list")
        .output()
        .unwrap();

    assert_exit_code(&output, 6);
    let text = combined(&output).to_lowercase();
    assert!(
        text.contains("storage") || text.contains("database") || text.contains("cannot create"),
        "expected storage failure message, got:\n{}",
        combined(&output)
    );
}

#[test]
fn storage_failure_db_path_is_directory_exits_persistence() {
    let root = temp_root("accept12-dbdir");
    let vest_home = root.join("home");
    let bad_db = root.join("db-is-dir");
    fs::create_dir_all(&vest_home).unwrap();
    fs::create_dir_all(&bad_db).unwrap();

    let output = vest_cmd(&vest_home)
        .env("VEST_DB_PATH", &bad_db)
        .arg("findings")
        .arg("stats")
        .output()
        .unwrap();

    assert_exit_code(&output, 6);
}

#[test]
fn storage_failure_on_scan_persist_exits_persistence() {
    let root = temp_root("accept12-scan");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
    let bad_db = root.join("not-a-sqlite-file");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"accept12\"\n").unwrap();
    // Directory where a DB file is expected → sqlite open fails as Storage.
    fs::create_dir_all(&bad_db).unwrap();

    let output = vest_cmd(&vest_home)
        .env("VEST_DB_PATH", &bad_db)
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

    assert_exit_code(&output, 6);
}
