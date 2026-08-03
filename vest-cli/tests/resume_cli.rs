//! Scanner-level `--resume` integration tests.

mod common;

use common::*;
use std::fs;
use std::path::Path;

fn seed_running_scan(db_path: &Path, fixture: &Path) -> String {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    vest_storage::schema::run_migrations(&conn).unwrap();

    let now = chrono::Utc::now();
    let target_id = "target-resume-1".to_string();
    let scan_id = "scan-resume-1".to_string();
    let target = vest_core::types::Target {
        id: target_id.clone(),
        name: fixture.file_name().unwrap().to_string_lossy().into_owned(),
        target_type: vest_core::types::TargetType::File,
        path: Some(fixture.to_string_lossy().into_owned()),
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    vest_storage::targets::insert_target(&conn, &target).unwrap();

    let scan = vest_core::types::ScanSession {
        id: scan_id.clone(),
        target_id,
        mode: vest_core::types::ScanMode::Pipeline,
        config: serde_json::json!({
            "provider": "none",
            "model": "none",
            "scanners": ["files", "network"],
        }),
        status: vest_core::types::ScanStatus::Running,
        agent_model: None,
        started_at: Some(now),
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    vest_storage::scans::insert_scan(&conn, &scan).unwrap();

    // files already done — resume should only run network (and finalize).
    vest_storage::checkpoints::upsert_scanner_checkpoint(
        &conn,
        &scan_id,
        "files",
        "completed",
        None,
    )
    .unwrap();
    scan_id
}

#[test]
fn resume_continues_remaining_scanners() {
    let root = temp_root("resume-continue");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("secret.env");
    let db_path = vest_home.join("vest.db");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"hunter2\"\nAPI_KEY=abc\n").unwrap();

    let scan_id = seed_running_scan(&db_path, &fixture);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("--provider")
        .arg("none")
        .arg("--resume")
        .arg(&scan_id)
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output).to_lowercase();
    assert!(
        text.contains("skipped (checkpoint)") || text.contains("resuming"),
        "expected resume UI, got:\n{}",
        combined(&output)
    );

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let status: String = conn
        .query_row(
            "SELECT status FROM scans WHERE id = ?1",
            rusqlite::params![scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "completed");

    let completed =
        vest_storage::checkpoints::list_completed_scanner_names(&conn, &scan_id).unwrap();
    assert!(completed.iter().any(|s| s == "files"));
    assert!(completed.iter().any(|s| s == "network"));
}

#[test]
fn resume_rejects_completed_scan() {
    let root = temp_root("resume-completed");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"x\"\n").unwrap();

    let scan = vest_cmd(&vest_home)
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
        .arg("-f")
        .arg("json")
        .output()
        .unwrap();
    assert_success(&scan);

    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let scan_id = report["scan_id"]
        .as_str()
        .or_else(|| report["id"].as_str())
        .expect("scan id in json report")
        .to_string();

    let resume = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("--resume")
        .arg(&scan_id)
        .output()
        .unwrap();
    assert!(!resume.status.success());
    let text = combined(&resume).to_lowercase();
    assert!(
        text.contains("cannot be resumed") || text.contains("completed"),
        "{}",
        combined(&resume)
    );
}

#[test]
fn resume_missing_scan_exits_invalid_input() {
    let root = temp_root("resume-missing");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("--resume")
        .arg("00000000-0000-0000-0000-000000000000")
        .output()
        .unwrap();

    assert_exit_code(&output, 2);
}
