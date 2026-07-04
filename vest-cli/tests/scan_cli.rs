use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn vest_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vest")
}

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vest-cli-{name}-{}-{nanos}", std::process::id()))
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn command_stdout(output: std::process::Output) -> String {
    assert_success(&output);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn scan_file_with_builtin_scanner_reports_and_stores_findings() {
    let root = temp_root("scan-file");
    let vest_home = root.join("home");
    let fixture = root.join("fixture.txt");
    let report = root.join("report.json");

    fs::create_dir_all(&root).unwrap();
    fs::write(
        &fixture,
        "service_password = \"correct-horse-battery-staple\"\n",
    )
    .unwrap();

    let output = Command::new(vest_bin())
        .env("VEST_HOME", &vest_home)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"total\": 1"), "stdout was:\n{stdout}");
    assert!(
        stdout.contains("Hardcoded password"),
        "stdout was:\n{stdout}"
    );

    let report_json = read_json(&report);
    assert_eq!(report_json["summary"]["total"], 1);
    assert_eq!(
        report_json["target"]["name"].as_str(),
        Some(fixture.to_string_lossy().as_ref())
    );
    assert_eq!(report_json["target"]["type"], "file");

    let db_path = vest_home.join("vest.db");
    assert!(db_path.exists());
    let pool = vest_storage::ConnectionPool::new(db_path.to_str().unwrap()).unwrap();
    let scans = vest_storage::scans::list_scans(pool.conn()).unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].total_findings, 1);
    assert_eq!(scans[0].metadata["target"]["type"], "file");

    let findings =
        vest_storage::findings::list_findings_by_scan(pool.conn(), &scans[0].id).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Hardcoded password found in file");

    let scans_list = command_stdout(
        Command::new(vest_bin())
            .env("VEST_HOME", &vest_home)
            .arg("scans")
            .arg("list")
            .output()
            .unwrap(),
    );
    assert!(
        scans_list.contains(&scans[0].id),
        "stdout was:\n{scans_list}"
    );
    assert!(scans_list.contains("Total: 1"), "stdout was:\n{scans_list}");

    let scans_show = command_stdout(
        Command::new(vest_bin())
            .env("VEST_HOME", &vest_home)
            .arg("scans")
            .arg("show")
            .arg(&scans[0].id)
            .output()
            .unwrap(),
    );
    assert!(scans_show.contains("Findings: 1 total"));
    assert!(scans_show.contains("Hardcoded password"));

    let findings_list = command_stdout(
        Command::new(vest_bin())
            .env("VEST_HOME", &vest_home)
            .arg("findings")
            .arg("list")
            .arg("--scan-id")
            .arg(&scans[0].id)
            .output()
            .unwrap(),
    );
    assert!(findings_list.contains("Hardcoded password"));

    let stored_report = root.join("stored-report.json");
    let report_stdout = command_stdout(
        Command::new(vest_bin())
            .env("VEST_HOME", &vest_home)
            .arg("report")
            .arg("generate")
            .arg(&scans[0].id)
            .arg("--format")
            .arg("json")
            .arg("--output")
            .arg(&stored_report)
            .output()
            .unwrap(),
    );
    assert!(report_stdout.contains("Report saved to"));
    let stored_report_json = read_json(&stored_report);
    assert_eq!(stored_report_json["summary"]["total"], 1);
}

#[test]
fn dry_run_does_not_create_database() {
    let root = temp_root("dry-run");
    let vest_home = root.join("home");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&root).unwrap();
    fs::write(&fixture, "password = \"test-only-secret\"\n").unwrap();

    let output = Command::new(vest_bin())
        .env("VEST_HOME", &vest_home)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_success(&output);
    assert!(!vest_home.join("vest.db").exists());
}
