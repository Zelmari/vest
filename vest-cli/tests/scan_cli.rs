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
fn json_scan_stdout_is_machine_clean() {
    let root = temp_root("json-stdout-clean");
    let vest_home = root.join("home");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&root).unwrap();
    fs::write(
        &fixture,
        "service_password = \"correct-horse-battery-staple\"\n",
    )
    .unwrap();

    let output = Command::new(vest_bin())
        .env("VEST_HOME", &vest_home)
        .env_remove("VEST_DB_PATH")
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

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Box-drawing / banner chatter must not appear on stdout.
    for ch in [
        '\u{250c}', '\u{2510}', '\u{2514}', '\u{2518}', '\u{2502}', '\u{2500}', '\u{251c}',
        '\u{2524}',
    ] {
        assert!(
            !stdout.contains(ch),
            "stdout must not contain box-drawing {ch:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    assert!(
        !stdout.contains("VEST SCAN"),
        "stdout must not contain human banner\nstdout:\n{stdout}"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON only");
    assert!(
        parsed.get("summary").is_some() || parsed.get("findings").is_some(),
        "expected a scan report JSON object, got: {parsed}"
    );
    assert!(
        stderr.contains("VEST SCAN") || stderr.contains("Running scan"),
        "banners/progress should land on stderr\nstderr:\n{stderr}"
    );
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
        .env_remove("VEST_DB_PATH")
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
            .env_remove("VEST_DB_PATH")
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
            .env_remove("VEST_DB_PATH")
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
            .env_remove("VEST_DB_PATH")
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
            .env_remove("VEST_DB_PATH")
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
fn providers_pull_checks_ollama() {
    let root = temp_root("pull");
    let vest_home = root.join("home");
    fs::create_dir_all(&root).unwrap();

    let output = Command::new(vest_bin())
        .env("VEST_HOME", &vest_home)
        .env_remove("VEST_DB_PATH")
        .arg("providers")
        .arg("pull")
        .arg("llama3.2")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        // Either ollama was found and pull ran (unlikely in CI), or we see the helpful message
        assert!(
            stdout.contains("pulling manifest")
                || stdout.contains("Ollama is not installed")
                || stdout.is_empty(),
            "unexpected stdout: {stdout}"
        );
    }
}

#[test]
fn completions_generates_shell_script() {
    let output = Command::new(vest_bin())
        .arg("completions")
        .arg("bash")
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("complete"),
        "Bash completions should contain 'complete': {stdout}"
    );
    assert!(
        stdout.contains("vest"),
        "Completions should mention 'vest': {stdout}"
    );
}

#[test]
fn completions_unsupported_shell_exits_gracefully() {
    let output = Command::new(vest_bin())
        .arg("completions")
        .arg("nonexistent")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "unsupported shell must be a non-zero exit"
    );
    assert!(
        stderr.contains("Unsupported shell"),
        "Should warn about unsupported shell: {stderr}"
    );
}

#[test]
fn malformed_config_via_c_flag_fails_closed() {
    let root = temp_root("bad-config");
    fs::create_dir_all(&root).unwrap();
    let bad = root.join("bad.toml");
    fs::write(&bad, "this is {{{ not toml\n").unwrap();

    let output = Command::new(vest_bin())
        .arg("-c")
        .arg(&bad)
        .arg("scan")
        .arg("./examples/demo-target/vulnerable-files")
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "malformed present config must fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("config") || stderr.to_lowercase().contains("parse"),
        "stderr should mention config/parse failure: {stderr}"
    );
}

#[test]
fn memory_scan_without_simulation_is_fatal() {
    let root = temp_root("memory-unsup");
    let vest_home = root.join("home");
    fs::create_dir_all(&vest_home).unwrap();

    let output = Command::new(vest_bin())
        .env("VEST_HOME", &vest_home)
        .env_remove("VEST_DB_PATH")
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

    assert!(
        !output.status.success(),
        "unsupported memory scan must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.to_lowercase().contains("unsupported")
            || combined.to_lowercase().contains("scanner failure"),
        "should report unsupported/scanner failure: {combined}"
    );
}

#[test]
fn set_key_never_echoes_secret() {
    let output = Command::new(vest_bin())
        .arg("providers")
        .arg("set-key")
        .arg("openai")
        .arg("--key")
        .arg("SUPER_SECRET_TEST_KEY_123")
        .output()
        .unwrap();

    assert_success(&output);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("SUPER_SECRET_TEST_KEY_123"),
        "API key must never be printed: {combined}"
    );
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
        .env_remove("VEST_DB_PATH")
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
