//! End-to-end human workflows: scan → inspect → report, plus adversarial CLI inputs.

mod common;

use common::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;

#[test]
fn full_workflow_scan_list_show_findings_report_markdown() {
    let root = temp_root("workflow");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture_dir = root.join("target");
    let fixture = fixture_dir.join("secrets.env");
    let report_json = root.join("out.json");
    let report_md = root.join("out.md");

    fs::create_dir_all(&fixture_dir).unwrap();
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(
        &fixture,
        "API_KEY=sk-test-human-workflow-secret-001\npassword = \"hunter2-workflow\"\n",
    )
    .unwrap();

    let scan = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture_dir)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report_json)
        .output()
        .unwrap();
    assert_success(&scan);

    let report = read_json(&report_json);
    assert!(
        report["summary"]["total"].as_u64().unwrap_or(0) >= 1,
        "expected findings in report: {report}"
    );

    let scans_list = vest_cmd(&vest_home)
        .arg("scans")
        .arg("list")
        .output()
        .unwrap();
    assert_success(&scans_list);
    assert!(stdout(&scans_list).contains("Total:"));

    let pool =
        vest_storage::ConnectionPool::new(vest_home.join("vest.db").to_str().unwrap()).unwrap();
    let scans = vest_storage::scans::list_scans(pool.conn()).unwrap();
    assert_eq!(scans.len(), 1);
    let scan_id = scans[0].id.clone();

    let show = vest_cmd(&vest_home)
        .arg("scans")
        .arg("show")
        .arg(&scan_id)
        .output()
        .unwrap();
    assert_success(&show);

    let findings = vest_cmd(&vest_home)
        .arg("findings")
        .arg("list")
        .arg("--scan-id")
        .arg(&scan_id)
        .output()
        .unwrap();
    assert_success(&findings);

    let md = vest_cmd(&vest_home)
        .arg("report")
        .arg("generate")
        .arg(&scan_id)
        .arg("--format")
        .arg("markdown")
        .arg("--output")
        .arg(&report_md)
        .output()
        .unwrap();
    assert_success(&md);
    let md_body = fs::read_to_string(&report_md).unwrap();
    assert!(!md_body.is_empty());
}

#[test]
fn missing_scan_id_report_fails() {
    let root = temp_root("missing-scan");
    let vest_home = root.join("home");
    fs::create_dir_all(&vest_home).unwrap();

    // Touch empty DB by running a dry-run... dry-run skips DB. Create DB via a tiny scan.
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"x\"\n").unwrap();
    let _ = vest_cmd(&vest_home)
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

    let output = vest_cmd(&vest_home)
        .arg("report")
        .arg("generate")
        .arg("does-not-exist-scan-id")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "missing scan id must fail\n{}",
        combined(&output)
    );
}

#[test]
fn providers_set_key_never_leaks_and_instructs_env() {
    let secret = "HUMAN_TEST_KEY_NEVER_PRINT_ME_987654321";
    let output = Command::new(vest_bin())
        .arg("providers")
        .arg("set-key")
        .arg("openai")
        .arg("--key")
        .arg(secret)
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output);
    assert!(!text.contains(secret), "key leaked:\n{text}");
    assert!(
        text.contains("OPENAI_API_KEY") || text.contains("environment"),
        "should instruct env configuration:\n{text}"
    );
}

#[test]
fn file_scan_ignores_symlink_escape_outside_target_tree() {
    let root = temp_root("symlink-escape");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let target = root.join("in-scope");
    let outside = root.join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    fs::write(
        outside.join("secret.txt"),
        "password = \"outside-secret-xyz\"\n",
    )
    .unwrap();
    fs::write(target.join("ok.txt"), "hello = world\n").unwrap();
    let link = target.join("escape");
    let _ = fs::remove_file(&link);
    symlink(&outside, &link).unwrap();

    let report = root.join("report.json");
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
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();

    assert_success(&output);
    let body = fs::read_to_string(&report).unwrap();
    assert!(
        !body.contains("outside-secret-xyz"),
        "symlink escape must not pull outside secrets into report:\n{body}"
    );
}

#[test]
fn help_and_version_are_usable() {
    let help = Command::new(vest_bin()).arg("--help").output().unwrap();
    assert_success(&help);
    assert!(stdout(&help).to_lowercase().contains("scan"));

    let ver = Command::new(vest_bin()).arg("--version").output().unwrap();
    assert_success(&ver);
    assert!(!stdout(&ver).trim().is_empty());
}

#[test]
fn json_report_does_not_echo_provider_api_key_from_env() {
    let root = temp_root("no-key-leak");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("f.txt");
    let report = root.join("report.json");
    let secret = "env-api-key-must-not-appear-in-report-ABCDEF";

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "note = \"no password here\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .env("OPENAI_API_KEY", secret)
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
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();

    assert_success(&output);
    let body = combined(&output) + &fs::read_to_string(&report).unwrap_or_default();
    assert!(
        !body.contains(secret),
        "API key from env must not appear in CLI output/report"
    );
}
