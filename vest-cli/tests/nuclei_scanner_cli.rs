//! Nuclei first-class scanner CLI gates.

mod common;

use common::*;
use std::fs;

#[test]
fn nuclei_without_active_probe_consent_fails() {
    let root = temp_root("nuclei-consent");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("https://example.com/")
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("nuclei")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "nuclei without consent must fail:\n{}",
        combined(&output)
    );
    let text = combined(&output).to_lowercase();
    assert!(
        text.contains("active") || text.contains("approval") || text.contains("probe"),
        "expected active-probe/approval messaging:\n{}",
        combined(&output)
    );
}

#[test]
fn nuclei_is_known_scanner_in_dry_run() {
    let root = temp_root("nuclei-dry");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("https://example.com/")
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("nuclei")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output).to_lowercase();
    assert!(text.contains("nuclei"), "{}", combined(&output));
}
