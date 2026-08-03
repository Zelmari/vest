//! N3: `vest doctor` diagnostics.

mod common;

use common::*;
use std::fs;

#[test]
fn doctor_prints_diagnostics_for_valid_config() {
    let root = temp_root("doctor-ok");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("DEEPSEEK_API_KEY")
        .env_remove("GOOGLE_API_KEY")
        .env_remove("GROQ_API_KEY")
        .env_remove("OPENROUTER_API_KEY")
        .arg("doctor")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(out.contains("VEST doctor"), "stdout:\n{out}");
    assert!(out.contains("config:"), "stdout:\n{out}");
    assert!(out.contains("valid"), "stdout:\n{out}");
    assert!(out.contains("VEST_HOME"), "stdout:\n{out}");
    assert!(
        out.contains(vest_home.to_str().unwrap()),
        "VEST_HOME path missing:\n{out}"
    );
    assert!(out.contains("sqlite:"), "stdout:\n{out}");
    assert!(out.contains("vest.db"), "stdout:\n{out}");
    assert!(out.contains("Provider env keys"), "stdout:\n{out}");
    assert!(out.contains("OPENAI_API_KEY"), "stdout:\n{out}");
    assert!(out.contains("unset"), "stdout:\n{out}");
    assert!(out.contains("Policy summary"), "stdout:\n{out}");
    assert!(out.contains("write_approval"), "stdout:\n{out}");
    assert!(
        out.contains("offline") || out.contains("no-ai") || out.contains("scanner-only"),
        "posture line missing:\n{out}"
    );
    // Never echo secret-looking values
    assert!(
        !out.contains("sk-") && !out.to_lowercase().contains("secret="),
        "must not print secrets:\n{out}"
    );
}

#[test]
fn doctor_fails_closed_on_bad_config() {
    let root = temp_root("doctor-bad");
    let vest_home = root.join("home");
    let bad = root.join("bad.toml");

    fs::create_dir_all(&vest_home).unwrap();
    fs::write(&bad, "not = {{{ toml\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&bad)
        .arg("doctor")
        .output()
        .unwrap();

    assert_exit_code(&output, 3); // CONFIG
    let err = stderr(&output);
    assert!(
        err.contains("config") || err.contains("Failed to load"),
        "stderr:\n{err}"
    );
}

#[test]
fn doctor_reports_key_presence_not_value() {
    let root = temp_root("doctor-key");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let sentinel = "sk-doctor-test-sentinel-never-print";
    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .env("OPENAI_API_KEY", sentinel)
        .arg("doctor")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = combined(&output);
    assert!(out.contains("OPENAI_API_KEY"), "stdout/err:\n{out}");
    assert!(out.contains("set"), "should report key present:\n{out}");
    assert!(
        !out.contains(sentinel),
        "must never print API key value:\n{out}"
    );
}
