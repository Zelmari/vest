//! `vest policy explain` CLI tests.

mod common;

use common::*;
use std::fs;

#[test]
fn policy_explain_prints_catalog_and_tools() {
    let root = temp_root("policy-explain");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("policy")
        .arg("explain")
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output);
    assert!(text.contains("ToolEffect catalog"), "{text}");
    assert!(text.contains("http_get"), "{text}");
    assert!(text.contains("http_post"), "{text}");
    assert!(text.contains("CLI pre-grants"), "{text}");
    assert!(text.contains("Evaluation pipeline"), "{text}");
}

#[test]
fn policy_explain_simulates_http_get_allow() {
    let root = temp_root("policy-sim-get");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("policy")
        .arg("explain")
        .arg("--tool")
        .arg("http_get")
        .arg("--url")
        .arg("https://example.com/")
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output);
    assert!(
        text.contains("decision:   Allow"),
        "expected Allow for passive http_get:\n{text}"
    );
}

#[test]
fn policy_explain_simulates_http_post_deny_without_grants() {
    let root = temp_root("policy-sim-post");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("policy")
        .arg("explain")
        .arg("--tool")
        .arg("http_post")
        .arg("--url")
        .arg("https://example.com/")
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output);
    assert!(
        text.contains("decision:   Deny"),
        "expected Deny for http_post without grants:\n{text}"
    );
}

#[test]
fn policy_explain_simulates_http_post_allow_with_approve_exploits() {
    let root = temp_root("policy-sim-post-grant");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("policy")
        .arg("explain")
        .arg("--tool")
        .arg("http_post")
        .arg("--url")
        .arg("https://example.com/")
        .arg("--approve-exploits")
        .output()
        .unwrap();

    assert_success(&output);
    let text = combined(&output);
    assert!(
        text.contains("decision:   Allow"),
        "expected Allow with --approve-exploits:\n{text}"
    );
}
