//! K4: TargetContent / PotentiallySecretBearing must not reach the model by default.

use serde_json::json;
use vest_agent::{filter_for_model, AuthorisationContext};
use vest_core::DataEgressClass;

const TARGET_BODY_SENTINEL: &str = "TARGET_BODY_SENTINEL_k4_do_not_egress";

#[test]
fn target_content_body_stubbed_by_default() {
    let ctx = AuthorisationContext::new("k4-default");
    let raw = json!({
        "status": 200,
        "content_type": "text/html",
        "url": "http://example.test/",
        "body": TARGET_BODY_SENTINEL,
        "body_size": TARGET_BODY_SENTINEL.len(),
    });

    let filtered = filter_for_model(&raw, DataEgressClass::TargetContent, &ctx).unwrap();
    let s = filtered.to_string();

    assert!(
        !s.contains(TARGET_BODY_SENTINEL),
        "raw TargetContent body must not reach model context by default: {s}"
    );
    assert_eq!(filtered["egress_denied"], true);
    assert_eq!(filtered["class"], "target_content");
    assert_eq!(filtered["metadata"]["status"], 200);
    assert_eq!(filtered["metadata"]["content_type"], "text/html");
    assert_eq!(
        filtered["metadata"]["length"],
        TARGET_BODY_SENTINEL.len() as u64
    );
    let hash = filtered["metadata"]["body_sha256"]
        .as_str()
        .expect("body_sha256");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn target_content_allowed_when_flag_set_is_bounded_and_redacted() {
    let mut ctx = AuthorisationContext::new("k4-allow");
    ctx.allow_target_content_egress = true;
    ctx.known_secrets = vec!["SUPERSECRETTOKEN12345".into()];

    let raw = json!({
        "status": 200,
        "content_type": "application/json",
        "body": format!("ok token=SUPERSECRETTOKEN12345 note={TARGET_BODY_SENTINEL}"),
        "body_size": 80,
    });

    let filtered = filter_for_model(&raw, DataEgressClass::TargetContent, &ctx).unwrap();
    let s = filtered.to_string();

    assert_ne!(filtered.get("egress_denied"), Some(&json!(true)));
    assert!(
        s.contains(TARGET_BODY_SENTINEL),
        "non-secret body may pass when TargetContent egress is allowed: {s}"
    );
    assert!(
        !s.contains("SUPERSECRETTOKEN12345"),
        "known secrets must still be redacted when flag is set: {s}"
    );
    assert!(s.contains("REDACTED") || s.contains("redacted"), "{s}");
}

#[test]
fn potentially_secret_bearing_stubbed_by_default() {
    let ctx = AuthorisationContext::new("k4-psb");
    let raw = json!({
        "stdout": "CMD_OUTPUT_SENTINEL_secret_material",
        "exit_code": 0,
    });

    let filtered = filter_for_model(&raw, DataEgressClass::PotentiallySecretBearing, &ctx).unwrap();
    let s = filtered.to_string();

    assert!(!s.contains("CMD_OUTPUT_SENTINEL"));
    assert_eq!(filtered["egress_denied"], true);
    assert_eq!(filtered["class"], "potentially_secret_bearing");
}

#[test]
fn potentially_secret_bearing_allowed_when_flag_set_is_redacted() {
    let mut ctx = AuthorisationContext::new("k4-psb-allow");
    ctx.allow_potentially_secret_bearing_egress = true;
    ctx.known_secrets = vec!["CMD_OUTPUT_SENTINEL_secret_material".into()];

    let raw = json!({
        "stdout": "CMD_OUTPUT_SENTINEL_secret_material",
        "exit_code": 0,
    });

    let filtered = filter_for_model(&raw, DataEgressClass::PotentiallySecretBearing, &ctx).unwrap();
    let s = filtered.to_string();

    assert_ne!(filtered.get("egress_denied"), Some(&json!(true)));
    assert!(!s.contains("CMD_OUTPUT_SENTINEL_secret_material"), "{s}");
}
