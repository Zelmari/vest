//! REP-1: JSON/Markdown reports must not dump raw secret evidence by default.

use vest_core::traits::Reporter;
use vest_core::types::{
    Finding, FindingStatus, ScanMode, ScanSession, ScanStatus, Severity, VulnerabilityClass,
};
use vest_report::{JsonReporter, MarkdownReporter, TerminalReporter};

const SENTINEL: &str = "VEST_REPORT_SECRET_SENTINEL_9f3a";

fn make_scan() -> ScanSession {
    ScanSession {
        id: "rep1-scan".into(),
        target_id: "rep1-target".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Completed,
        agent_model: None,
        started_at: Some(chrono::Utc::now()),
        completed_at: Some(chrono::Utc::now()),
        duration_ms: Some(1000),
        total_findings: 1,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({
            "target": { "name": "secrets.env", "type": "file" }
        }),
        created_at: chrono::Utc::now(),
    }
}

fn secret_finding() -> Finding {
    Finding {
        id: "rep1-finding".into(),
        scan_id: "rep1-scan".into(),
        target_id: "rep1-target".into(),
        title: "Hardcoded secret".into(),
        description: "Secret material detected in file".into(),
        vulnerability_class: VulnerabilityClass::HardcodedCredentials,
        severity: Severity::High,
        confidence: 0.95,
        status: FindingStatus::Open,
        severity_score_estimate: Some(7.0),
        cve_id: None,
        cwe_id: Some("CWE-798".into()),
        evidence: serde_json::json!({
            "file": "secrets.env",
            "pattern": "api_key",
            "match_preview": SENTINEL,
            "note": format!("Authorization: Bearer {SENTINEL}")
        }),
        poc: Some(format!(
            "curl -H 'Authorization: Bearer {SENTINEL}' https://example.test"
        )),
        remediation: Some("Rotate the key and remove it from source.".into()),
        location: serde_json::json!({"file": "secrets.env", "line": 3}),
        false_positive_history: None,
        tags: vec!["secret".into()],
        metadata: serde_json::json!({"source": "files"}),
        discovered_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn json_omits_sentinel_by_default() {
    let report = JsonReporter::new()
        .generate_report(&make_scan(), &[secret_finding()])
        .await
        .unwrap();
    assert!(
        !report.contains(SENTINEL),
        "default JSON report leaked sentinel: {report}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(parsed["findings"][0]["evidence"]["omitted"], true);
    assert!(parsed["findings"][0]["poc"].is_null());
}

#[tokio::test]
async fn markdown_omits_sentinel_by_default() {
    let report = MarkdownReporter::new()
        .generate_report(&make_scan(), &[secret_finding()])
        .await
        .unwrap();
    assert!(
        !report.contains(SENTINEL),
        "default Markdown report leaked sentinel: {report}"
    );
    assert!(!report.contains("<summary>Evidence</summary>"));
    assert!(!report.contains("Proof of Concept"));
    assert!(report.contains("omitted by default"));
}

#[tokio::test]
async fn terminal_still_omits_evidence() {
    let report = TerminalReporter
        .generate_report(&make_scan(), &[secret_finding()])
        .await
        .unwrap();
    assert!(
        !report.contains(SENTINEL),
        "terminal report leaked sentinel: {report}"
    );
    assert!(!report.contains("match_preview"));
}

#[tokio::test]
async fn include_evidence_still_redacts_sentinel() {
    let json = JsonReporter::new()
        .include_evidence(true)
        .generate_report(&make_scan(), &[secret_finding()])
        .await
        .unwrap();
    assert!(
        !json.contains(SENTINEL),
        "JSON --include-evidence leaked sentinel: {json}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["findings"][0]["evidence"]["omitted"].is_null());
    assert!(parsed["findings"][0]["evidence"]["match_preview"]
        .as_str()
        .unwrap()
        .contains("REDACTED"));
    assert!(json.contains("REDACTED"));

    let md = MarkdownReporter::new()
        .include_evidence(true)
        .generate_report(&make_scan(), &[secret_finding()])
        .await
        .unwrap();
    assert!(
        !md.contains(SENTINEL),
        "Markdown --include-evidence leaked sentinel: {md}"
    );
    assert!(md.contains("<summary>Evidence</summary>"));
    assert!(md.contains("Proof of Concept"));
    assert!(md.contains("REDACTED"));
}
