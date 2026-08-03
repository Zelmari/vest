//! K16: heuristic scores live on `severity_score_estimate`, with serde alias for
//! legacy `cvss_score` JSON. The field is not a CVSS vector.

use chrono::Utc;
use vest_core::types::{Finding, FindingStatus, Severity, VulnerabilityClass};

fn sample_finding(estimate: Option<f64>) -> Finding {
    let now = Utc::now();
    Finding {
        id: "finding-1".into(),
        scan_id: "scan-1".into(),
        target_id: "target-1".into(),
        title: "Heuristic finding".into(),
        description: "Scanner heuristic score".into(),
        vulnerability_class: VulnerabilityClass::XSS,
        severity: Severity::High,
        confidence: 0.9,
        status: FindingStatus::Open,
        severity_score_estimate: estimate,
        cve_id: None,
        cwe_id: Some("CWE-79".into()),
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: now,
        updated_at: now,
    }
}

#[test]
fn serializes_as_severity_score_estimate_not_cvss_score() {
    let json = serde_json::to_value(sample_finding(Some(7.5))).unwrap();
    assert_eq!(json["severity_score_estimate"], 7.5);
    assert!(json.get("cvss_score").is_none());
}

#[test]
fn deserializes_legacy_cvss_score_alias() {
    let mut value = serde_json::to_value(sample_finding(None)).unwrap();
    let obj = value.as_object_mut().unwrap();
    obj.remove("severity_score_estimate");
    obj.insert("cvss_score".into(), serde_json::json!(6.1));

    let finding: Finding = serde_json::from_value(value).unwrap();
    assert_eq!(finding.severity_score_estimate, Some(6.1));
}

#[test]
fn deserializes_new_field_name() {
    let finding: Finding =
        serde_json::from_value(serde_json::to_value(sample_finding(Some(7.5))).unwrap()).unwrap();
    assert_eq!(finding.severity_score_estimate, Some(7.5));
}
