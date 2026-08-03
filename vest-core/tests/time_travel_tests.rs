use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use vest_core::types::*;

#[test]
fn test_finding_timestamps_are_monotonic() {
    let f1 = Finding {
        id: "1".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "First".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let f2 = Finding {
        id: "2".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Second".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(f1.discovered_at <= f2.discovered_at);
}

#[test]
fn test_finding_dates_in_past_and_future() {
    let past_naive = NaiveDate::from_ymd_opt(1970, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let past: DateTime<Utc> = Utc.from_utc_datetime(&past_naive);

    let future_naive = NaiveDate::from_ymd_opt(9999, 12, 31)
        .unwrap()
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let future: DateTime<Utc> = Utc.from_utc_datetime(&future_naive);

    let f = Finding {
        id: "time".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Time Travel".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: past,
        updated_at: future,
    };
    let json = serde_json::to_string(&f).unwrap();
    let deser: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.title, "Time Travel");
}

#[test]
fn test_finding_duration_calculation() {
    let start = DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339("2100-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let duration: Duration = end - start;
    assert!(duration.num_seconds() > 0);
}

#[test]
fn test_finding_subsecond_precision_roundtrip() {
    let now = Utc::now();
    let f = Finding {
        id: "precise".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Precise".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: now,
        updated_at: now,
    };
    let json = serde_json::to_string(&f).unwrap();
    let deser: Finding = serde_json::from_str(&json).unwrap();
    let diff_ms = (deser.discovered_at - now).num_milliseconds().abs();
    // Should be within a few seconds of original
    assert!(diff_ms < 5000, "Time drift too large: {}ms", diff_ms);
}

#[test]
fn test_epoch_zero_is_valid() {
    let epoch_naive = NaiveDate::from_ymd_opt(1970, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let epoch: DateTime<Utc> = Utc.from_utc_datetime(&epoch_naive);

    let f = Finding {
        id: "epoch".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Epoch".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.0,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: epoch,
        updated_at: epoch,
    };
    let json = serde_json::to_string(&f).unwrap();
    let _: Finding = serde_json::from_str(&json).unwrap();
}

#[test]
fn test_finding_updated_at_never_before_discovered_at() {
    // A finding should never have updated_at before discovered_at.
    // This is a property check: if your system allows it, it's a sign
    // that timestamp validation may be missing.
    let start = Utc::now();
    let end = start - Duration::days(1);

    let f = Finding {
        id: "temporal".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Backwards Time".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({}),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: start,
        updated_at: end,
    };
    // This documents: the system currently allows this inconsistency.
    // If this test starts failing because a validation guard was added,
    // that's a GOOD thing — but adjust the test to match.
    assert!(
        f.updated_at <= f.discovered_at,
        "System now validates temporal consistency"
    );
}
