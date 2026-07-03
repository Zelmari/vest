use chrono::Utc;
use rusqlite::Connection;
use vest_core::types::*;
use vest_storage::{findings, scans, schema, targets, ConnectionPool};

fn setup() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    schema::run_migrations(&conn).unwrap();
    conn
}

#[test]
fn test_insert_duplicate_target_errors() {
    let conn = setup();
    let now = Utc::now();
    let target = Target {
        id: "dup-target".into(),
        name: "test".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &target).unwrap();
    let result = targets::insert_target(&conn, &target);
    assert!(result.is_err());
}

#[test]
fn test_get_nonexistent_target_returns_error() {
    let conn = setup();
    let result = targets::get_target(&conn, "does-not-exist");
    assert!(result.is_err());
}

#[test]
fn test_update_nonexistent_target_no_error() {
    let conn = setup();
    let now = Utc::now();
    let target = Target {
        id: "nonexistent".into(),
        name: "ghost".into(),
        target_type: TargetType::Binary,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    assert!(targets::update_target(&conn, &target).is_ok());
}

#[test]
fn test_bulk_insert_and_query() {
    let conn = setup();
    let now = Utc::now();

    for i in 0..1000 {
        let t = Target {
            id: format!("t-{}", i),
            name: format!("target-{}", i),
            target_type: if i % 2 == 0 {
                TargetType::Web
            } else {
                TargetType::Binary
            },
            path: None,
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({"index": i}),
            created_at: now,
            updated_at: now,
        };
        targets::insert_target(&conn, &t).unwrap();
    }

    let all = targets::list_targets(&conn).unwrap();
    assert_eq!(all.len(), 1000);

    let web = targets::list_targets_by_type(&conn, &TargetType::Web).unwrap();
    assert_eq!(web.len(), 500);

    let binary = targets::list_targets_by_type(&conn, &TargetType::Binary).unwrap();
    assert_eq!(binary.len(), 500);
}

#[test]
fn test_delete_with_referencing_data() {
    let conn = setup();
    let now = Utc::now();

    let t = Target {
        id: "t-cascade".into(),
        name: "cascade".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &t).unwrap();

    let s = ScanSession {
        id: "s-cascade".into(),
        target_id: "t-cascade".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Completed,
        agent_model: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    scans::insert_scan(&conn, &s).unwrap();

    let scan = scans::get_scan(&conn, "s-cascade").unwrap();
    assert_eq!(scan.target_id, "t-cascade");

    assert!(targets::get_target(&conn, "t-cascade").is_ok());

    let delete_result = targets::delete_target(&conn, "t-cascade");
    assert!(delete_result.is_err());

    assert!(targets::get_target(&conn, "t-cascade").is_ok());
}

#[test]
fn test_findings_by_empty_scan_id() {
    let conn = setup();
    let findings = findings::list_findings_by_scan(&conn, "").unwrap();
    assert!(findings.is_empty());
}

#[test]
fn test_list_targets_ordering() {
    let conn = setup();
    let now = Utc::now();

    for i in 0..5 {
        let t = Target {
            id: format!("t-{}", i),
            name: format!("target-{}", i),
            target_type: TargetType::Web,
            path: None,
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        };
        targets::insert_target(&conn, &t).unwrap();
    }

    let all = targets::list_targets(&conn).unwrap();
    assert_eq!(all.len(), 5);
}

#[test]
fn test_schema_run_migrations_is_idempotent() {
    let conn = setup();
    for _ in 0..10 {
        assert!(schema::run_migrations(&conn).is_ok());
    }
}

#[test]
fn test_finding_insert_and_retrieve() {
    let conn = setup();
    let now = Utc::now();

    let t = Target {
        id: "t-find-test".into(),
        name: "findtest".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &t).unwrap();

    let s = ScanSession {
        id: "s-find-test".into(),
        target_id: "t-find-test".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Completed,
        agent_model: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    scans::insert_scan(&conn, &s).unwrap();

    let f = Finding {
        id: "f-1".into(),
        scan_id: "s-find-test".into(),
        target_id: "t-find-test".into(),
        title: "Test Vuln".into(),
        description: "Test description".into(),
        vulnerability_class: VulnerabilityClass::XSS,
        severity: Severity::High,
        confidence: 0.85,
        status: FindingStatus::Open,
        cvss_score: Some(7.5),
        cve_id: None,
        cwe_id: Some("CWE-79".into()),
        evidence: serde_json::json!({"url": "https://test.com"}),
        poc: None,
        remediation: Some("Sanitize input".into()),
        location: serde_json::json!({"url": "https://test.com/search"}),
        false_positive_history: None,
        tags: vec!["xss".into()],
        metadata: serde_json::json!({}),
        discovered_at: now,
        updated_at: now,
    };
    findings::insert_finding(&conn, &f).unwrap();

    let retrieved = findings::get_finding(&conn, "f-1").unwrap();
    assert_eq!(retrieved.id, "f-1");
    assert_eq!(retrieved.severity, Severity::High);
    assert_eq!(retrieved.vulnerability_class, VulnerabilityClass::XSS);

    let by_scan = findings::list_findings_by_scan(&conn, "s-find-test").unwrap();
    assert_eq!(by_scan.len(), 1);

    let by_target = findings::list_findings_by_target(&conn, "t-find-test").unwrap();
    assert_eq!(by_target.len(), 1);

    let by_sev = findings::list_findings_by_severity(&conn, &Severity::High).unwrap();
    assert_eq!(by_sev.len(), 1);
}

#[test]
fn test_finding_update_status() {
    let conn = setup();
    let now = Utc::now();

    let t = Target {
        id: "t-find-upd".into(),
        name: "findupd".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &t).unwrap();

    let s = ScanSession {
        id: "s-find-upd".into(),
        target_id: "t-find-upd".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Completed,
        agent_model: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    scans::insert_scan(&conn, &s).unwrap();

    let f = Finding {
        id: "f-upd".into(),
        scan_id: "s-find-upd".into(),
        target_id: "t-find-upd".into(),
        title: "To Update".into(),
        description: "desc".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Low,
        confidence: 0.3,
        status: FindingStatus::Open,
        cvss_score: None,
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
    findings::insert_finding(&conn, &f).unwrap();

    findings::update_finding_status(&conn, "f-upd", &FindingStatus::FalsePositive).unwrap();
    let updated = findings::get_finding(&conn, "f-upd").unwrap();
    assert_eq!(updated.status, FindingStatus::FalsePositive);
}

#[test]
fn test_scan_status_update() {
    let conn = setup();
    let now = Utc::now();

    let t = Target {
        id: "t-scan-upd".into(),
        name: "scanupd".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &t).unwrap();

    let s = ScanSession {
        id: "s-scan-upd".into(),
        target_id: "t-scan-upd".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Pending,
        agent_model: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    scans::insert_scan(&conn, &s).unwrap();

    scans::update_scan_status(&conn, "s-scan-upd", &ScanStatus::Running).unwrap();
    let updated = scans::get_scan(&conn, "s-scan-upd").unwrap();
    assert_eq!(updated.status, ScanStatus::Running);

    scans::update_scan_status(&conn, "s-scan-upd", &ScanStatus::Completed).unwrap();
    let updated = scans::get_scan(&conn, "s-scan-upd").unwrap();
    assert_eq!(updated.status, ScanStatus::Completed);
}

#[test]
fn test_list_scans_empty() {
    let conn = setup();
    let scans_list = scans::list_scans(&conn).unwrap();
    assert!(scans_list.is_empty());
}

#[test]
fn test_list_scans_by_target_empty() {
    let conn = setup();
    let scans_list = scans::list_scans_by_target(&conn, "no-target").unwrap();
    assert!(scans_list.is_empty());
}

#[test]
fn test_connection_pool() {
    let pool = ConnectionPool::new(":memory:").unwrap();
    assert!(schema::run_migrations(pool.conn()).is_ok());
}

#[test]
fn test_get_nonexistent_finding_returns_error() {
    let conn = setup();
    let result = findings::get_finding(&conn, "does-not-exist");
    assert!(result.is_err());
}

#[test]
fn test_get_nonexistent_scan_returns_error() {
    let conn = setup();
    let result = scans::get_scan(&conn, "does-not-exist");
    assert!(result.is_err());
}

#[test]
fn test_finding_with_special_characters_in_strings() {
    let conn = setup();
    let now = Utc::now();

    let t = Target {
        id: "t-special".into(),
        name: "special".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &t).unwrap();

    let s = ScanSession {
        id: "s-special".into(),
        target_id: "t-special".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Completed,
        agent_model: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    scans::insert_scan(&conn, &s).unwrap();

    let special_strings = vec!["", "' OR 1=1 --", "\\", "\"quoted\"", "日本語", "a\0b"];

    for (i, evil_title) in special_strings.iter().enumerate() {
        let f = Finding {
            id: format!("f-special-{}", i),
            scan_id: "s-special".into(),
            target_id: "t-special".into(),
            title: evil_title.to_string(),
            description: evil_title.to_string(),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: Severity::Info,
            confidence: 0.5,
            status: FindingStatus::Open,
            cvss_score: None,
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
        findings::insert_finding(&conn, &f).unwrap();

        let retrieved = findings::get_finding(&conn, &format!("f-special-{}", i)).unwrap();
        assert_eq!(retrieved.title, *evil_title);
    }
}

#[test]
fn test_finding_update_with_sql_injection_attempt() {
    let conn = setup();
    let now = Utc::now();

    let t = Target {
        id: "t-sqli".into(),
        name: "sqli".into(),
        target_type: TargetType::Web,
        path: None,
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    };
    targets::insert_target(&conn, &t).unwrap();

    let s = ScanSession {
        id: "s-sqli".into(),
        target_id: "t-sqli".into(),
        mode: ScanMode::Pipeline,
        config: serde_json::json!({}),
        status: ScanStatus::Completed,
        agent_model: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: now,
    };
    scans::insert_scan(&conn, &s).unwrap();

    let f = Finding {
        id: "f-sqli".into(),
        scan_id: "s-sqli".into(),
        target_id: "t-sqli".into(),
        title: "Normal".into(),
        description: "Normal".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        cvss_score: None,
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
    findings::insert_finding(&conn, &f).unwrap();

    let mut evil = f.clone();
    evil.title = "'); DROP TABLE findings; --".into();
    evil.updated_at = Utc::now();

    let result = findings::update_finding(&conn, &evil);
    assert!(result.is_ok());

    let all = findings::list_findings_by_scan(&conn, "s-sqli").unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].title, "'); DROP TABLE findings; --");
}
