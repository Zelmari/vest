use chrono::{DateTime, Utc};
use vest_core::types::*;

#[test]
fn test_finding_json_injection_attack() {
    let malicious_strings = vec![
        "}{\"malicious\": true, \"real\": false, \"x\": {",
        "\"}\"\",\"\":\"\"",
        "\\u0000\\u0000\\u0000",
        "{{\"nested\": {\"deep\": {\"very_deep\": 999}}}}",
        "]\n[\n[\n[\n[",
        "\"../../../../etc/passwd\"",
    ];

    for malicious in &malicious_strings {
        let finding = Finding {
            id: "test".into(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: malicious.to_string(),
            description: malicious.to_string(),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: Severity::Info,
            confidence: 0.5,
            status: FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::Value::String(malicious.to_string()),
            poc: Some(malicious.to_string()),
            remediation: Some(malicious.to_string()),
            location: serde_json::Value::String(malicious.to_string()),
            false_positive_history: None,
            tags: vec![malicious.to_string()],
            metadata: serde_json::Value::String(malicious.to_string()),
            discovered_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&finding).unwrap();
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();

        let deser: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.title, *malicious);
    }
}

#[test]
fn test_very_deeply_nested_json_evidence() {
    let mut value = serde_json::json!({});
    for i in 0..100 {
        value = serde_json::json!({"level": i, "next": value});
    }

    let finding = Finding {
        id: "deep".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Deep JSON".into(),
        description: "test".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        cvss_score: None,
        cve_id: None,
        cwe_id: None,
        evidence: value.clone(),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let json = serde_json::to_string(&finding).unwrap();
    let deser: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.title, "Deep JSON");
}

#[test]
fn test_very_wide_json_evidence() {
    let mut map = serde_json::Map::new();
    for i in 0..10000 {
        map.insert(format!("key_{}", i), serde_json::Value::Number(i.into()));
    }

    let finding = Finding {
        id: "wide".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Wide JSON".into(),
        description: "test".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.5,
        status: FindingStatus::Open,
        cvss_score: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::Value::Object(map),
        poc: None,
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.len() > 1000);
    let deser: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.title, "Wide JSON");
}

#[test]
fn test_all_enums_roundtrip_through_json() {
    let test_cases: Vec<(&str, serde_json::Value)> = vec![
        ("severity", serde_json::json!("critical")),
        ("severity", serde_json::json!("high")),
        ("severity", serde_json::json!("medium")),
        ("severity", serde_json::json!("low")),
        ("severity", serde_json::json!("info")),
        ("target_type", serde_json::json!("web")),
        ("target_type", serde_json::json!("binary")),
        ("target_type", serde_json::json!("process")),
        ("scan_mode", serde_json::json!("pipeline")),
        ("scan_mode", serde_json::json!("swarm")),
        ("scan_mode", serde_json::json!("tool_use")),
        ("scan_mode", serde_json::json!("hierarchical")),
        ("scan_status", serde_json::json!("running")),
        ("scan_status", serde_json::json!("completed")),
        ("scan_status", serde_json::json!("failed")),
        ("finding_status", serde_json::json!("open")),
        ("finding_status", serde_json::json!("false_positive")),
    ];

    for (field, value) in &test_cases {
        match *field {
            "severity" => {
                let _: Severity = serde_json::from_value(value.clone()).unwrap();
            }
            "target_type" => {
                let _: TargetType = serde_json::from_value(value.clone()).unwrap();
            }
            "scan_mode" => {
                let _: ScanMode = serde_json::from_value(value.clone()).unwrap();
            }
            "scan_status" => {
                let _: ScanStatus = serde_json::from_value(value.clone()).unwrap();
            }
            "finding_status" => {
                let _: FindingStatus = serde_json::from_value(value.clone()).unwrap();
            }
            _ => {}
        }
    }
}

#[test]
fn test_invalid_enum_json_values() {
    let invalid_severities = vec![
        serde_json::json!(null),
        serde_json::json!(42),
        serde_json::json!([]),
        serde_json::json!({"key": "value"}),
        serde_json::json!("INVALID_SEVERITY"),
        serde_json::json!(""),
    ];
    for val in &invalid_severities {
        let result: Result<Severity, _> = serde_json::from_value(val.clone());
        assert!(result.is_err(), "Expected error for {:?}", val);
    }
}

#[test]
fn test_finding_serialization_is_stable() {
    let fixed_time = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let finding = Finding {
        id: "fixed-id".into(),
        scan_id: "fixed-scan".into(),
        target_id: "fixed-target".into(),
        title: "Fixed Title".into(),
        description: "Fixed Desc".into(),
        vulnerability_class: VulnerabilityClass::XSS,
        severity: Severity::High,
        confidence: 0.75,
        status: FindingStatus::Open,
        cvss_score: Some(7.5),
        cve_id: Some("CVE-2024-0001".into()),
        cwe_id: Some("CWE-79".into()),
        evidence: serde_json::json!({"url": "https://test.com"}),
        poc: Some("test".into()),
        remediation: Some("fix".into()),
        location: serde_json::json!({"url": "https://test.com/search"}),
        false_positive_history: None,
        tags: vec!["test".into(), "xss".into()],
        metadata: serde_json::json!({}),
        discovered_at: fixed_time,
        updated_at: fixed_time,
    };

    let json1 = serde_json::to_string(&finding).unwrap();
    let json2 = serde_json::to_string(&finding).unwrap();
    let json3 = serde_json::to_string(&finding).unwrap();
    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
}

#[test]
fn test_finding_roundtrip_preserves_all_data() {
    let now = Utc::now();
    let finding = Finding {
        id: "full-test".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Complete Finding".into(),
        description: "Full description with all fields populated".into(),
        vulnerability_class: VulnerabilityClass::BufferOverflow,
        severity: Severity::Critical,
        confidence: 0.99,
        status: FindingStatus::Confirmed,
        cvss_score: Some(9.8),
        cve_id: Some("CVE-2024-99999".into()),
        cwe_id: Some("CWE-120".into()),
        evidence: serde_json::json!({
            "crash_address": "0xDEADBEEF",
            "registers": {"eax": "0x41414141", "eip": "0xDEADBEEF"},
            "stack_trace": ["frame1", "frame2", "frame3"]
        }),
        poc: Some("Send 4096 'A' bytes to trigger overflow".into()),
        remediation: Some("Add bounds checking before memcpy".into()),
        location: serde_json::json!({
            "module": "game.exe",
            "address": "0x1400A4B00",
            "function": "ProcessPacket"
        }),
        false_positive_history: None,
        tags: vec!["critical".into(), "memory".into(), "rce".into()],
        metadata: serde_json::json!({"scan_duration_ms": 45000, "tool_version": "1.0"}),
        discovered_at: now,
        updated_at: now,
    };

    let json = serde_json::to_string_pretty(&finding).unwrap();
    let deser: Finding = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.id, finding.id);
    assert_eq!(deser.title, finding.title);
    assert_eq!(deser.vulnerability_class, finding.vulnerability_class);
    assert_eq!(deser.severity, finding.severity);
    assert_eq!(deser.confidence, finding.confidence);
    assert_eq!(deser.cvss_score, finding.cvss_score);
    assert_eq!(deser.cve_id, finding.cve_id);
    assert_eq!(deser.cwe_id, finding.cwe_id);
    assert_eq!(deser.poc, finding.poc);
    assert_eq!(deser.remediation, finding.remediation);
    assert_eq!(deser.tags, finding.tags);
    assert_eq!(deser.location, finding.location);
    assert_eq!(deser.evidence, finding.evidence);
    assert_eq!(deser.status, finding.status);
}

#[test]
fn test_finding_all_vuln_classes_roundtrip() {
    let now = Utc::now();
    let all_classes = vec![
        VulnerabilityClass::BufferOverflow,
        VulnerabilityClass::UseAfterFree,
        VulnerabilityClass::DoubleFree,
        VulnerabilityClass::IntegerOverflow,
        VulnerabilityClass::FormatString,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::XSS,
        VulnerabilityClass::SQLInjection,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::SSTI,
        VulnerabilityClass::SSRF,
        VulnerabilityClass::XXE,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::IDOR,
        VulnerabilityClass::AuthBypass,
        VulnerabilityClass::CSRF,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::JWTAttack,
        VulnerabilityClass::CORS,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::RequestSmuggling,
        VulnerabilityClass::StackCanaryBypass,
        VulnerabilityClass::ROPGadget,
        VulnerabilityClass::ASLRBypass,
        VulnerabilityClass::DEPBypass,
        VulnerabilityClass::SEHOverwrite,
        VulnerabilityClass::ImportTableHooking,
        VulnerabilityClass::DLLInjection,
        VulnerabilityClass::CodeCave,
        VulnerabilityClass::AntiDebug,
        VulnerabilityClass::SpeedHack,
        VulnerabilityClass::WallHack,
        VulnerabilityClass::Aimbot,
        VulnerabilityClass::NoClip,
        VulnerabilityClass::InfiniteResources,
        VulnerabilityClass::SaveFileRCE,
        VulnerabilityClass::ProtocolExploit,
        VulnerabilityClass::AssetTheft,
        VulnerabilityClass::DRMBypass,
        VulnerabilityClass::EngineExploit,
        VulnerabilityClass::WebSocketTamper,
        VulnerabilityClass::ClientPredictionExploit,
        VulnerabilityClass::Unknown,
    ];

    for cls in &all_classes {
        let finding = Finding {
            id: "vuln-class-test".into(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: format!("Vuln: {:?}", cls),
            description: "test".into(),
            vulnerability_class: *cls,
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

        let json = serde_json::to_string(&finding).unwrap();
        let deser: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deser.vulnerability_class, *cls,
            "Failed roundtrip for {:?}",
            cls
        );
    }
}

#[test]
fn test_finding_confidence_edge_values() {
    let now = Utc::now();
    let extreme_confs = vec![0.0, 1.0, 0.5, 1e-10, f64::MIN_POSITIVE, 0.9999999999];

    for conf in &extreme_confs {
        let finding = Finding {
            id: "conf-test".into(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: "Confidence edge test".into(),
            description: "test".into(),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: Severity::Info,
            confidence: *conf,
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

        let json = serde_json::to_string(&finding).unwrap();
        let deser: Finding = serde_json::from_str(&json).unwrap();
        assert!(
            (deser.confidence - *conf).abs() < 1e-9,
            "Confidence mismatch: {} vs {}",
            deser.confidence,
            conf
        );
    }
}

#[test]
fn test_finding_null_byte_injection_in_strings() {
    let now = Utc::now();
    let nb_strings = vec!["before\0after", "\0", "normal", "\0\0\0", "a\0b\0c"];

    for s in &nb_strings {
        let finding = Finding {
            id: "nb-test".into(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: s.to_string(),
            description: s.to_string(),
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

        let json = serde_json::to_string(&finding).unwrap();
        let deser: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.title, *s);
    }
}

#[test]
fn test_empty_and_minimal_json() {
    let now = Utc::now();

    let finding = Finding {
        id: "".into(),
        scan_id: "".into(),
        target_id: "".into(),
        title: "".into(),
        description: "".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::Info,
        confidence: 0.0,
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

    let json = serde_json::to_string(&finding).unwrap();
    let deser: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.id, "");
    assert_eq!(deser.title, "");
    assert!(deser.tags.is_empty());
    assert!(deser.poc.is_none());
}
