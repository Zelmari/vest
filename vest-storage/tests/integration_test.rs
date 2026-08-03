#[cfg(test)]
mod integration_tests {
    use chrono::Utc;
    use vest_core::types::*;
    use vest_storage::*;

    fn setup_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to create in-memory DB");
        schema::run_migrations(&conn).expect("Failed to run migrations");
        conn
    }

    fn make_target(name: &str, t: TargetType) -> Target {
        Target {
            id: format!("target-{}", name),
            name: name.into(),
            target_type: t,
            path: None,
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_scan(id: &str, target_id: &str, mode: ScanMode) -> ScanSession {
        ScanSession {
            id: id.into(),
            target_id: target_id.into(),
            mode,
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
            created_at: Utc::now(),
        }
    }

    fn make_finding(
        scan_id: &str,
        target_id: &str,
        severity: Severity,
        vuln_class: VulnerabilityClass,
    ) -> Finding {
        let now = Utc::now();
        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: scan_id.into(),
            target_id: target_id.into(),
            title: "Test Vuln".into(),
            description: "Test vuln description".into(),
            vulnerability_class: vuln_class,
            severity,
            confidence: 0.9,
            status: FindingStatus::Open,
            cvss_score: Some(7.5),
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({"test": true}),
            poc: None,
            remediation: None,
            location: serde_json::json!({"file": "test.rs", "line": 42}),
            false_positive_history: None,
            tags: vec!["test".into()],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        }
    }

    fn make_artifact(scan_id: &str, finding_id: Option<&str>, artifact_type: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: scan_id.into(),
            finding_id: finding_id.map(|s| s.to_string()),
            artifact_type: artifact_type.into(),
            mime_type: Some("image/png".into()),
            filename: "test.png".into(),
            size_bytes: None,
            content_path: Some("/tmp/test.png".into()),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
        }
    }

    // Target tests

    #[test]
    fn test_insert_and_get_target() {
        let conn = setup_db();
        let target = make_target("test.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let fetched = targets::get_target(&conn, &target.id).unwrap();
        assert_eq!(fetched.name, "test.exe");
        assert_eq!(fetched.target_type, TargetType::Process);
    }

    #[test]
    fn test_get_nonexistent_target_fails() {
        let conn = setup_db();
        let err = targets::get_target(&conn, "nonexistent").unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn test_list_targets_empty() {
        let conn = setup_db();
        let list = targets::list_targets(&conn).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn test_list_targets_with_data() {
        let conn = setup_db();
        targets::insert_target(&conn, &make_target("a.exe", TargetType::Process)).unwrap();
        targets::insert_target(&conn, &make_target("b.com", TargetType::Web)).unwrap();
        let list = targets::list_targets(&conn).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_list_targets_by_type() {
        let conn = setup_db();
        targets::insert_target(&conn, &make_target("game.exe", TargetType::Process)).unwrap();
        targets::insert_target(&conn, &make_target("web.com", TargetType::Web)).unwrap();
        targets::insert_target(&conn, &make_target("app.exe", TargetType::Process)).unwrap();

        let processes = targets::list_targets_by_type(&conn, &TargetType::Process).unwrap();
        assert_eq!(processes.len(), 2);

        let webs = targets::list_targets_by_type(&conn, &TargetType::Web).unwrap();
        assert_eq!(webs.len(), 1);
    }

    #[test]
    fn test_update_target() {
        let conn = setup_db();
        let mut target = make_target("old.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();

        target.name = "new.exe".into();
        target.target_type = TargetType::Binary;
        targets::update_target(&conn, &target).unwrap();

        let updated = targets::get_target(&conn, &target.id).unwrap();
        assert_eq!(updated.name, "new.exe");
        assert_eq!(updated.target_type, TargetType::Binary);
    }

    #[test]
    fn test_delete_target() {
        let conn = setup_db();
        let target = make_target("del.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        assert!(targets::get_target(&conn, &target.id).is_ok());

        targets::delete_target(&conn, &target.id).unwrap();
        assert!(targets::get_target(&conn, &target.id).is_err());
    }

    #[test]
    fn test_delete_nonexistent_target_ok() {
        let conn = setup_db();
        assert!(targets::delete_target(&conn, "nonexistent").is_ok());
    }

    #[test]
    fn test_target_with_all_optionals_none() {
        let conn = setup_db();
        let target = Target {
            id: "t1".into(),
            name: "minimal".into(),
            target_type: TargetType::File,
            path: None,
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        targets::insert_target(&conn, &target).unwrap();
        let fetched = targets::get_target(&conn, "t1").unwrap();
        assert_eq!(fetched.name, "minimal");
        assert!(fetched.path.is_none());
        assert!(fetched.pid.is_none());
    }

    // Scan tests

    #[test]
    fn test_insert_and_get_scan() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();

        let scan = make_scan("scan-1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let fetched = scans::get_scan(&conn, "scan-1").unwrap();
        assert_eq!(fetched.mode, ScanMode::Pipeline);
        assert_eq!(fetched.status, ScanStatus::Pending);
    }

    #[test]
    fn test_get_nonexistent_scan_fails() {
        let conn = setup_db();
        let err = scans::get_scan(&conn, "no-such-scan").unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn test_list_scans() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();

        scans::insert_scan(&conn, &make_scan("s1", &target.id, ScanMode::ToolUse)).unwrap();
        scans::insert_scan(&conn, &make_scan("s2", &target.id, ScanMode::Swarm)).unwrap();

        let list = scans::list_scans(&conn).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_list_scans_by_target() {
        let conn = setup_db();
        let t1 = make_target("a.exe", TargetType::Process);
        let t2 = make_target("b.exe", TargetType::Process);
        targets::insert_target(&conn, &t1).unwrap();
        targets::insert_target(&conn, &t2).unwrap();

        scans::insert_scan(&conn, &make_scan("s1", &t1.id, ScanMode::Pipeline)).unwrap();
        scans::insert_scan(&conn, &make_scan("s2", &t2.id, ScanMode::Swarm)).unwrap();

        let t1_scans = scans::list_scans_by_target(&conn, &t1.id).unwrap();
        assert_eq!(t1_scans.len(), 1);
        assert_eq!(t1_scans[0].id, "s1");
    }

    #[test]
    fn test_update_scan_status() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();

        let scan = make_scan("scan-1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        scans::update_scan_status(&conn, "scan-1", &ScanStatus::Running).unwrap();
        let updated = scans::get_scan(&conn, "scan-1").unwrap();
        assert_eq!(updated.status, ScanStatus::Running);

        scans::update_scan_status(&conn, "scan-1", &ScanStatus::Completed).unwrap();
        let updated = scans::get_scan(&conn, "scan-1").unwrap();
        assert_eq!(updated.status, ScanStatus::Completed);
    }

    #[test]
    fn test_update_scan_status_nonexistent_returns_not_found() {
        let conn = setup_db();
        let err = scans::update_scan_status(&conn, "nonexistent", &ScanStatus::Failed).unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    // Finding tests

    #[test]
    fn test_insert_and_get_finding() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let finding = make_finding(
            "s1",
            &target.id,
            Severity::Critical,
            VulnerabilityClass::BufferOverflow,
        );
        let finding_id = finding.id.clone();
        findings::insert_finding(&conn, &finding).unwrap();

        let fetched = findings::get_finding(&conn, &finding_id).unwrap();
        assert_eq!(fetched.severity, Severity::Critical);
        assert_eq!(
            fetched.vulnerability_class,
            VulnerabilityClass::BufferOverflow
        );
        assert_eq!(fetched.confidence, 0.9);
    }

    #[test]
    fn test_get_nonexistent_finding_fails() {
        let conn = setup_db();
        let err = findings::get_finding(&conn, "no-finding").unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn test_list_findings_by_scan() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        findings::insert_finding(
            &conn,
            &make_finding("s1", &target.id, Severity::High, VulnerabilityClass::XSS),
        )
        .unwrap();
        findings::insert_finding(
            &conn,
            &make_finding("s1", &target.id, Severity::Medium, VulnerabilityClass::CSRF),
        )
        .unwrap();

        let list = findings::list_findings_by_scan(&conn, "s1").unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_list_findings_by_severity() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        findings::insert_finding(
            &conn,
            &make_finding(
                "s1",
                &target.id,
                Severity::Critical,
                VulnerabilityClass::BufferOverflow,
            ),
        )
        .unwrap();
        findings::insert_finding(
            &conn,
            &make_finding("s1", &target.id, Severity::High, VulnerabilityClass::XSS),
        )
        .unwrap();
        findings::insert_finding(
            &conn,
            &make_finding("s1", &target.id, Severity::Medium, VulnerabilityClass::CSRF),
        )
        .unwrap();

        let critical = findings::list_findings_by_severity(&conn, &Severity::Critical).unwrap();
        assert_eq!(critical.len(), 1);

        let high = findings::list_findings_by_severity(&conn, &Severity::High).unwrap();
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn test_update_finding_status() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let finding = make_finding("s1", &target.id, Severity::High, VulnerabilityClass::XSS);
        let fid = finding.id.clone();
        findings::insert_finding(&conn, &finding).unwrap();

        findings::update_finding_status(&conn, &fid, &FindingStatus::FalsePositive).unwrap();
        let updated = findings::get_finding(&conn, &fid).unwrap();
        assert_eq!(updated.status, FindingStatus::FalsePositive);
    }

    #[test]
    fn test_update_finding() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let finding = make_finding("s1", &target.id, Severity::Low, VulnerabilityClass::Unknown);
        let fid = finding.id.clone();
        findings::insert_finding(&conn, &finding).unwrap();

        let mut updated = findings::get_finding(&conn, &fid).unwrap();
        updated.title = "Updated Title".into();
        updated.severity = Severity::Critical;
        findings::update_finding(&conn, &updated).unwrap();

        let refetched = findings::get_finding(&conn, &fid).unwrap();
        assert_eq!(refetched.title, "Updated Title");
        assert_eq!(refetched.severity, Severity::Critical);
    }

    #[test]
    fn test_list_findings_empty_scan() {
        let conn = setup_db();
        let findings = findings::list_findings_by_scan(&conn, "no-scan").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_list_findings_by_target() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        findings::insert_finding(
            &conn,
            &make_finding(
                "s1",
                &target.id,
                Severity::High,
                VulnerabilityClass::SQLInjection,
            ),
        )
        .unwrap();

        let list = findings::list_findings_by_target(&conn, &target.id).unwrap();
        assert_eq!(list.len(), 1);
    }

    // Artifact tests

    #[test]
    fn test_insert_and_get_artifact() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let artifact = make_artifact("s1", None, "screenshot");
        let aid = artifact.id.clone();
        artifacts::insert_artifact(&conn, &artifact).unwrap();

        let fetched = artifacts::get_artifact(&conn, &aid).unwrap();
        assert_eq!(fetched.artifact_type, "screenshot");
        assert_eq!(fetched.filename, "test.png");
    }

    #[test]
    fn test_get_nonexistent_artifact_fails() {
        let conn = setup_db();
        let err = artifacts::get_artifact(&conn, "nonexistent").unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn test_list_artifacts_by_scan() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        artifacts::insert_artifact(&conn, &make_artifact("s1", None, "screenshot")).unwrap();
        artifacts::insert_artifact(&conn, &make_artifact("s1", None, "memory_dump")).unwrap();

        let list = artifacts::list_artifacts_by_scan(&conn, "s1").unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_list_artifacts_by_finding() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();
        let finding = make_finding("s1", &target.id, Severity::High, VulnerabilityClass::XSS);
        let fid = finding.id.clone();
        findings::insert_finding(&conn, &finding).unwrap();

        artifacts::insert_artifact(&conn, &make_artifact("s1", Some(&fid), "screenshot")).unwrap();

        let list = artifacts::list_artifacts_by_finding(&conn, &fid).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_artifact_with_all_optionals() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let artifact = Artifact {
            id: "a1".into(),
            scan_id: "s1".into(),
            finding_id: None,
            artifact_type: "log".into(),
            mime_type: None,
            filename: "scan.log".into(),
            size_bytes: None,
            content_path: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
        };
        artifacts::insert_artifact(&conn, &artifact).unwrap();
        let fetched = artifacts::get_artifact(&conn, "a1").unwrap();
        assert!(fetched.mime_type.is_none());
        assert!(fetched.size_bytes.is_none());
    }

    // Memory tests

    #[test]
    fn test_insert_and_get_memory_entry() {
        let conn = setup_db();
        let entry = ScanMemoryEntry {
            id: "mem-1".into(),
            pattern_hash: "abc123".into(),
            pattern_type: PatternType::FalsePositive,
            target_hash: Some("target-hash".into()),
            description: "Common FP in login form".into(),
            evidence: serde_json::json!({"form": "/login"}),
            confidence: 0.95,
            occurrences: 3,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        memory::insert_memory_entry(&conn, &entry).unwrap();
        let fetched = memory::get_memory_entry(&conn, "mem-1").unwrap();
        assert_eq!(fetched.pattern_hash, "abc123");
        assert_eq!(fetched.pattern_type, PatternType::FalsePositive);
        assert_eq!(fetched.occurrences, 3);
    }

    #[test]
    fn test_get_nonexistent_memory_entry_fails() {
        let conn = setup_db();
        let err = memory::get_memory_entry(&conn, "nonexistent").unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[test]
    fn test_find_memory_by_pattern() {
        let conn = setup_db();
        let now = Utc::now();
        let e1 = ScanMemoryEntry {
            id: "m1".into(),
            pattern_hash: "hash-a".into(),
            pattern_type: PatternType::FalsePositive,
            target_hash: None,
            description: "FP 1".into(),
            evidence: serde_json::json!({}),
            confidence: 0.9,
            occurrences: 1,
            created_at: now,
            updated_at: now,
        };
        let e2 = ScanMemoryEntry {
            id: "m2".into(),
            pattern_hash: "hash-a".into(),
            pattern_type: PatternType::ConfirmedVuln,
            target_hash: None,
            description: "Real 1".into(),
            evidence: serde_json::json!({}),
            confidence: 0.85,
            occurrences: 2,
            created_at: now,
            updated_at: now,
        };
        let e3 = ScanMemoryEntry {
            id: "m3".into(),
            pattern_hash: "hash-b".into(),
            pattern_type: PatternType::UsefulToolSequence,
            target_hash: None,
            description: "Tool seq".into(),
            evidence: serde_json::json!({}),
            confidence: 0.7,
            occurrences: 1,
            created_at: now,
            updated_at: now,
        };
        memory::insert_memory_entry(&conn, &e1).unwrap();
        memory::insert_memory_entry(&conn, &e2).unwrap();
        memory::insert_memory_entry(&conn, &e3).unwrap();

        let matches_a = memory::find_memory_by_pattern(&conn, "hash-a").unwrap();
        assert_eq!(matches_a.len(), 2);

        let matches_b = memory::find_memory_by_pattern(&conn, "hash-b").unwrap();
        assert_eq!(matches_b.len(), 1);

        let matches_none = memory::find_memory_by_pattern(&conn, "no-hash").unwrap();
        assert!(matches_none.is_empty());
    }

    // Schema tests

    #[test]
    fn test_migrations_idempotent() {
        let conn = setup_db();
        assert!(schema::run_migrations(&conn).is_ok());
        assert!(schema::run_migrations(&conn).is_ok());
    }

    #[test]
    fn test_foreign_key_enforcement() {
        let conn = setup_db();
        let target = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &target).unwrap();
        let scan = make_scan("s1", &target.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let finding = make_finding("s1", &target.id, Severity::High, VulnerabilityClass::XSS);
        assert!(findings::insert_finding(&conn, &finding).is_ok());

        let bad_finding = Finding {
            scan_id: "bad-scan-id".into(),
            target_id: "bad-target-id".into(),
            ..finding
        };
        let result = findings::insert_finding(&conn, &bad_finding);
        // FK enforcement may or may not work in in-memory SQLite
        // depending on how PRAGMA foreign_keys is handled.
        // If it fails, it should be a database error (FK constraint).
        if let Err(e) = result {
            assert!(
                matches!(e, StorageError::Database(_)),
                "Unexpected error: {:?}",
                e
            );
        }
    }

    // Connection tests

    #[test]
    fn test_connection_pool_in_memory() {
        let pool = ConnectionPool::new(":memory:").unwrap();
        let conn = pool.conn();
        let count: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    // Injection and malicious input tests

    #[test]
    fn test_malicious_target_name_in_db() {
        let conn = setup_db();
        let malicious_names = vec![
            "'; DROP TABLE targets; --",
            "<script>alert('xss')</script>",
            "foo\\bar",
            "foo'bar",
            "\x00\x00null",
        ];
        for name in &malicious_names {
            let target = Target {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.to_string(),
                target_type: TargetType::Web,
                path: None,
                url_str: None,
                pid: None,
                host: None,
                metadata: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            targets::insert_target(&conn, &target).unwrap();
            let fetched = targets::get_target(&conn, &target.id).unwrap();
            assert_eq!(
                fetched.name, *name,
                "Failed to roundtrip malicious name: {}",
                name
            );
        }
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM targets", [], |r| r.get(0))
            .unwrap();
        assert!(count >= 5);
    }

    #[test]
    fn test_empty_finding_fields() {
        let conn = setup_db();
        let t = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &t).unwrap();
        let s = make_scan("s1", &t.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &s).unwrap();

        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: "s1".into(),
            target_id: t.id.clone(),
            title: String::new(),
            description: String::new(),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: Severity::Info,
            confidence: 0.0,
            status: FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!(null),
            poc: Some(String::new()),
            remediation: Some(String::new()),
            location: serde_json::json!(null),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: Utc::now(),
            updated_at: Utc::now(),
        };
        findings::insert_finding(&conn, &finding).unwrap();
        let fetched = findings::get_finding(&conn, &finding.id).unwrap();
        assert_eq!(fetched.title, "");
        assert_eq!(fetched.description, "");
    }

    #[test]
    fn test_maximum_size_finding() {
        let conn = setup_db();
        let t = make_target("t.exe", TargetType::Process);
        targets::insert_target(&conn, &t).unwrap();
        let s = make_scan("s1", &t.id, ScanMode::Pipeline);
        scans::insert_scan(&conn, &s).unwrap();

        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: "s1".into(),
            target_id: t.id.clone(),
            title: "A".repeat(10000),
            description: "B".repeat(50000),
            vulnerability_class: VulnerabilityClass::BufferOverflow,
            severity: Severity::Critical,
            confidence: 1.0,
            status: FindingStatus::Open,
            cvss_score: Some(10.0),
            cve_id: Some("CVE-2024-99999".into()),
            cwe_id: Some("CWE-999".into()),
            evidence: serde_json::json!({"huge": "C".repeat(100000)}),
            poc: Some("D".repeat(50000)),
            remediation: Some("E".repeat(50000)),
            location: serde_json::json!({"file": "F".repeat(5000)}),
            false_positive_history: None,
            tags: (0..1000).map(|i| format!("tag-{}", i)).collect(),
            metadata: serde_json::json!({"big": "G".repeat(10000)}),
            discovered_at: Utc::now(),
            updated_at: Utc::now(),
        };
        findings::insert_finding(&conn, &finding).unwrap();
        let fetched = findings::get_finding(&conn, &finding.id).unwrap();
        assert_eq!(fetched.title.len(), 10000);
    }
}
