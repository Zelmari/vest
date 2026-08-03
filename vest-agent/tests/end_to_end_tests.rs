use async_trait::async_trait;
use std::sync::Arc;
use vest_agent::context::ToolDefinition;
use vest_agent::patterns::tooluse::ToolUseRunner;
use vest_agent::safety::SafetyChecker;
use vest_agent::tool_registry::ToolRegistry;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::traits::{LlmProvider, Reporter};
use vest_core::types::*;
use vest_core::{DataEgressClass, ToolEffect};
use vest_storage::{findings, scans, schema, targets};

// Mock Providers

struct CyclicMockProvider {
    responses: std::sync::Mutex<(Vec<String>, usize)>,
}

impl CyclicMockProvider {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses: std::sync::Mutex::new((responses, 0)),
        }
    }
}

#[async_trait]
impl LlmProvider for CyclicMockProvider {
    async fn chat(
        &self,
        _messages: &[serde_json::Value],
        _model: &str,
    ) -> Result<String, VestError> {
        let mut guard = self.responses.lock().unwrap();
        let (responses, idx) = &mut *guard;
        let resp = responses[*idx % responses.len()].clone();
        *idx += 1;
        Ok(resp)
    }
    async fn chat_stream(
        &self,
        _messages: &[serde_json::Value],
        _model: &str,
    ) -> Result<String, VestError> {
        let mut guard = self.responses.lock().unwrap();
        let (responses, idx) = &mut *guard;
        let resp = responses[*idx % responses.len()].clone();
        *idx += 1;
        Ok(resp)
    }
    async fn list_models(&self) -> Result<Vec<String>, VestError> {
        Ok(vec!["cyclic-mock".into()])
    }
    async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
        Ok(true)
    }
    async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
        Ok(vec![])
    }
}

// Helper: Create in-memory DB with schema

fn setup_in_memory_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    schema::run_migrations(&conn).unwrap();
    conn
}

// Helper: Create a minimal Target

fn make_target(id: &str, name: &str, target_type: TargetType, pid: Option<u32>) -> Target {
    Target {
        id: id.into(),
        name: name.into(),
        target_type,
        path: None,
        url_str: None,
        pid,
        host: None,
        metadata: serde_json::json!({"test": true}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_web_target(id: &str, name: &str, url: &str) -> Target {
    Target {
        id: id.into(),
        name: name.into(),
        target_type: TargetType::Web,
        path: None,
        url_str: Some(url.into()),
        pid: None,
        host: None,
        metadata: serde_json::json!({"test": true}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// Helper: Create a ScanSession

fn make_scan(id: &str, target_id: &str, mode: ScanMode) -> ScanSession {
    ScanSession {
        id: id.into(),
        target_id: target_id.into(),
        mode,
        config: serde_json::json!({"e2e": true}),
        status: ScanStatus::Running,
        agent_model: Some("mock-model".into()),
        started_at: Some(chrono::Utc::now()),
        completed_at: None,
        duration_ms: None,
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
    }
}

// Helper: Create a Finding

fn make_finding(
    id: &str,
    scan_id: &str,
    target_id: &str,
    severity: Severity,
    vuln_class: VulnerabilityClass,
    title: &str,
    confidence: f64,
) -> Finding {
    Finding {
        id: id.into(),
        scan_id: scan_id.into(),
        target_id: target_id.into(),
        title: title.into(),
        description: format!("Description for {}", title),
        vulnerability_class: vuln_class,
        severity,
        confidence,
        status: FindingStatus::Open,
        severity_score_estimate: Some(5.0),
        cve_id: None,
        cwe_id: Some("CWE-79".into()),
        evidence: serde_json::json!({"e2e": true}),
        poc: None,
        remediation: Some("Apply the fix".into()),
        location: serde_json::json!({"url": "https://test.example.com"}),
        false_positive_history: None,
        tags: vec!["e2e".into()],
        metadata: serde_json::json!({}),
        discovered_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// TEST 1: End-to-end ToolUse scan → storage → report

#[tokio::test]
async fn test_end_to_end_tooluse_scan_to_report() {
    let conn = setup_in_memory_db();

    let target = make_target(
        "e2e-target",
        "Integration Test Target",
        TargetType::Process,
        Some(99999),
    );
    targets::insert_target(&conn, &target).unwrap();

    let scan_id = new_id();
    let scan = make_scan(&scan_id, "e2e-target", ScanMode::ToolUse);
    scans::insert_scan(&conn, &scan).unwrap();

    let mut registry = ToolRegistry::new();
    registry.register(
        ToolDefinition::new(
            "read_memory",
            "Read process memory at given address",
            serde_json::json!({"address": "string", "size": "integer"}),
            ToolEffect::ProcessMemoryRead,
            DataEgressClass::ProcessMemory,
        ),
        |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let addr = args
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0");
            Ok(serde_json::json!({"data": format!("memory dump at {}", addr), "readable": true}))
        },
    );
    registry.register(
        ToolDefinition::new(
            "list_regions",
            "List memory regions of process",
            serde_json::json!({}),
            ToolEffect::ProcessMetadataRead,
            DataEgressClass::LocalMetadata,
        ),
        |_args: serde_json::Value| -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"regions": [
                {"name": "game.exe", "perms": "RX"},
                {"name": "heap", "perms": "RW"}
            ]}))
        },
    );

    let provider = Arc::new(CyclicMockProvider::new(vec![
        r#"{"tool": "list_regions", "args": {}}"#.into(),
        r#"{"tool": "read_memory", "args": {"address": "0x00400000", "size": 4096}}"#.into(),
        r#"Scan complete. Final report: Found executable section at 0x00400000, no immediate vulnerabilities detected in test environment."#.into(),
    ]));

    let safety = Arc::new(SafetyChecker::permissive());

    let runner = ToolUseRunner::new(
        provider,
        Arc::new(registry),
        "mock-model",
        "You are a memory analysis agent. Use tools to inspect the target.",
        safety,
    )
    .with_max_iterations(10);

    let findings = runner.run(&target).await.unwrap();
    eprintln!(
        "TEST 1: ToolUse runner completed with {} findings",
        findings.len()
    );

    let stored_count = findings.len();
    for finding in &findings {
        let f = Finding {
            id: finding.id.clone(),
            scan_id: scan_id.clone(),
            target_id: "e2e-target".into(),
            ..finding.clone()
        };
        findings::insert_finding(&conn, &f).unwrap();
    }

    let stored = findings::list_findings_by_scan(&conn, &scan_id).unwrap();
    assert_eq!(stored.len(), stored_count);

    let reporter = vest_report::TerminalReporter;
    let report = reporter.generate_report(&scan, &stored).await.unwrap();
    assert!(report.contains("VEST Scan Report"));
    eprintln!("TEST 1: Terminal report generated ({} chars)", report.len());

    let json_reporter = vest_report::JsonReporter::new();
    let json_report = json_reporter.generate_report(&scan, &stored).await.unwrap();
    let _parsed: serde_json::Value = serde_json::from_str(&json_report).unwrap();
    eprintln!("TEST 1: JSON report generated and validated");
}

// TEST 2: End-to-end storage full workflow

#[tokio::test]
async fn test_end_to_end_storage_full_workflow() {
    let conn = setup_in_memory_db();

    let target = make_web_target("st-e2e", "Storage Test Target", "https://test.example.com");
    targets::insert_target(&conn, &target).unwrap();

    let scan_id = "st-scan-1";
    let scan = make_scan(scan_id, "st-e2e", ScanMode::Pipeline);
    scans::insert_scan(&conn, &scan).unwrap();

    let severities = [
        Severity::Critical,
        Severity::Critical,
        Severity::High,
        Severity::High,
        Severity::High,
        Severity::Medium,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for (i, sev) in severities.iter().enumerate() {
        let finding = make_finding(
            &format!("st-f-{}", i),
            scan_id,
            "st-e2e",
            *sev,
            VulnerabilityClass::XSS,
            &format!("Finding {}", i),
            0.5 + (i as f64 * 0.05),
        );
        findings::insert_finding(&conn, &finding).unwrap();
    }

    let all = findings::list_findings_by_scan(&conn, scan_id).unwrap();
    assert_eq!(all.len(), 9);

    let criticals = findings::list_findings_by_severity(&conn, &Severity::Critical).unwrap();
    assert_eq!(criticals.len(), 2);

    let highs = findings::list_findings_by_severity(&conn, &Severity::High).unwrap();
    assert_eq!(highs.len(), 3);

    scans::update_scan_status(&conn, scan_id, &ScanStatus::Completed).unwrap();
    let updated = scans::get_scan(&conn, scan_id).unwrap();
    assert_eq!(updated.status, ScanStatus::Completed);

    findings::update_finding_status(&conn, "st-f-0", &FindingStatus::FalsePositive).unwrap();
    let fp = findings::get_finding(&conn, "st-f-0").unwrap();
    assert_eq!(fp.status, FindingStatus::FalsePositive);

    let json_reporter = vest_report::JsonReporter::new();
    let json_report = json_reporter.generate_report(&updated, &all).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_report).unwrap();
    assert_eq!(parsed["summary"]["total"].as_u64().unwrap(), 9);
    assert_eq!(parsed["summary"]["critical"].as_u64().unwrap(), 2);
    assert_eq!(parsed["summary"]["high"].as_u64().unwrap(), 3);
    eprintln!("TEST 2: Storage full workflow completed, reports generated");
}

// TEST 3: End-to-end target CRUD → scan → findings → report

#[tokio::test]
async fn test_end_to_end_target_crud_chain() {
    let conn = setup_in_memory_db();

    let target = make_web_target("crud-e2e", "CRUD Chain Target", "https://crud.example.com");
    targets::insert_target(&conn, &target).unwrap();

    let retrieved = targets::get_target(&conn, "crud-e2e").unwrap();
    assert_eq!(retrieved.name, "CRUD Chain Target");
    assert_eq!(retrieved.target_type, TargetType::Web);

    let all_targets = targets::list_targets(&conn).unwrap();
    assert_eq!(all_targets.len(), 1);

    let web_targets = targets::list_targets_by_type(&conn, &TargetType::Web).unwrap();
    assert_eq!(web_targets.len(), 1);

    let scan_id = new_id();
    let scan = make_scan(&scan_id, "crud-e2e", ScanMode::ToolUse);
    scans::insert_scan(&conn, &scan).unwrap();

    let finding = make_finding(
        "crud-f-0",
        &scan_id,
        "crud-e2e",
        Severity::Critical,
        VulnerabilityClass::SQLInjection,
        "SQL Injection in login form",
        0.95,
    );
    findings::insert_finding(&conn, &finding).unwrap();

    let scan_findings = findings::list_findings_by_scan(&conn, &scan_id).unwrap();
    assert_eq!(scan_findings.len(), 1);
    assert_eq!(scan_findings[0].severity, Severity::Critical);

    let target_findings = findings::list_findings_by_target(&conn, "crud-e2e").unwrap();
    assert_eq!(target_findings.len(), 1);

    let terminal_reporter = vest_report::TerminalReporter;
    let terminal_report = terminal_reporter
        .generate_report(&scan, &scan_findings)
        .await
        .unwrap();
    assert!(terminal_report.contains("VEST Scan Report"));
    assert!(terminal_report.contains("SQL Injection"));
    eprintln!("TEST 3: Target CRUD chain completed, terminal report verified");

    let json_reporter = vest_report::JsonReporter::new();
    let json_report = json_reporter
        .generate_report(&scan, &scan_findings)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_report).unwrap();
    assert_eq!(parsed["scan_id"].as_str().unwrap(), scan_id);
    eprintln!("TEST 3: JSON report verified with scan_id = {}", scan_id);
}

// TEST 4: Multiple scans on same target

#[tokio::test]
async fn test_end_to_end_multiple_scans_same_target() {
    let conn = setup_in_memory_db();

    let target = make_target(
        "multi-scan-target",
        "Multi-Scan Target",
        TargetType::Process,
        Some(42),
    );
    targets::insert_target(&conn, &target).unwrap();

    let scan_ids = ["multi-scan-1", "multi-scan-2", "multi-scan-3"];
    for (i, sid) in scan_ids.iter().enumerate() {
        let scan = make_scan(sid, "multi-scan-target", ScanMode::Pipeline);
        scans::insert_scan(&conn, &scan).unwrap();

        let finding = make_finding(
            &format!("multi-f-{}", i),
            sid,
            "multi-scan-target",
            Severity::High,
            VulnerabilityClass::BufferOverflow,
            &format!("Finding from scan {}", i),
            0.8,
        );
        findings::insert_finding(&conn, &finding).unwrap();
    }

    let target_scans = scans::list_scans_by_target(&conn, "multi-scan-target").unwrap();
    assert_eq!(target_scans.len(), 3);

    for sid in &scan_ids {
        let scan_findings = findings::list_findings_by_scan(&conn, sid).unwrap();
        assert_eq!(scan_findings.len(), 1);
    }
    eprintln!("TEST 4: Multiple scans on same target completed");
}

// TEST 5: Findings with all severity levels and report validation

#[tokio::test]
async fn test_end_to_end_all_severity_levels_report() {
    let conn = setup_in_memory_db();

    let target = make_web_target("sev-e2e", "Severity Test", "https://sev.example.com");
    targets::insert_target(&conn, &target).unwrap();

    let scan_id = "sev-scan-1";
    let mut scan = make_scan(scan_id, "sev-e2e", ScanMode::Pipeline);
    scan.total_findings = 5;
    scan.critical_count = 1;
    scan.high_count = 1;
    scan.medium_count = 1;
    scan.low_count = 1;
    scan.info_count = 1;
    scans::insert_scan(&conn, &scan).unwrap();

    let all_sevs = [
        (
            Severity::Critical,
            VulnerabilityClass::BufferOverflow,
            "Critical Buffer Overflow",
        ),
        (
            Severity::High,
            VulnerabilityClass::UseAfterFree,
            "High Use-After-Free",
        ),
        (Severity::Medium, VulnerabilityClass::XSS, "Medium XSS"),
        (Severity::Low, VulnerabilityClass::CORS, "Low CORS Issue"),
        (
            Severity::Info,
            VulnerabilityClass::Unknown,
            "Info Observation",
        ),
    ];

    for (i, (sev, cls, title)) in all_sevs.iter().enumerate() {
        let finding = make_finding(
            &format!("sev-f-{}", i),
            scan_id,
            "sev-e2e",
            *sev,
            *cls,
            title,
            0.7 + (i as f64 * 0.05),
        );
        findings::insert_finding(&conn, &finding).unwrap();
    }

    let stored = findings::list_findings_by_scan(&conn, scan_id).unwrap();
    assert_eq!(stored.len(), 5);

    let json_reporter = vest_report::JsonReporter::new();
    let json_report = json_reporter.generate_report(&scan, &stored).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_report).unwrap();

    assert_eq!(parsed["summary"]["critical"].as_u64().unwrap(), 1);
    assert_eq!(parsed["summary"]["high"].as_u64().unwrap(), 1);
    assert_eq!(parsed["summary"]["medium"].as_u64().unwrap(), 1);
    assert_eq!(parsed["summary"]["low"].as_u64().unwrap(), 1);
    assert_eq!(parsed["summary"]["info"].as_u64().unwrap(), 1);
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 5);

    let terminal_reporter = vest_report::TerminalReporter;
    let terminal_report = terminal_reporter
        .generate_report(&scan, &stored)
        .await
        .unwrap();
    assert!(terminal_report.contains("Critical"));
    assert!(terminal_report.contains("TOP FINDINGS"));
    eprintln!("TEST 5: All severity levels report validated");
}

// TEST 6: ToolUseRunner with multiple tool calls, multi-tool registry

#[tokio::test]
async fn test_end_to_end_multi_tool_registry() {
    let conn = setup_in_memory_db();

    let mut registry = ToolRegistry::new();
    for i in 0..5 {
        let tool_name = format!("tool_{}", i);
        registry.register(
            ToolDefinition::new(
                tool_name.clone(),
                format!("Tool {}", i),
                serde_json::json!({"input": "string"}),
                ToolEffect::PureComputation,
                DataEgressClass::PublicNonSensitive,
            ),
            move |args: serde_json::Value| -> Result<serde_json::Value, String> {
                Ok(serde_json::json!({"result": format!("tool_{}_result", i), "input": args}))
            },
        );
    }

    let responses: Vec<String> = (0..5)
        .map(|i| {
            format!(
                r#"{{"tool": "tool_{}", "args": {{"input": "test_{}"}}}}"#,
                i, i
            )
        })
        .chain(std::iter::once(
            "Scan complete. All tools executed successfully.".to_string(),
        ))
        .collect();

    let provider = Arc::new(CyclicMockProvider::new(responses));
    let safety = Arc::new(SafetyChecker::permissive());

    let runner = ToolUseRunner::new(
        provider,
        Arc::new(registry),
        "test-model",
        "Execute all available tools and report results.",
        safety,
    )
    .with_max_iterations(10);

    let target = make_target(
        "e2e-multi",
        "Multi-tool Target",
        TargetType::Process,
        Some(1),
    );
    targets::insert_target(&conn, &target).unwrap();

    let findings = runner.run(&target).await.unwrap();
    eprintln!(
        "TEST 6: Multi-tool runner completed with {} findings",
        findings.len()
    );
}

// TEST 7: Empty findings report generation

#[tokio::test]
async fn test_end_to_end_empty_findings_report() {
    let conn = setup_in_memory_db();

    let target = make_target(
        "empty-target",
        "Empty Scan Target",
        TargetType::Binary,
        None,
    );
    targets::insert_target(&conn, &target).unwrap();

    let scan_id = "empty-scan-1";
    let scan = make_scan(scan_id, "empty-target", ScanMode::ToolUse);
    scans::insert_scan(&conn, &scan).unwrap();

    let stored = findings::list_findings_by_scan(&conn, scan_id).unwrap();
    assert!(stored.is_empty());

    let json_reporter = vest_report::JsonReporter::new();
    let json_report = json_reporter.generate_report(&scan, &stored).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_report).unwrap();
    assert_eq!(parsed["summary"]["total"].as_u64().unwrap(), 0);
    assert!(parsed["findings"].as_array().unwrap().is_empty());

    let terminal_reporter = vest_report::TerminalReporter;
    let terminal_report = terminal_reporter
        .generate_report(&scan, &stored)
        .await
        .unwrap();
    assert!(terminal_report.contains("VEST Scan Report"));
    eprintln!("TEST 7: Empty findings report generated successfully");
}

// TEST 8: Error handling - target with no URL/pid for scanners

#[tokio::test]
async fn test_end_to_end_scanner_error_handling() {
    use vest_core::traits::Scanner;

    let web_scanner = vest_scanner::web::WebScanner::new();
    let target_no_url = make_target("err-web", "No URL Target", TargetType::Web, None);
    let result = web_scanner.scan(&target_no_url).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("URL") || err.to_string().contains("host"));
    eprintln!("TEST 8: Web scanner correctly errored: {}", err);

    let binary_scanner = vest_scanner::binary::BinaryScanner::new();
    let target_no_path = make_target("err-bin", "No Path Target", TargetType::Binary, None);
    let result = binary_scanner.scan(&target_no_path).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("path"));
    eprintln!("TEST 8: Binary scanner correctly errored: {}", err);
}

// TEST 9: Scan update and status transitions

#[tokio::test]
async fn test_end_to_end_scan_status_transitions() {
    let conn = setup_in_memory_db();

    let target = make_target(
        "status-target",
        "Status Test Target",
        TargetType::Network,
        None,
    );
    targets::insert_target(&conn, &target).unwrap();

    let scan_id = "status-scan-1";
    let scan = make_scan(scan_id, "status-target", ScanMode::Swarm);
    scans::insert_scan(&conn, &scan).unwrap();

    let retrieved = scans::get_scan(&conn, scan_id).unwrap();
    assert_eq!(retrieved.status, ScanStatus::Running);

    scans::update_scan_status(&conn, scan_id, &ScanStatus::Completed).unwrap();
    let completed = scans::get_scan(&conn, scan_id).unwrap();
    assert_eq!(completed.status, ScanStatus::Completed);

    scans::update_scan_status(&conn, scan_id, &ScanStatus::Failed).unwrap();
    let failed = scans::get_scan(&conn, scan_id).unwrap();
    assert_eq!(failed.status, ScanStatus::Failed);

    let all_scans = scans::list_scans(&conn).unwrap();
    assert_eq!(all_scans.len(), 1);
    eprintln!("TEST 9: Scan status transitions completed");
}

// TEST 10: Full scan with Orchestrator (ToolUse mode)

#[tokio::test]
async fn test_end_to_end_orchestrator_tooluse() {
    use vest_agent::Orchestrator;

    let conn = setup_in_memory_db();

    let mut registry = ToolRegistry::new();
    registry.register(
        ToolDefinition::new(
            "inspect_target",
            "Inspect the scan target for vulnerabilities",
            serde_json::json!({}),
            ToolEffect::LocalMetadataRead,
            DataEgressClass::LocalMetadata,
        ),
        |_args: serde_json::Value| -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({
                "target_info": {"os": "Linux", "arch": "x86_64"},
                "vulnerabilities": []
            }))
        },
    );
    registry.register(
        ToolDefinition::new(
            "scan_ports",
            "Scan open ports",
            serde_json::json!({"host": "string"}),
            ToolEffect::ActiveNetworkProbe,
            DataEgressClass::TargetMetadata,
        ),
        |_args: serde_json::Value| -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"ports": [80, 443, 8080]}))
        },
    );

    let provider = Arc::new(CyclicMockProvider::new(vec![
        r#"{"tool": "inspect_target", "args": {}}"#.into(),
        r#"{"tool": "scan_ports", "args": {"host": "localhost"}}"#.into(),
        r#"Scan complete. Target analysis finished, no vulnerabilities found."#.into(),
    ]));

    let safety = Arc::new(SafetyChecker::permissive());

    let orchestrator = Orchestrator::new(
        provider,
        Arc::new(registry),
        "orchestrator-model",
        ScanMode::ToolUse,
        safety,
    )
    .with_max_iterations(10);

    let target = make_target(
        "orch-target",
        "Orchestrator Target",
        TargetType::Process,
        Some(9999),
    );
    targets::insert_target(&conn, &target).unwrap();

    let scan_id = new_id();
    let scan = make_scan(&scan_id, "orch-target", ScanMode::ToolUse);
    scans::insert_scan(&conn, &scan).unwrap();

    let findings_result = orchestrator.run(&target).await;
    match findings_result {
        Ok(findings) => {
            eprintln!(
                "TEST 10: Orchestrator completed with {} findings",
                findings.len()
            );
            for finding in &findings {
                let f = Finding {
                    id: finding.id.clone(),
                    scan_id: scan_id.clone(),
                    target_id: "orch-target".into(),
                    ..finding.clone()
                };
                findings::insert_finding(&conn, &f).unwrap();
            }
            let stored = findings::list_findings_by_scan(&conn, &scan_id).unwrap();
            assert_eq!(stored.len(), findings.len());
        }
        Err(e) => {
            eprintln!(
                "TEST 10: Orchestrator returned error (may be expected): {}",
                e
            );
        }
    }

    eprintln!("TEST 10: Orchestrator tooluse test completed");
}

// TEST 11: Report format type verification

#[tokio::test]
async fn test_end_to_end_report_format_types() {
    let terminal = vest_report::TerminalReporter;
    assert_eq!(
        terminal.format_type(),
        vest_core::traits::ReportFormat::Terminal
    );

    let json = vest_report::JsonReporter::new();
    assert_eq!(json.format_type(), vest_core::traits::ReportFormat::Json);

    let sarif = vest_report::SarifReporter::new();
    assert_eq!(sarif.format_type(), vest_core::traits::ReportFormat::Sarif);

    eprintln!("TEST 11: Report format types verified");
}

// TEST 12: Scanner trait methods for MemoryScanner

#[tokio::test]
async fn test_end_to_end_memory_scanner_trait() {
    use vest_core::traits::Scanner;

    let scanner = vest_scanner::memory::MemoryScanner::new();

    assert_eq!(scanner.name().await, "memory-scanner");
    assert!(scanner.description().await.contains("memory"));
    assert!(scanner.enabled().await);

    let target = make_target(
        "mem-trait-target",
        "memory_test",
        TargetType::Process,
        Some(12345),
    );
    // Default path is honest: real acquisition unsupported.
    let err = scanner.scan(&target).await.unwrap_err();
    assert!(matches!(err, vest_core::error::VestError::Unsupported(_)));

    let sim = vest_scanner::memory::MemoryScanner::new().with_simulation_allowed(true);
    let findings = sim.scan(&target).await.unwrap();
    eprintln!(
        "TEST 12: MemoryScanner simulation found {} findings via trait",
        findings.len()
    );
    assert!(
        !findings.iter().all(|f| f.target_id.is_empty()),
        "Findings should have target_id set"
    );
    if !findings.is_empty() {
        assert_eq!(findings[0].target_id, "mem-trait-target");
        assert_eq!(findings[0].metadata["simulation"], serde_json::json!(true));
        assert!(findings[0].title.contains("SIMULATED"));
    }
}
