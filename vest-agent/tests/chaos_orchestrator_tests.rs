use vest_core::traits::AgentStatus;
use vest_core::types::*;

#[test]
fn test_orchestrator_handles_all_scan_modes() {
    let modes = vec![
        ScanMode::Pipeline,
        ScanMode::Swarm,
        ScanMode::ToolUse,
        ScanMode::Hierarchical,
    ];
    for mode in &modes {
        let s = mode.to_string();
        let parsed: ScanMode = s.parse().unwrap();
        assert_eq!(parsed, *mode);
    }
}

#[test]
fn test_scan_mode_display_matches_config() {
    assert_eq!(ScanMode::ToolUse.to_string(), "tool-use");
    assert_eq!(ScanMode::Pipeline.to_string(), "pipeline");
    assert_eq!(ScanMode::Swarm.to_string(), "swarm");
    assert_eq!(ScanMode::Hierarchical.to_string(), "hierarchical");
}

#[test]
fn test_all_agent_status_variants() {
    let statuses = [
        AgentStatus::Idle,
        AgentStatus::Running,
        AgentStatus::Completed,
        AgentStatus::Failed,
        AgentStatus::Stopped,
    ];
    for i in 0..statuses.len() {
        for j in 0..statuses.len() {
            if i != j {
                assert_ne!(statuses[i], statuses[j]);
            }
        }
    }
}

#[test]
fn test_pipeline_phase_count() {
    use vest_agent::patterns::pipeline::PipelinePhase;

    let with_exploit = PipelinePhase::phases(true);
    assert_eq!(with_exploit.len(), 6);
    assert!(with_exploit.contains(&PipelinePhase::Exploitation));

    let without_exploit = PipelinePhase::phases(false);
    assert_eq!(without_exploit.len(), 5);
    assert!(!without_exploit.contains(&PipelinePhase::Exploitation));
}

#[test]
fn test_swarm_agent_configs_are_distinct() {
    use vest_agent::patterns::swarm::SwarmAgentConfig;

    let memory = SwarmAgentConfig::memory_hunter();
    let web = SwarmAgentConfig::web_hunter();
    let binary = SwarmAgentConfig::binary_hunter();
    let auth = SwarmAgentConfig::auth_logic_hunter();

    let names = [memory.name, web.name, binary.name, auth.name];
    let dedup: std::collections::HashSet<&String> = names.iter().collect();
    assert_eq!(dedup.len(), 4, "All agents should have unique names");

    assert!(memory
        .vulnerability_classes
        .contains(&"buffer_overflow".to_string()));
    assert!(web.vulnerability_classes.contains(&"xss".to_string()));
    assert!(binary
        .vulnerability_classes
        .contains(&"rop_gadget".to_string()));
    assert!(auth
        .vulnerability_classes
        .contains(&"auth_bypass".to_string()));
}

#[test]
fn test_merge_strategy_all_variants() {
    let strategies = [
        MergeStrategy::Voting,
        MergeStrategy::Union,
        MergeStrategy::Strict,
    ];
    for s in &strategies {
        let display = s.to_string();
        let parsed: MergeStrategy = display.parse().unwrap();
        assert_eq!(parsed, *s);
    }
}

#[test]
fn test_validator_heuristic_all_severities() {
    use vest_agent::validator::Validator;

    let validator = Validator::new();

    let test_cases = vec![
        (Severity::Critical, 0.95),
        (Severity::Critical, 0.4),
        (Severity::High, 0.9),
        (Severity::Medium, 0.2),
        (Severity::Low, 0.05),
        (Severity::Info, 0.5),
    ];

    let now = chrono::Utc::now();
    for (severity, confidence) in &test_cases {
        let finding = Finding {
            id: "test".into(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: "Test".into(),
            description: "".into(),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: *severity,
            confidence: *confidence,
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

        let (result, _enriched) = validator.heuristic_validate(&finding);
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }
}

#[test]
fn test_planner_all_target_types() {
    use vest_agent::planner::Planner;

    let planner = Planner::new();
    let types = [
        TargetType::Web,
        TargetType::Binary,
        TargetType::Process,
        TargetType::Network,
        TargetType::Browser,
        TargetType::File,
    ];

    for t in &types {
        let target = Target {
            id: "t1".into(),
            name: "test".into(),
            target_type: *t,
            path: Some("test".into()),
            url_str: Some("https://test.com".into()),
            pid: Some(12345),
            host: Some("localhost".into()),
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let plan = planner.rule_based_plan(&target);
        assert!(!plan.is_empty(), "No plan for type {:?}", t);
    }
}
