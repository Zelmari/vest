//! Model-egress boundary — action allow ≠ data leave.

use serde_json::json;
use vest_agent::{
    build_provider_finding_dto, filter_for_model, ApprovedFilesystemScope, AuthorisationContext,
    PolicyEngine, ToolDefinition, ToolRegistry,
};
use vest_core::types::{Finding, FindingStatus, Severity, VulnerabilityClass};
use vest_core::{DataEgressClass, ToolEffect};

#[test]
fn local_file_content_blocked_from_model_by_default() {
    let mut registry = ToolRegistry::new();
    registry.register(
        ToolDefinition::new(
            "read_file",
            "read",
            serde_json::json!({}),
            ToolEffect::LocalFileContentRead,
            DataEgressClass::LocalContent,
        ),
        |_| {
            Ok(serde_json::json!({
                "path": "/tmp/x",
                "content": "password = super-secret-value",
                "size": 32
            }))
        },
    );

    let root = std::env::temp_dir().join(format!(
        "vest-egress-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("x"), "password = super-secret-value").unwrap();
    let fs = ApprovedFilesystemScope::new([root.clone()]).unwrap();
    let mut ctx = AuthorisationContext::permissive_for_tests("egress");
    ctx.filesystem = fs;
    ctx.allow_local_content_egress = false;

    let policy = PolicyEngine::new();
    let out = registry
        .invoke(
            &policy,
            &ctx,
            "read_file",
            serde_json::json!({"path": root.join("x").to_string_lossy()}),
        )
        .unwrap();

    assert_eq!(out["egress_denied"], true);
    let s = out.to_string();
    assert!(
        !s.contains("super-secret-value"),
        "local content must not reach model context: {s}"
    );
}

#[test]
fn process_memory_blocked_from_model_by_default() {
    let ctx = AuthorisationContext::new("mem");
    let raw = serde_json::json!({"bytes": "SHELLCODE_DEADBEEF"});
    let filtered = filter_for_model(&raw, DataEgressClass::ProcessMemory, &ctx).unwrap();
    assert_eq!(filtered["egress_denied"], true);
    assert!(!filtered.to_string().contains("SHELLCODE"));
}

#[test]
fn credential_material_hard_errors() {
    let ctx = AuthorisationContext::permissive();
    let err = filter_for_model(
        &serde_json::json!({"key": "sk-abc"}),
        DataEgressClass::CredentialMaterial,
        &ctx,
    )
    .unwrap_err();
    let lower = err.to_lowercase();
    assert!(
        lower.contains("credential") || lower.contains("prohibited") || lower.contains("egress"),
        "{err}"
    );
}

#[test]
fn known_secrets_redacted_from_allowed_egress() {
    let mut ctx = AuthorisationContext::permissive();
    ctx.known_secrets = vec!["SUPERSECRETTOKEN12345".into()];
    let filtered = filter_for_model(
        &serde_json::json!({"note": "token=SUPERSECRETTOKEN12345"}),
        DataEgressClass::PublicNonSensitive,
        &ctx,
    )
    .unwrap();
    let s = filtered.to_string();
    assert!(!s.contains("SUPERSECRETTOKEN12345"), "{s}");
    assert!(s.contains("REDACTED") || s.contains("redacted"), "{s}");
}

#[test]
fn finding_dto_omits_raw_evidence_by_default() {
    let finding = Finding {
        id: "f1".into(),
        scan_id: "s1".into(),
        target_id: "t1".into(),
        title: "Hardcoded password".into(),
        description: "found".into(),
        vulnerability_class: VulnerabilityClass::HardcodedCredentials,
        severity: Severity::High,
        confidence: 0.9,
        status: FindingStatus::Open,
        cvss_score: None,
        cve_id: None,
        cwe_id: None,
        evidence: json!({"password": "literal-secret-should-not-egress"}),
        poc: None,
        remediation: None,
        location: json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: json!({}),
        discovered_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let dto = build_provider_finding_dto(&finding, false);
    let s = serde_json::to_string(&dto).unwrap();
    assert!(
        !s.contains("literal-secret-should-not-egress"),
        "raw evidence must stay local by default: {s}"
    );
}
