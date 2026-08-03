//! REP-2: untrusted PoC/evidence must not break markdown code fences.

use vest_core::traits::Reporter;
use vest_core::types::{
    Finding, FindingStatus, ScanMode, ScanSession, ScanStatus, Severity, VulnerabilityClass,
};
use vest_report::MarkdownReporter;

fn make_scan() -> ScanSession {
    ScanSession {
        id: "rep2-scan".into(),
        target_id: "rep2-target".into(),
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
            "target": { "name": "fixture.txt", "type": "file" }
        }),
        created_at: chrono::Utc::now(),
    }
}

fn fence_breakout_finding() -> Finding {
    Finding {
        id: "rep2-finding".into(),
        scan_id: "rep2-scan".into(),
        target_id: "rep2-target".into(),
        title: "Fence breakout finding".into(),
        description: "Untrusted finding text with fence markers".into(),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: Severity::High,
        confidence: 0.9,
        status: FindingStatus::Open,
        cvss_score: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({
            "payload": "```\n# injected heading\n```",
            "note": "ends with ```"
        }),
        poc: Some(
            "legit step\n```\n# injected after breakout\n<script>alert(1)</script>\n```\nmore"
                .into(),
        ),
        remediation: None,
        location: serde_json::json!({}),
        false_positive_history: None,
        tags: vec![],
        metadata: serde_json::json!({}),
        discovered_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn markdown_escapes_fence_breakouts_in_poc_and_evidence() {
    let md = MarkdownReporter::new()
        .include_evidence(true)
        .generate_report(&make_scan(), &[fence_breakout_finding()])
        .await
        .unwrap();

    assert!(md.contains("<summary>Evidence</summary>"));
    assert!(md.contains("**Proof of Concept:**"));

    // Untrusted body must not contain a raw triple-backtick sequence.
    let evidence_start = md.find("```json\n").expect("evidence fence open") + "```json\n".len();
    let evidence_end = md[evidence_start..]
        .find("\n```\n")
        .expect("evidence fence close")
        + evidence_start;
    let evidence_body = &md[evidence_start..evidence_end];
    assert!(
        !evidence_body.contains("```"),
        "evidence body still contains raw fence: {evidence_body}"
    );
    assert!(
        evidence_body.contains("`\u{200b}`\u{200b}`"),
        "evidence body missing neutralized fence marker"
    );

    let poc_marker = "**Proof of Concept:**\n\n```\n";
    let poc_start = md.find(poc_marker).expect("poc fence open") + poc_marker.len();
    let poc_end = md[poc_start..].find("\n```\n").expect("poc fence close") + poc_start;
    let poc_body = &md[poc_start..poc_end];
    assert!(
        !poc_body.contains("```"),
        "poc body still contains raw fence: {poc_body}"
    );
    assert!(
        poc_body.contains("`\u{200b}`\u{200b}`"),
        "poc body missing neutralized fence marker"
    );
    // Injected heading remains inside the PoC fence body (not after a closed fence).
    assert!(poc_body.contains("# injected after breakout"));
}
