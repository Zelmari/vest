use async_trait::async_trait;
use serde::Serialize;
use vest_core::error::VestError;
use vest_core::traits::{ReportFormat, Reporter};
use vest_core::types::{Finding, ScanSession};

#[derive(Serialize)]
struct JsonReport {
    version: String,
    generated_at: String,
    scan_id: String,
    target: JsonTarget,
    scan_config: JsonScanConfig,
    summary: JsonSummary,
    findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
struct JsonTarget {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct JsonScanConfig {
    mode: String,
    duration_ms: Option<i64>,
    token_usage: Option<u64>,
}

#[derive(Serialize)]
struct JsonSummary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Serialize)]
struct JsonFinding {
    id: String,
    title: String,
    description: String,
    vulnerability_class: String,
    severity: String,
    confidence: f64,
    cvss_score: Option<f64>,
    cwe_id: Option<String>,
    cve_id: Option<String>,
    evidence: serde_json::Value,
    location: serde_json::Value,
    poc: Option<String>,
    remediation: Option<String>,
}

pub struct JsonReporter;

#[async_trait]
impl Reporter for JsonReporter {
    async fn generate_report(
        &self,
        scan: &ScanSession,
        findings: &[Finding],
    ) -> Result<String, VestError> {
        let (critical, high, medium, low, info) = count_by_severity(findings);

        let report = JsonReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            scan_id: scan.id.clone(),
            target: JsonTarget {
                id: scan.target_id.clone(),
                name: scan.target_id.clone(),
            },
            scan_config: JsonScanConfig {
                mode: scan.mode.to_string(),
                duration_ms: scan.duration_ms,
                token_usage: None,
            },
            summary: JsonSummary {
                total: findings.len(),
                critical,
                high,
                medium,
                low,
                info,
            },
            findings: findings
                .iter()
                .map(|f| JsonFinding {
                    id: f.id.clone(),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    vulnerability_class: f.vulnerability_class.to_string(),
                    severity: f.severity.to_string(),
                    confidence: f.confidence,
                    cvss_score: f.cvss_score,
                    cwe_id: f.cwe_id.clone(),
                    cve_id: f.cve_id.clone(),
                    evidence: f.evidence.clone(),
                    location: f.location.clone(),
                    poc: f.poc.clone(),
                    remediation: f.remediation.clone(),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&report)
            .map_err(|e| VestError::Internal(format!("Failed to serialize JSON report: {}", e)))
    }

    fn format_type(&self) -> ReportFormat {
        ReportFormat::Json
    }
}

fn count_by_severity(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    for f in findings {
        match f.severity {
            vest_core::Severity::Critical => critical += 1,
            vest_core::Severity::High => high += 1,
            vest_core::Severity::Medium => medium += 1,
            vest_core::Severity::Low => low += 1,
            vest_core::Severity::Info => info += 1,
        }
    }
    (critical, high, medium, low, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scan() -> ScanSession {
        ScanSession {
            id: "scan-1".into(),
            target_id: "target-1".into(),
            mode: vest_core::types::ScanMode::Pipeline,
            config: serde_json::json!({}),
            status: vest_core::types::ScanStatus::Completed,
            agent_model: Some("gpt-4o".into()),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            duration_ms: Some(3600000),
            total_findings: 2,
            critical_count: 1,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
        }
    }

    fn make_finding(
        severity: vest_core::Severity,
        vuln_class: vest_core::VulnerabilityClass,
    ) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: "scan-1".into(),
            target_id: "target-1".into(),
            title: format!("{} vulnerability", vuln_class.to_string()),
            description: "Test description".into(),
            vulnerability_class: vuln_class,
            severity,
            confidence: 0.9,
            status: vest_core::types::FindingStatus::Open,
            cvss_score: Some(8.5),
            cve_id: None,
            cwe_id: Some("CWE-79".into()),
            evidence: serde_json::json!({"test": true}),
            poc: None,
            remediation: Some("Fix it".into()),
            location: serde_json::json!({"file": "test.rs"}),
            false_positive_history: None,
            tags: vec!["test".into()],
            metadata: serde_json::json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_json_report_generation() {
        let reporter = JsonReporter;
        let scan = make_scan();
        let findings = vec![
            make_finding(
                vest_core::Severity::Critical,
                vest_core::VulnerabilityClass::BufferOverflow,
            ),
            make_finding(
                vest_core::Severity::High,
                vest_core::VulnerabilityClass::XSS,
            ),
        ];

        let rt = tokio::runtime::Runtime::new().unwrap();
        let json = rt
            .block_on(reporter.generate_report(&scan, &findings))
            .unwrap();

        assert!(json.contains("\"version\""));
        assert!(json.contains("\"scan_id\""));
        assert!(json.contains("\"critical\""));
        assert!(json.contains("\"buffer_overflow\""));
        assert!(json.contains("\"xss\""));

        let _parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_json_report_empty_findings() {
        let reporter = JsonReporter;
        let scan = make_scan();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let json = rt.block_on(reporter.generate_report(&scan, &[])).unwrap();
        assert!(json.contains("\"total\": 0"));
    }
}
