//! SARIF 2.1.0 JSON reporter for CI / code-scanning consumers.

use crate::target::report_target;
use async_trait::async_trait;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use vest_core::error::VestError;
use vest_core::traits::{ReportFormat, Reporter};
use vest_core::types::{Finding, ScanSession, Severity};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json";

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invocations: Option<Vec<SarifInvocation>>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    short_description: Option<SarifMessage>,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u64,
}

#[derive(Serialize)]
struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    execution_successful: bool,
    #[serde(rename = "commandLine", skip_serializing_if = "Option::is_none")]
    command_line: Option<String>,
}

/// SARIF 2.1.0 report writer.
#[derive(Debug, Clone, Default)]
pub struct SarifReporter;

impl SarifReporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Reporter for SarifReporter {
    async fn generate_report(
        &self,
        scan: &ScanSession,
        findings: &[Finding],
    ) -> Result<String, VestError> {
        let mut rule_ids: BTreeSet<String> = BTreeSet::new();
        for f in findings {
            rule_ids.insert(f.vulnerability_class.to_string());
        }

        let rules: Vec<SarifRule> = rule_ids
            .into_iter()
            .map(|id| SarifRule {
                name: Some(id.clone()),
                short_description: Some(SarifMessage {
                    text: format!("Vest vulnerability class: {id}"),
                }),
                id,
            })
            .collect();

        let results: Vec<SarifResult> = findings.iter().map(finding_to_result).collect();
        let target = report_target(scan);

        let log = SarifLog {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Vest",
                        semantic_version: env!("CARGO_PKG_VERSION").to_string(),
                        rules,
                    },
                },
                results,
                invocations: Some(vec![SarifInvocation {
                    execution_successful: true,
                    command_line: Some(format!("vest scan {} (scan_id={})", target.name, scan.id)),
                }]),
            }],
        };

        serde_json::to_string_pretty(&log)
            .map_err(|e| VestError::Internal(format!("Failed to serialize SARIF report: {}", e)))
    }

    fn format_type(&self) -> ReportFormat {
        ReportFormat::Sarif
    }
}

fn finding_to_result(f: &Finding) -> SarifResult {
    let mut properties = BTreeMap::new();
    properties.insert("findingId".into(), serde_json::Value::String(f.id.clone()));
    properties.insert(
        "severity".into(),
        serde_json::Value::String(f.severity.to_string()),
    );
    properties.insert("confidence".into(), serde_json::json!(f.confidence));
    if let Some(cwe) = &f.cwe_id {
        properties.insert("cweId".into(), serde_json::Value::String(cwe.clone()));
    }
    if let Some(cve) = &f.cve_id {
        properties.insert("cveId".into(), serde_json::Value::String(cve.clone()));
    }

    SarifResult {
        rule_id: f.vulnerability_class.to_string(),
        level: severity_to_level(f.severity),
        message: SarifMessage {
            text: message_text(f),
        },
        locations: locations_from_finding(f),
        properties: Some(properties),
    }
}

fn message_text(f: &Finding) -> String {
    if f.description.is_empty() {
        f.title.clone()
    } else if f.title.is_empty() {
        f.description.clone()
    } else {
        format!("{}\n\n{}", f.title, f.description)
    }
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn locations_from_finding(f: &Finding) -> Vec<SarifLocation> {
    let uri = f
        .location
        .get("file")
        .and_then(|v| v.as_str())
        .or_else(|| f.location.get("url").and_then(|v| v.as_str()))
        .or_else(|| f.location.get("path").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string();

    let start_line = f
        .location
        .get("line")
        .and_then(|v| v.as_u64())
        .or_else(|| f.location.get("startLine").and_then(|v| v.as_u64()));

    vec![SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation { uri },
            region: start_line.map(|start_line| SarifRegion { start_line }),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use vest_core::types::{FindingStatus, ScanMode, ScanStatus, VulnerabilityClass};

    fn make_scan() -> ScanSession {
        ScanSession {
            id: "scan-sarif-1".into(),
            target_id: "target-1".into(),
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
                "target": {
                    "id": "target-1",
                    "name": "fixture.rs",
                    "type": "file"
                }
            }),
            created_at: chrono::Utc::now(),
        }
    }

    fn make_finding() -> Finding {
        Finding {
            id: "finding-1".into(),
            scan_id: "scan-sarif-1".into(),
            target_id: "target-1".into(),
            title: "Reflected XSS".into(),
            description: "User input reflected without encoding.".into(),
            vulnerability_class: VulnerabilityClass::XSS,
            severity: Severity::High,
            confidence: 0.9,
            status: FindingStatus::Open,
            severity_score_estimate: Some(7.5),
            cve_id: None,
            cwe_id: Some("CWE-79".into()),
            evidence: serde_json::json!({}),
            poc: None,
            remediation: Some("Encode output".into()),
            location: serde_json::json!({"file": "src/web.rs", "line": 42}),
            false_positive_history: None,
            tags: vec!["web".into()],
            metadata: serde_json::json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_sarif_report_validates_required_keys() {
        let reporter = SarifReporter::new();
        let scan = make_scan();
        let findings = vec![make_finding()];

        let rt = tokio::runtime::Runtime::new().unwrap();
        let sarif = rt
            .block_on(reporter.generate_report(&scan, &findings))
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF must be JSON");

        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed.get("$schema").is_some(), "missing $schema");
        assert!(parsed.get("runs").is_some(), "missing runs");

        let runs = parsed["runs"].as_array().expect("runs must be array");
        assert!(!runs.is_empty());

        let run = &runs[0];
        assert!(run.get("tool").is_some(), "missing tool");
        assert!(run["tool"].get("driver").is_some(), "missing tool.driver");
        assert_eq!(run["tool"]["driver"]["name"], "Vest");
        assert!(run.get("results").is_some(), "missing results");

        let results = run["results"].as_array().expect("results must be array");
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result["ruleId"], "xss");
        assert_eq!(result["level"], "error");
        assert!(result.get("message").is_some(), "missing message");
        let text = result["message"]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("Reflected XSS"),
            "message should include title"
        );
        assert!(
            text.contains("User input reflected"),
            "message should include description"
        );

        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("driver.rules must be array");
        assert!(
            rules.iter().any(|r| r["id"] == "xss"),
            "rules should include vuln class"
        );
    }

    #[test]
    fn test_severity_to_level_mapping() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "note");
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    #[test]
    fn test_format_type_is_sarif() {
        assert_eq!(SarifReporter::new().format_type(), ReportFormat::Sarif);
    }
}
