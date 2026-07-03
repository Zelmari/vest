use async_trait::async_trait;
use vest_core::error::VestError;
use vest_core::traits::{ReportFormat, Reporter};
use vest_core::types::{Finding, ScanSession, Severity};

pub struct MarkdownReporter;

#[async_trait]
impl Reporter for MarkdownReporter {
    async fn generate_report(
        &self,
        scan: &ScanSession,
        findings: &[Finding],
    ) -> Result<String, VestError> {
        let (critical, high, medium, low, info) = count_by_severity(findings);

        let mut md = String::new();

        md.push_str("# VEST Scan Report\n\n");
        md.push_str(&format!("**Target:** {}\n\n", scan.target_id));
        md.push_str(&format!("**Scan ID:** {}\n\n", scan.id));
        md.push_str(&format!("**Mode:** {}\n\n", scan.mode));
        md.push_str(&format!(
            "**Model:** {}\n\n",
            scan.agent_model.as_deref().unwrap_or("N/A")
        ));
        md.push_str(&format!(
            "**Duration:** {}\n\n",
            format_duration(scan.duration_ms)
        ));

        md.push_str("## Summary\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!("| Critical | {} |\n", critical));
        md.push_str(&format!("| High     | {} |\n", high));
        md.push_str(&format!("| Medium   | {} |\n", medium));
        md.push_str(&format!("| Low      | {} |\n", low));
        md.push_str(&format!("| Info     | {} |\n", info));
        md.push_str(&format!("| **Total** | **{}** |\n\n", findings.len()));

        let mut sorted: Vec<&Finding> = findings.iter().collect();
        sorted.sort_by(|a, b| {
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        md.push_str("## Findings\n\n");

        for f in &sorted {
            let severity_icon = match f.severity {
                Severity::Critical => "\u{1f534}",
                Severity::High => "\u{1f7e0}",
                Severity::Medium => "\u{1f7e1}",
                Severity::Low => "\u{1f7e2}",
                Severity::Info => "\u{26aa}",
            };

            md.push_str(&format!(
                "### {} {} ({:?})\n\n",
                severity_icon, f.title, f.severity
            ));
            md.push_str(&format!(
                "**Vulnerability Class:** {}\n\n",
                f.vulnerability_class
            ));
            md.push_str(&format!("**Confidence:** {:.0}%\n\n", f.confidence * 100.0));

            if let Some(cvss) = f.cvss_score {
                md.push_str(&format!("**CVSS Score:** {:.1}\n\n", cvss));
            }
            if let Some(ref cwe) = f.cwe_id {
                md.push_str(&format!("**CWE:** {}\n\n", cwe));
            }
            if let Some(ref cve) = f.cve_id {
                md.push_str(&format!("**CVE:** {}\n\n", cve));
            }

            md.push_str(&format!("**Description:** {}\n\n", f.description));

            let evidence_str = serde_json::to_string_pretty(&f.evidence).unwrap_or_default();
            if evidence_str.len() > 4 {
                md.push_str(&format!(
                    "<details>\n<summary>Evidence</summary>\n\n```json\n{}\n```\n</details>\n\n",
                    evidence_str
                ));
            }

            if let Some(ref poc) = f.poc {
                md.push_str(&format!("**Proof of Concept:**\n\n```\n{}\n```\n\n", poc));
            }

            if let Some(ref remediation) = f.remediation {
                md.push_str(&format!("**Remediation:** {}\n\n", remediation));
            }

            md.push_str("---\n\n");
        }

        md.push_str(&format!(
            "\n*Report generated at {} by VEST*\n",
            chrono::Utc::now().to_rfc3339()
        ));
        Ok(md)
    }

    fn format_type(&self) -> ReportFormat {
        ReportFormat::Markdown
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn format_duration(ms: Option<i64>) -> String {
    match ms {
        Some(ms) => {
            let secs = ms / 1000;
            let mins = secs / 60;
            format!("{}m {}s", mins, secs % 60)
        }
        None => "N/A".into(),
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
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
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
            target_id: "game.exe".into(),
            mode: vest_core::types::ScanMode::Swarm,
            config: serde_json::json!({}),
            status: vest_core::types::ScanStatus::Completed,
            agent_model: Some("deepseek-v3".into()),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            duration_ms: Some(1800000),
            total_findings: 2,
            critical_count: 0,
            high_count: 2,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
        }
    }

    fn make_finding(severity: Severity, title: &str) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: "scan-1".into(),
            target_id: "target-1".into(),
            title: title.into(),
            description: "Test description".into(),
            vulnerability_class: vest_core::VulnerabilityClass::SQLInjection,
            severity,
            confidence: 0.88,
            status: vest_core::FindingStatus::Open,
            cvss_score: Some(9.8),
            cve_id: Some("CVE-2024-1234".into()),
            cwe_id: Some("CWE-89".into()),
            evidence: serde_json::json!({"payload": "1' OR 1=1"}),
            poc: Some("Submit ' OR 1=1--".into()),
            remediation: Some("Use parameterized queries".into()),
            location: serde_json::json!({"url": "/api/login"}),
            false_positive_history: None,
            tags: vec!["sqli".into()],
            metadata: serde_json::json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_markdown_report_generation() {
        let reporter = MarkdownReporter;
        let scan = make_scan();
        let findings = vec![
            make_finding(Severity::High, "SQL Injection in login"),
            make_finding(Severity::High, "XSS in search form"),
        ];

        let rt = tokio::runtime::Runtime::new().unwrap();
        let md = rt
            .block_on(reporter.generate_report(&scan, &findings))
            .unwrap();

        assert!(md.contains("# VEST Scan Report"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("## Findings"));
        assert!(md.contains("SQL Injection"));
        assert!(md.contains("CWE-89"));
        assert!(md.contains("parameterized queries"));
    }

    #[test]
    fn test_markdown_report_empty() {
        let reporter = MarkdownReporter;
        let scan = make_scan();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let md = rt.block_on(reporter.generate_report(&scan, &[])).unwrap();
        assert!(md.contains("**Total** | **0**"));
    }

    #[test]
    fn test_severity_icons_rendered() {
        let reporter = MarkdownReporter;
        let scan = make_scan();
        let findings = vec![
            make_finding(Severity::Critical, "Critical bug"),
            make_finding(Severity::Info, "Info note"),
        ];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let md = rt
            .block_on(reporter.generate_report(&scan, &findings))
            .unwrap();
        assert!(md.contains("\u{1f534}"));
    }
}
