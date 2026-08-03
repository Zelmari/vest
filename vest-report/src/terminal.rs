use crate::target::target_display;
use async_trait::async_trait;
use vest_core::error::VestError;
use vest_core::traits::{ReportFormat, Reporter};
use vest_core::types::{Finding, ScanSession, Severity};

pub struct TerminalReporter;

#[async_trait]
impl Reporter for TerminalReporter {
    async fn generate_report(
        &self,
        scan: &ScanSession,
        findings: &[Finding],
    ) -> Result<String, VestError> {
        let (critical, high, medium, low, info) = count_by_severity(findings);

        let mut output = String::new();

        let width = 63;
        let border = "\u{2500}".repeat(width);
        output.push_str(&format!("\u{250c}{}\u{2510}\n", border));
        output.push_str(&format!("\u{2502} {:^63} \u{2502}\n", "VEST Scan Report"));
        output.push_str(&format!(
            "\u{2502}  Target: {:<54} \u{2502}\n",
            truncate(&target_display(scan), 54)
        ));
        output.push_str(&format!(
            "\u{2502}  Duration: {:<49} \u{2502}\n",
            format_duration(scan.duration_ms)
        ));
        output.push_str(&format!(
            "\u{2502}  Mode: {} | Model: {:<44} \u{2502}\n",
            scan.mode,
            truncate(scan.agent_model.as_deref().unwrap_or("N/A"), 44)
        ));
        output.push_str(&format!("\u{251c}{}\u{2524}\n", border));

        output.push_str(&format!("\u{2502} {:^63} \u{2502}\n", "SUMMARY"));
        output.push_str(&format!(
            "\u{2502} {:<63} \u{2502}\n",
            "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
        ));
        output.push_str(&format!(
            "\u{2502}  Critical: {:>3}   {:<42} \u{2502}\n",
            critical,
            severity_bar(critical, 42)
        ));
        output.push_str(&format!(
            "\u{2502}  High:     {:>3}   {:<42} \u{2502}\n",
            high,
            severity_bar(high, 42)
        ));
        output.push_str(&format!(
            "\u{2502}  Medium:   {:>3}   {:<42} \u{2502}\n",
            medium,
            severity_bar(medium, 42)
        ));
        output.push_str(&format!(
            "\u{2502}  Low:      {:>3}   {:<42} \u{2502}\n",
            low,
            severity_bar(low, 42)
        ));
        output.push_str(&format!(
            "\u{2502}  Info:     {:>3}   {:<42} \u{2502}\n",
            info,
            severity_bar(info, 42)
        ));

        output.push_str(&format!("\u{251c}{}\u{2524}\n", border));
        output.push_str(&format!("\u{2502} {:^63} \u{2502}\n", "TOP FINDINGS"));
        output.push_str(&format!(
            "\u{2502} {:<63} \u{2502}\n",
            "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
        ));

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

        for f in sorted.iter().take(10) {
            let severity_tag = format!("[{:^8}]", f.severity.to_string().to_uppercase());
            let score_est = f
                .severity_score_estimate
                .map(|c| format!("est {:.1}", c))
                .unwrap_or_default();

            output.push_str(&format!(
                "\u{2502}  {} {} | {:<30} \u{2502}\n",
                severity_tag,
                score_est,
                truncate(&f.title, 30)
            ));

            let loc = if let Some(file) = f.location.get("file").and_then(|v| v.as_str()) {
                file.to_string()
            } else if let Some(url) = f.location.get("url").and_then(|v| v.as_str()) {
                url.to_string()
            } else {
                String::new()
            };
            if !loc.is_empty() {
                output.push_str(&format!(
                    "\u{2502}    {:<59} \u{2502}\n",
                    truncate(&loc, 59)
                ));
            }

            if let Some(source) = f.metadata.get("source").and_then(|value| value.as_str()) {
                output.push_str(&format!(
                    "\u{2502}    source: {:<51} \u{2502}\n",
                    truncate(source, 51)
                ));
            }
        }

        output.push_str(&format!("\u{2514}{}\u{2518}\n", border));
        Ok(output)
    }

    fn format_type(&self) -> ReportFormat {
        ReportFormat::Terminal
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    let end = s
        .char_indices()
        .take(max_len)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    if end >= s.len() {
        s.to_string()
    } else {
        format!("{}...", &s[..end.saturating_sub(3)])
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

fn severity_bar(count: usize, width: usize) -> String {
    let n = (count * width / 20).min(width);
    "\u{2588}".repeat(n)
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
            target_id: "target-1".into(),
            mode: vest_core::types::ScanMode::Pipeline,
            config: serde_json::json!({}),
            status: vest_core::types::ScanStatus::Completed,
            agent_model: Some("claude-sonnet-4".into()),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            duration_ms: Some(2712000),
            total_findings: 3,
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
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
            description: "desc".into(),
            vulnerability_class: vest_core::VulnerabilityClass::BufferOverflow,
            severity,
            confidence: 0.9,
            status: vest_core::FindingStatus::Open,
            severity_score_estimate: Some(7.5),
            cve_id: None,
            cwe_id: Some("CWE-120".into()),
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({"file": "game.exe+0xDEAD"}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_terminal_report_generation() {
        let reporter = TerminalReporter;
        let scan = make_scan();
        let findings = vec![
            make_finding(Severity::Critical, "Buffer Overflow in packet handler"),
            make_finding(Severity::High, "Auth bypass in login form"),
            make_finding(Severity::Medium, "Missing security headers"),
        ];

        let rt = tokio::runtime::Runtime::new().unwrap();
        let output = rt
            .block_on(reporter.generate_report(&scan, &findings))
            .unwrap();

        assert!(output.contains("VEST Scan Report"));
        assert!(output.contains("Critical"));
        assert!(output.contains("Buffer Overflow"));
        assert!(output.contains("Auth bypass"));
        assert!(output.contains("est 7.5"));
        assert!(
            !output.to_uppercase().contains("CVSS"),
            "heuristic scores must not be labelled CVSS: {output}"
        );
    }

    #[test]
    fn test_severity_rank_ordering() {
        assert!(severity_rank(Severity::Critical) > severity_rank(Severity::High));
        assert!(severity_rank(Severity::High) > severity_rank(Severity::Medium));
        assert!(severity_rank(Severity::Info) < severity_rank(Severity::Low));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Some(65000)), "1m 5s");
        assert_eq!(format_duration(Some(3600000)), "60m 0s");
        assert_eq!(format_duration(None), "N/A");
    }

    #[test]
    fn test_terminal_report_uses_target_metadata() {
        let reporter = TerminalReporter;
        let mut scan = make_scan();
        scan.metadata = serde_json::json!({
            "target": {
                "name": "fixture.txt",
                "type": "file"
            }
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let output = rt.block_on(reporter.generate_report(&scan, &[])).unwrap();
        assert!(output.contains("fixture.txt (file)"));
    }
}
