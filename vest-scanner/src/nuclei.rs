//! First-class nuclei scanner wrapping [`vest_tools::NucleiTool`].

use async_trait::async_trait;
use std::path::PathBuf;
use std::time::Duration;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, TargetType, VulnerabilityClass};
use vest_core::Scanner;
use vest_tools::NucleiTool;

#[derive(Debug, Clone)]
pub struct NucleiScanner {
    enabled: bool,
    timeout: Duration,
    severity_filter: Vec<String>,
    allow_active_probes: bool,
    /// Optional override for tests (fake binary).
    binary_override: Option<PathBuf>,
    templates_root_override: Option<PathBuf>,
}

impl NucleiScanner {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_secs(300),
            severity_filter: vec!["critical".into(), "high".into(), "medium".into()],
            allow_active_probes: false,
            binary_override: None,
            templates_root_override: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_severity_filter(mut self, severities: Vec<String>) -> Self {
        self.severity_filter = severities;
        self
    }

    pub fn with_allow_active_probes(mut self, allow: bool) -> Self {
        self.allow_active_probes = allow;
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Test / advanced: force a specific nuclei binary path.
    pub fn with_binary(mut self, path: PathBuf) -> Self {
        self.binary_override = Some(path);
        self
    }

    pub fn with_templates_root(mut self, root: PathBuf) -> Self {
        self.templates_root_override = Some(root);
        self
    }

    fn build_tool(&self) -> Result<NucleiTool, VestError> {
        let mut tool = if let Some(ref bin) = self.binary_override {
            NucleiTool::with_binary(bin.clone())
        } else {
            NucleiTool::new().ok_or_else(|| {
                VestError::Scan(
                    "nuclei binary not found. Install with `vest tools install nuclei` \
                     or place it at ~/.vest/tools/nuclei"
                        .into(),
                )
            })?
        };
        tool = tool
            .with_timeout(self.timeout)
            .with_severity_filter(self.severity_filter.clone());
        if let Some(ref root) = self.templates_root_override {
            tool = tool.with_templates_root(root.clone());
        }
        Ok(tool)
    }
}

impl Default for NucleiScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn nuclei_finding_to_finding(nf: &vest_tools::NucleiFinding, target: &Target) -> Finding {
    let now = chrono::Utc::now();
    Finding {
        id: new_id(),
        scan_id: String::new(),
        target_id: target.id.clone(),
        title: nf.name.clone(),
        description: nf
            .description
            .clone()
            .unwrap_or_else(|| format!("Nuclei template {}", nf.template_id)),
        vulnerability_class: VulnerabilityClass::Unknown,
        severity: parse_severity(&nf.severity),
        confidence: 0.7,
        status: FindingStatus::Open,
        severity_score_estimate: None,
        cve_id: None,
        cwe_id: None,
        evidence: serde_json::json!({
            "template_id": nf.template_id,
            "matched_at": nf.matched_at,
            "nuclei_severity": nf.severity,
        }),
        poc: None,
        remediation: None,
        location: serde_json::json!({
            "url": nf.matched_at,
            "template_id": nf.template_id,
        }),
        false_positive_history: None,
        tags: vec!["scanner:nuclei".into(), "nuclei".into()],
        metadata: serde_json::json!({
            "scanner": "nuclei",
            "template_id": nf.template_id,
        }),
        discovered_at: now,
        updated_at: now,
    }
}

#[async_trait]
impl Scanner for NucleiScanner {
    async fn name(&self) -> &str {
        "nuclei"
    }

    async fn description(&self) -> &str {
        "Template-based active web scanner (ProjectDiscovery nuclei)"
    }

    async fn enabled(&self) -> bool {
        self.enabled
    }

    async fn scan(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !matches!(target.target_type, TargetType::Web | TargetType::Browser) {
            return Err(VestError::InvalidInput(
                "nuclei scanner requires a web (or browser) target with a URL".into(),
            ));
        }
        let url = target
            .url_str
            .as_deref()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| VestError::InvalidInput("nuclei scanner requires target URL".into()))?;

        if !self.allow_active_probes {
            return Err(VestError::ApprovalDenied(
                "nuclei is active probing; enable with --allow-active-probes and \
                 --confirm-active-probes (or --approve-exploits)"
                    .into(),
            ));
        }

        let tool = self.build_tool()?;
        let raw = tool
            .scan_url_with_all_templates(url)
            .map_err(|e| VestError::Scan(format!("nuclei failed: {e}")))?;
        Ok(raw
            .iter()
            .map(|nf| nuclei_finding_to_finding(nf, target))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vest_tools::NucleiFinding;

    fn web_target() -> Target {
        Target {
            id: "t1".into(),
            name: "example".into(),
            target_type: TargetType::Web,
            path: None,
            url_str: Some("http://example.com".into()),
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn maps_nuclei_finding_fields() {
        let nf = NucleiFinding {
            template_id: "cve-1".into(),
            name: "Demo".into(),
            severity: "high".into(),
            matched_at: "http://example.com/x".into(),
            description: Some("desc".into()),
        };
        let f = nuclei_finding_to_finding(&nf, &web_target());
        assert_eq!(f.title, "Demo");
        assert_eq!(f.severity, Severity::High);
        assert!(f.tags.iter().any(|t| t == "scanner:nuclei"));
        assert_eq!(f.evidence["template_id"], "cve-1");
    }

    #[tokio::test]
    async fn denies_without_active_probe_consent() {
        let scanner = NucleiScanner::new().with_allow_active_probes(false);
        let err = scanner.scan(&web_target()).await.unwrap_err();
        assert!(matches!(err, VestError::ApprovalDenied(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_binary_produces_findings() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "vest-nuclei-scanner-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fake-nuclei");
        fs::write(
            &bin,
            r#"#!/bin/sh
echo '{"templateID":"t1","name":"N1","severity":"medium","matchedAt":"http://example.com"}'
exit 0
"#,
        )
        .unwrap();
        let mut perms = fs::metadata(&bin).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin, perms).unwrap();

        let scanner = NucleiScanner::new()
            .with_allow_active_probes(true)
            .with_binary(bin)
            .with_templates_root(dir.clone())
            .with_timeout(Duration::from_secs(5));
        let findings = scanner.scan(&web_target()).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "N1");
        let _ = fs::remove_dir_all(&dir);
    }
}
