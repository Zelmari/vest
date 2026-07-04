use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Deserialize, Clone)]
pub struct NucleiFinding {
    #[serde(rename = "templateID", alias = "template-id")]
    pub template_id: String,
    pub name: String,
    pub severity: String,
    #[serde(rename = "matchedAt", alias = "matched-at")]
    pub matched_at: String,
    pub description: Option<String>,
}

impl std::fmt::Display for NucleiFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} — {} (matched at: {})",
            self.severity.to_uppercase(),
            self.template_id,
            self.name,
            self.matched_at
        )?;
        if let Some(ref desc) = self.description {
            if !desc.is_empty() {
                write!(f, " — {}", desc)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NucleiTool {
    binary_path: PathBuf,
}

impl NucleiTool {
    pub fn new() -> Option<Self> {
        Self::find_binary().map(|binary_path| Self { binary_path })
    }

    pub fn check_installed() -> bool {
        Self::find_binary().is_some()
    }

    fn find_binary() -> Option<PathBuf> {
        if let Ok(home) = std::env::var("HOME") {
            let path = PathBuf::from(&home).join(".vest/tools/nuclei");
            if path.exists() {
                return Some(path);
            }
        }

        let local = PathBuf::from("./nuclei-templates/nuclei");
        if local.exists() {
            return Some(local);
        }

        if Command::new("nuclei").arg("-version").output().is_ok() {
            return Some(PathBuf::from("nuclei"));
        }

        None
    }

    pub fn scan_url(
        &self,
        url: &str,
        templates: &[&str],
    ) -> Result<Vec<NucleiFinding>, NucleiError> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-u").arg(url).arg("-json").arg("-silent");

        if !templates.is_empty() {
            cmd.arg("-t").arg(templates.join(","));
        }

        let output = cmd
            .output()
            .map_err(|e| NucleiError::ExecutionError(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(finding) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    pub fn scan_url_with_all_templates(
        &self,
        url: &str,
    ) -> Result<Vec<NucleiFinding>, NucleiError> {
        self.scan_url(url, &[])
    }

    pub fn version(&self) -> Result<String, NucleiError> {
        let output = Command::new(&self.binary_path)
            .arg("-version")
            .output()
            .map_err(|e| NucleiError::ExecutionError(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", stdout.trim(), stderr.trim());

        Ok(combined.lines().next().unwrap_or("").to_string())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NucleiError {
    #[error("execution error: {0}")]
    ExecutionError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nuclei_finding_deserialize_v2_kebab_case() {
        let json = r#"{"template-id":"http-missing-security-headers","name":"Missing Security Headers","severity":"info","matched-at":"http://example.com","description":"Some missing headers"}"#;
        let finding: NucleiFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.template_id, "http-missing-security-headers");
        assert_eq!(finding.name, "Missing Security Headers");
        assert_eq!(finding.severity, "info");
        assert_eq!(finding.matched_at, "http://example.com");
        assert_eq!(finding.description, Some("Some missing headers".into()));
    }

    #[test]
    fn test_nuclei_finding_deserialize_v3_camel_case() {
        let json = r#"{"templateID":"xss-reflected","name":"Reflected XSS","severity":"medium","matchedAt":"http://example.com/search?q=test","description":null}"#;
        let finding: NucleiFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.template_id, "xss-reflected");
        assert_eq!(finding.name, "Reflected XSS");
        assert_eq!(finding.severity, "medium");
        assert_eq!(finding.matched_at, "http://example.com/search?q=test");
        assert!(finding.description.is_none());
    }

    #[test]
    fn test_nuclei_finding_deserialize_minimal() {
        let json = r#"{"templateID":"cve-2021-44228","name":"Log4j RCE","severity":"critical","matchedAt":"http://target.com"}"#;
        let finding: NucleiFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.template_id, "cve-2021-44228");
        assert_eq!(finding.severity, "critical");
        assert!(finding.description.is_none());
    }

    #[test]
    fn test_nuclei_finding_deserialize_invalid_json() {
        let json = r#"not json"#;
        let result = serde_json::from_str::<NucleiFinding>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_nuclei_finding_deserialize_missing_required_fields() {
        let json = r#"{"name":"test"}"#;
        let result = serde_json::from_str::<NucleiFinding>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_nuclei_finding_display() {
        let finding = NucleiFinding {
            template_id: "test-template".into(),
            name: "Test Finding".into(),
            severity: "high".into(),
            matched_at: "http://example.com".into(),
            description: Some("A test vulnerability".into()),
        };
        let display = format!("{}", finding);
        assert!(display.contains("[HIGH]"));
        assert!(display.contains("test-template"));
        assert!(display.contains("Test Finding"));
        assert!(display.contains("http://example.com"));
        assert!(display.contains("A test vulnerability"));
    }

    #[test]
    fn test_nuclei_finding_display_no_description() {
        let finding = NucleiFinding {
            template_id: "test-template".into(),
            name: "Test Finding".into(),
            severity: "low".into(),
            matched_at: "http://example.com".into(),
            description: None,
        };
        let display = format!("{}", finding);
        assert!(display.contains("[LOW]"));
        assert!(!display.contains(" —  — "));
    }

    #[test]
    fn test_nuclei_finding_display_empty_description() {
        let finding = NucleiFinding {
            template_id: "test-template".into(),
            name: "Test Finding".into(),
            severity: "medium".into(),
            matched_at: "http://example.com".into(),
            description: Some("".into()),
        };
        let display = format!("{}", finding);
        assert!(display.contains("[MEDIUM]"));
    }

    #[test]
    fn test_nuclei_tool_find_binary_path_not_installed() {
        let path = std::env::var("HOME").ok().map(|h| {
            std::path::PathBuf::from(&h).join(".vest/tools/nuclei-non-existent-binary-xyz")
        });
        assert!(path.is_none() || !path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_nuclei_scan_url_parses_multiple_lines() {
        let json_lines = r#"{"templateID":"vuln-1","name":"First Vuln","severity":"high","matchedAt":"http://example.com/page1","description":"desc1"}
{"templateID":"vuln-2","name":"Second Vuln","severity":"medium","matchedAt":"http://example.com/page2","description":"desc2"}
{"templateID":"vuln-3","name":"Third Vuln","severity":"low","matchedAt":"http://example.com/page3"}"#;

        let mut findings = Vec::new();
        for line in json_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(f) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(f);
            }
        }
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[1].severity, "medium");
        assert_eq!(findings[2].severity, "low");
    }

    #[test]
    fn test_nuclei_scan_url_skips_empty_lines() {
        let json_lines = "\n\n{\"templateID\":\"vuln-1\",\"name\":\"Test\",\"severity\":\"info\",\"matchedAt\":\"http://example.com\"}\n\n";

        let mut findings = Vec::new();
        for line in json_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(f) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(f);
            }
        }
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_nuclei_scan_url_skips_invalid_json_lines() {
        let json_lines = "not json\n{\"templateID\":\"vuln-1\",\"name\":\"Test\",\"severity\":\"info\",\"matchedAt\":\"http://example.com\"}\nalso not json";

        let mut findings = Vec::new();
        for line in json_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(f) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(f);
            }
        }
        assert_eq!(findings.len(), 1);
    }
}
