use async_trait::async_trait;
use regex::Regex;
use std::path::Path;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

pub struct FileScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub check_format: bool,
    pub scan_secrets: bool,
    pub detect_backups: bool,
    pub detect_sensitive: bool,
}

impl FileScanner {
    pub fn new() -> Self {
        Self {
            name: "file-scanner".into(),
            description:
                "Scans files for secrets, backups, debug files, and format vulnerabilities".into(),
            enabled: true,
            check_format: true,
            scan_secrets: true,
            detect_backups: true,
            detect_sensitive: true,
        }
    }

    pub fn with_format(mut self, check: bool) -> Self {
        self.check_format = check;
        self
    }

    pub fn with_secrets(mut self, scan: bool) -> Self {
        self.scan_secrets = scan;
        self
    }

    pub fn with_backups(mut self, detect: bool) -> Self {
        self.detect_backups = detect;
        self
    }

    pub fn with_sensitive(mut self, detect: bool) -> Self {
        self.detect_sensitive = detect;
        self
    }

    fn detect_file_format(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let dangerous_extensions: Vec<(&str, &str)> = vec![
            (".exe", "Windows executable"),
            (".dll", "Windows dynamic link library"),
            (".bat", "Windows batch script"),
            (".ps1", "PowerShell script"),
            (".vbs", "VBScript file"),
            (".scr", "Windows screensaver (executable)"),
            (".pif", "Program Information File (executable)"),
            (".com", "DOS executable"),
            (".msi", "Windows installer"),
            (".jar", "Java archive"),
            (".apk", "Android package"),
            (".ipa", "iOS application"),
            (".sh", "Shell script"),
            (".bin", "Binary file"),
            (".so", "Shared object library"),
            (".dylib", "macOS dynamic library"),
            (".sys", "System driver"),
        ];

        for (ext, desc) in &dangerous_extensions {
            if filename.ends_with(ext) {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("Potentially dangerous file type: .{}", ext.trim_start_matches('.')),
                    description: format!("File '{}' is a {} that could contain malicious code if from an untrusted source.", filename, desc),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: Severity::Medium,
                    confidence: 0.7,
                    status: FindingStatus::Open,
                    cvss_score: Some(5.0),
                    cve_id: None,
                    cwe_id: Some("CWE-506".into()),
                    evidence: serde_json::json!({
                        "file": path.to_string_lossy(),
                        "extension": ext,
                        "file_type": desc,
                    }),
                    poc: None,
                    remediation: Some(format!("Verify the source and integrity of '{}'. Scan with antivirus if from an external source.", filename)),
                    location: serde_json::json!({
                        "file": path.to_string_lossy(),
                    }),
                    false_positive_history: None,
                    tags: vec!["file-type".into(), "suspicious".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        findings
    }

    pub fn scan_for_secrets(&self, path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        let patterns: Vec<(&str, &str, Severity)> = vec![
            (
                r#"(?i)aws[_\-\.]?(?:access)?[_\-\.]?key[_\-\.]?id[\s:=]+['\x22\x27]?([A-Z0-9]{16,32})['\x22\x27]?"#,
                "AWS Access Key ID",
                Severity::Critical,
            ),
            (
                r#"(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key[\s:=]+['\x22\x27]?([A-Za-z0-9/+=]{40})['\x22\x27]?"#,
                "AWS Secret Access Key",
                Severity::Critical,
            ),
            (
                r#"(?i)github[_\-\.]?(?:pat|token|personal[_\-\.]?access[_\-\.]?token)[\s:=]+['\x22\x27]?(ghp_[A-Za-z0-9]{36})['\x22\x27]?"#,
                "GitHub Personal Access Token",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:api[_\-\.]?key|api[_\-\.]?token|api[_\-\.]?secret)[\s:=]+['\x22\x27]?([A-Za-z0-9\-_]{20,60})['\x22\x27]?"#,
                "API Key",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:password|passwd|pwd)[\s:=]+['\x22\x27]?([^\x22\x27\s]{4,})['\x22\x27]?"#,
                "Hardcoded password",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:private[_\-\.]?key|privkey)[\s:=]+['\x22\x27]?(\-{3,}BEGIN[\s\w]+\-{3,}.*?\-{3,}END[\s\w]+\-{3,})['\x22\x27]?"#,
                "Private key",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:secret|secret[_\-\.]?key)[\s:=]+['\x22\x27]?([A-Za-z0-9\-_]{16,})['\x22\x27]?"#,
                "Secret key",
                Severity::High,
            ),
            (
                r#"(?i)(?:jwt|jwt[_\-\.]?secret|jwt[_\-\.]?token)[\s:=]+['\x22\x27]?([A-Za-z0-9\-_\.]{20,})['\x22\x27]?"#,
                "JWT secret",
                Severity::High,
            ),
            (
                r#"(?i)(?:stripe[_\-\.]?(?:secret|key|api))[\s:=]+['\x22\x27]?(sk_(?:live|test)_[A-Za-z0-9]{24})['\x22\x27]?"#,
                "Stripe secret key",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:slack[_\-\.]?(?:token|webhook))[\s:=]+['\x22\x27]?(xox[bpras]\-[A-Za-z0-9\-]{10,})['\x22\x27]?"#,
                "Slack token",
                Severity::High,
            ),
        ];

        for (pattern, name, severity) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                    let truncated = if matched.len() > 80 {
                        format!("{}...", &matched[..80])
                    } else {
                        matched.to_string()
                    };

                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: format!("{} found in file", name),
                        description: format!(
                            "Found potential {} in '{}'. Secrets in source code or configuration files can lead to unauthorized access.",
                            name.to_lowercase(), filename
                        ),
                        vulnerability_class: VulnerabilityClass::Unknown,
                        severity: *severity,
                        confidence: 0.75,
                        status: FindingStatus::Open,
                        cvss_score: match severity {
                            Severity::Critical => Some(9.0),
                            Severity::High => Some(7.5),
                            Severity::Medium => Some(5.0),
                            _ => Some(3.0),
                        },
                        cve_id: None,
                        cwe_id: Some("CWE-798".into()),
                        evidence: serde_json::json!({
                            "file": filename,
                            "pattern": name,
                            "match_preview": truncated,
                            "match_length": matched.len(),
                        }),
                        poc: None,
                        remediation: Some(
                            "Remove hardcoded secrets from source code. Use environment variables, a secrets manager, or a vault service."
                                .into(),
                        ),
                        location: serde_json::json!({
                            "file": path.to_string_lossy(),
                        }),
                        false_positive_history: None,
                        tags: vec!["secret".into(), "hardcoded".into(), "credential".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }
        }

        findings
    }

    fn detect_backup_files(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let backup_patterns = [
            ".bak", ".backup", ".old", ".orig", ".save", ".tmp", ".temp", ".swp", ".swo", ".swn",
            ".swm",
        ];

        let ends_with_tilde = filename.ends_with('~');

        let matches_backup = backup_patterns.iter().any(|pat| filename.ends_with(pat));

        if matches_backup || ends_with_tilde {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: format!("Backup file detected: {}", path.to_string_lossy()),
                description: format!(
                    "File '{}' appears to be a backup or temporary file. Backup files may contain sensitive data or old configurations and are often accessible via web servers.",
                    filename
                ),
                vulnerability_class: VulnerabilityClass::Unknown,
                severity: Severity::Medium,
                confidence: 0.8,
                status: FindingStatus::Open,
                cvss_score: Some(5.3),
                cve_id: None,
                cwe_id: Some("CWE-538".into()),
                evidence: serde_json::json!({
                    "file": path.to_string_lossy(),
                    "is_backup": true,
                }),
                poc: None,
                remediation: Some(
                    "Remove backup files from web-accessible directories. Use version control instead of file backups for source code."
                        .into(),
                ),
                location: serde_json::json!({
                    "file": path.to_string_lossy(),
                }),
                false_positive_history: None,
                tags: vec!["backup".into(), "file".into(), "exposure".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        findings
    }

    fn detect_sensitive_files(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let filename_lower = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        struct SensitivePattern {
            name: &'static str,
            filename: &'static str,
            reason: &'static str,
            severity: Severity,
            cwe: &'static str,
        }

        let sensitive_patterns = vec![
            SensitivePattern {
                name: ".env file",
                filename: ".env",
                reason: "Contains environment variables which may include database credentials, API keys, and other secrets",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Git config",
                filename: ".gitconfig",
                reason: "May contain user credentials and repository configuration",
                severity: Severity::Medium,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key",
                filename: "id_rsa",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key (DSA)",
                filename: "id_dsa",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key (ECDSA)",
                filename: "id_ecdsa",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key (Ed25519)",
                filename: "id_ed25519",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Docker config",
                filename: "config.json",
                reason: "Docker config may contain registry credentials",
                severity: Severity::High,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "npm config",
                filename: ".npmrc",
                reason: "May contain npm registry tokens",
                severity: Severity::High,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "AWS credentials",
                filename: "credentials",
                reason: "Contains AWS access keys and secrets",
                severity: Severity::Critical,
                cwe: "CWE-798",
            },
            SensitivePattern {
                name: "Database file",
                filename: ".db",
                reason: "SQLite or similar database file may contain application data",
                severity: Severity::Medium,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Debug symbol file",
                filename: ".pdb",
                reason: "Program database file may expose internal symbols and paths",
                severity: Severity::Low,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Core dump",
                filename: "core.",
                reason: "Core dump may contain process memory including secrets",
                severity: Severity::High,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Dockerfile",
                filename: "dockerfile",
                reason: "Dockerfile may expose build secrets and configuration",
                severity: Severity::Low,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Docker Compose",
                filename: "docker-compose.yml",
                reason: "Docker Compose file may contain service credentials",
                severity: Severity::Medium,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Kubernetes secret",
                filename: "secret.yaml",
                reason: "Kubernetes secret manifest may contain base64-encoded secrets",
                severity: Severity::High,
                cwe: "CWE-798",
            },
        ];

        for sp in &sensitive_patterns {
            let matches = if sp.filename.starts_with("core.") {
                filename_lower.starts_with(sp.filename)
            } else if sp.filename.starts_with('.') {
                filename_lower == sp.filename || filename_lower.ends_with(sp.filename)
            } else {
                filename_lower == sp.filename
                    || filename_lower.ends_with(&format!(".{}", sp.filename))
            };

            if matches {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("Sensitive file detected: {}", sp.name),
                    description: format!(
                        "File '{}' matches pattern for '{}'. {}. This file should not be accessible.",
                        path.to_string_lossy(),
                        sp.name,
                        sp.reason
                    ),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: sp.severity,
                    confidence: 0.85,
                    status: FindingStatus::Open,
                    cvss_score: match sp.severity {
                        Severity::Critical => Some(9.0),
                        Severity::High => Some(7.5),
                        Severity::Medium => Some(5.0),
                        _ => Some(3.0),
                    },
                    cve_id: None,
                    cwe_id: Some(sp.cwe.into()),
                    evidence: serde_json::json!({
                        "file": path.to_string_lossy(),
                        "matched_pattern": sp.name,
                    }),
                    poc: None,
                    remediation: Some(format!(
                        "Remove '{}' from the repository. Add it to .gitignore and use secure alternatives like a secrets manager.",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )),
                    location: serde_json::json!({
                        "file": path.to_string_lossy(),
                    }),
                    false_positive_history: None,
                    tags: vec!["sensitive-file".into(), "exposure".into(), sp.name.to_lowercase().replace(' ', "-")],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        let parent_dir = path
            .parent()
            .and_then(|p| p.file_name())
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        if parent_dir == ".git"
            && filename_lower != "head"
            && filename_lower != "config"
        {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: format!("Git repository data exposed: {}", path.to_string_lossy()),
                description: "Git repository internal file is accessible. Git directories exposed via web server can leak source code and commit history.".into(),
                vulnerability_class: VulnerabilityClass::Unknown,
                severity: Severity::High,
                confidence: 0.9,
                status: FindingStatus::Open,
                cvss_score: Some(7.5),
                cve_id: None,
                cwe_id: Some("CWE-538".into()),
                evidence: serde_json::json!({
                    "file": path.to_string_lossy(),
                    "in_git_dir": true,
                }),
                poc: None,
                remediation: Some("Ensure .git directories are not exposed via web server. Add rules to block access to .git paths.".into()),
                location: serde_json::json!({
                    "file": path.to_string_lossy(),
                }),
                false_positive_history: None,
                tags: vec!["git".into(), "sensitive-file".into(), "exposure".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        findings
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<Finding>, VestError> {
        let mut findings = Vec::new();

        if self.check_format {
            findings.extend(self.detect_file_format(path));
        }

        if self.scan_secrets || self.detect_sensitive {
            let is_binary = {
                if let Ok(data) = std::fs::read(path) {
                    let text_bytes = data.iter().take(512).filter(|&&b| b == 0).count();
                    text_bytes > 0
                } else {
                    false
                }
            };

            if !is_binary {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if self.scan_secrets {
                        findings.extend(self.scan_for_secrets(path, &content));
                    }
                }
            }
        }

        if self.detect_backups {
            findings.extend(self.detect_backup_files(path));
        }

        if self.detect_sensitive {
            findings.extend(self.detect_sensitive_files(path));
        }

        Ok(findings)
    }

    pub fn collect_files(path: &Path) -> Result<Vec<std::path::PathBuf>, VestError> {
        let mut files = Vec::new();

        if !path.exists() {
            return Ok(files);
        }

        if path.is_file() {
            files.push(path.to_path_buf());
            return Ok(files);
        }

        let entries = std::fs::read_dir(path).map_err(VestError::Io)?;
        for entry in entries {
            let entry = entry.map_err(VestError::Io)?;
            let entry_path = entry.path();
            if entry_path.is_file() {
                files.push(entry_path);
            } else if entry_path.is_dir() {
                files.extend(Self::collect_files(&entry_path)?);
            }
        }

        Ok(files)
    }
}

impl Default for FileScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for FileScanner {
    async fn name(&self) -> &str {
        &self.name
    }

    async fn description(&self) -> &str {
        &self.description
    }

    async fn enabled(&self) -> bool {
        self.enabled
    }

    async fn scan(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let path = match &target.path {
            Some(p) => Path::new(p),
            None => return Err(VestError::Config("File target requires a path".into())),
        };

        if !path.exists() {
            return Err(VestError::Config(format!(
                "File target path not found: {}",
                path.display()
            )));
        }

        tracing::info!("Starting file scan of: {}", path.display());

        let files = Self::collect_files(path)?;
        tracing::info!("Found {} files to analyze", files.len());

        let mut all_findings = Vec::new();

        for file_path in &files {
            match self.scan_file(file_path) {
                Ok(mut file_findings) => {
                    for f in &mut file_findings {
                        f.target_id = target.id.clone();
                        if f.scan_id.is_empty() {
                            f.scan_id = "file-scan".into();
                        }
                    }
                    all_findings.extend(file_findings);
                }
                Err(e) => {
                    tracing::warn!("Failed to scan file {}: {}", file_path.display(), e);
                }
            }
        }

        tracing::info!(
            "File scan complete: {} total findings from {} files",
            all_findings.len(),
            files.len()
        );
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_file(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_default_values() {
        let scanner = FileScanner::new();
        assert!(scanner.enabled);
        assert_eq!(scanner.name, "file-scanner");
        assert!(scanner.check_format);
        assert!(scanner.scan_secrets);
        assert!(scanner.detect_backups);
        assert!(scanner.detect_sensitive);
    }

    #[test]
    fn test_format_detection_exe() {
        let scanner = FileScanner::new();
        let path = write_temp_file("test.exe", "fake executable");
        let findings = scanner.detect_file_format(&path);
        assert!(!findings.is_empty());
        let has_exe = findings.iter().any(|f| f.title.contains("exe"));
        assert!(has_exe);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_format_detection_sh() {
        let scanner = FileScanner::new();
        let path = write_temp_file("test.sh", "#!/bin/bash\necho hello");
        let findings = scanner.detect_file_format(&path);
        assert!(!findings.is_empty());
        let has_sh = findings.iter().any(|f| f.title.contains("sh"));
        assert!(has_sh);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_format_safe_file_no_findings() {
        let scanner = FileScanner::new();
        let path = write_temp_file("readme.txt", "Hello world");
        let findings = scanner.detect_file_format(&path);
        assert!(findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_aws_key() {
        let scanner = FileScanner::new();
        let path = write_temp_file("config.js", r#"AWS_ACCESS_KEY_ID = "AWSTESTFAKEEXAMPLEKEY12""#);
        let findings =
            scanner.scan_for_secrets(&path, r#"AWS_ACCESS_KEY_ID = "AWSTESTFAKEEXAMPLEKEY12""#);
        assert!(!findings.is_empty());
        let has_aws = findings.iter().any(|f| f.title.contains("AWS"));
        assert!(has_aws);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_password() {
        let scanner = FileScanner::new();
        let path = write_temp_file("app.py", r#"password = "supersecret123""#);
        let findings = scanner.scan_for_secrets(&path, r#"password = "supersecret123""#);
        assert!(!findings.is_empty());
        let has_pwd = findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("password"));
        assert!(has_pwd);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_api_key() {
        let scanner = FileScanner::new();
        let path = write_temp_file(
            "service.go",
            r#"apiKey = "sk_test_FAKESTRIPEKEY0987654321XY""#,
        );
        let findings =
            scanner.scan_for_secrets(&path, r#"apiKey = "sk_test_FAKESTRIPEKEY0987654321XY""#);
        assert!(!findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_no_secrets() {
        let scanner = FileScanner::new();
        let path = write_temp_file("clean.js", r#"const hello = "world";"#);
        let findings = scanner.scan_for_secrets(&path, r#"const hello = "world";"#);
        assert!(findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backup_file_detection() {
        let scanner = FileScanner::new();
        let path = write_temp_file("config.bak", "old config");
        let findings = scanner.detect_backup_files(&path);
        assert!(!findings.is_empty());
        let has_backup = findings.iter().any(|f| f.title.contains("Backup"));
        assert!(has_backup);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backup_swp_file() {
        let scanner = FileScanner::new();
        let path = write_temp_file("index.swp", "vim swap");
        let findings = scanner.detect_backup_files(&path);
        assert!(!findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backup_file_not_detected() {
        let scanner = FileScanner::new();
        let path = write_temp_file("config.json", r#"{"key": "value"}"#);
        let findings = scanner.detect_backup_files(&path);
        assert!(findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_env_file() {
        let scanner = FileScanner::new();
        let path = write_temp_file(".env", "DATABASE_URL=postgres://localhost");
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_env = findings.iter().any(|f| f.title.contains(".env"));
        assert!(has_env);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_ssh_key() {
        let scanner = FileScanner::new();
        let path = write_temp_file("id_rsa", "-----BEGIN RSA PRIVATE KEY-----");
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_ssh = findings.iter().any(|f| f.title.contains("SSH"));
        assert!(has_ssh);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_credentials_file() {
        let scanner = FileScanner::new();
        let path = write_temp_file("credentials", "[default]\naws_access_key_id=AKIA...");
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_creds = findings.iter().any(|f| f.title.contains("credential"));
        assert!(has_creds);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_git_exposure() {
        let tmp_dir = std::env::temp_dir().join("test_git_exposure");
        let git_dir = tmp_dir.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let path = git_dir.join("objects");
        std::fs::write(&path, "fake git object").unwrap();
        let scanner = FileScanner::new();
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&git_dir).ok();
        std::fs::remove_dir(&tmp_dir).ok();
    }

    #[test]
    fn test_sensitive_docker_config() {
        let scanner = FileScanner::new();
        let path = write_temp_file(
            "config.json",
            r#"{"auths": {"registry": {"auth": "base64"}}}"#,
        );
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_docker = findings.iter().any(|f| f.title.contains("Docker config"));
        assert!(has_docker);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_with_methods() {
        let scanner = FileScanner::new()
            .with_format(false)
            .with_secrets(false)
            .with_backups(false)
            .with_sensitive(false);
        assert!(!scanner.check_format);
        assert!(!scanner.scan_secrets);
        assert!(!scanner.detect_backups);
        assert!(!scanner.detect_sensitive);
    }

    #[test]
    fn test_scan_rejects_nonexistent_path() {
        let scanner = FileScanner::new();
        let target = Target {
            id: "test".into(),
            name: "missing".into(),
            target_type: vest_core::types::TargetType::File,
            path: Some("/definitely/nonexistent/file.txt".into()),
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.scan(&target));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_rejects_no_path() {
        let scanner = FileScanner::new();
        let target = Target {
            id: "test".into(),
            name: "nopath".into(),
            target_type: vest_core::types::TargetType::File,
            path: None,
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.scan(&target));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path"));
    }
}
