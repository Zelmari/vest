use async_trait::async_trait;
use std::path::Path;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

pub struct BrowserScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub check_storage: bool,
    pub check_websockets: bool,
    pub check_wasm: bool,
}

impl BrowserScanner {
    pub fn new() -> Self {
        Self {
            name: "browser-scanner".into(),
            description:
                "Scans browser-based targets for storage, WebSocket, and WASM vulnerabilities"
                    .into(),
            enabled: true,
            check_storage: true,
            check_websockets: true,
            check_wasm: true,
        }
    }

    pub fn with_storage(mut self, check: bool) -> Self {
        self.check_storage = check;
        self
    }

    pub fn with_websockets(mut self, check: bool) -> Self {
        self.check_websockets = check;
        self
    }

    pub fn with_wasm(mut self, check: bool) -> Self {
        self.check_wasm = check;
        self
    }

    fn read_target_files(path: &Path) -> Result<Vec<(String, String)>, VestError> {
        let mut files = Vec::new();
        collect_files(path, &mut files)?;
        Ok(files)
    }

    fn analyze_storage_safety(&self, files: &[(String, String)]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let sensitive_keys = [
            "password",
            "token",
            "secret",
            "apikey",
            "api_key",
            "auth",
            "jwt",
            "session",
            "credential",
            "private_key",
            "access_token",
            "refresh_token",
            "bearer",
            "ssn",
            "credit_card",
        ];

        for (filename, content) in files {
            if !filename.ends_with(".js")
                && !filename.ends_with(".html")
                && !filename.ends_with(".ts")
            {
                continue;
            }

            let lower = content.to_lowercase();

            for key in &sensitive_keys {
                let pattern1 = format!("localstorage.setitem(\"{}\"", key);
                let pattern2 = format!("localstorage.setitem('{}'", key);
                let pattern3 = format!("sessionstorage.setitem(\"{}\"", key);
                let pattern4 = format!("sessionstorage.setitem('{}'", key);

                if lower.contains(&pattern1)
                    || lower.contains(&pattern2)
                    || lower.contains(&pattern3)
                    || lower.contains(&pattern4)
                {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: format!(
                            "Sensitive data stored in browser storage: {}",
                            key
                        ),
                        description: format!(
                            "Found potential storage of '{}' in browser localStorage/sessionStorage in {}. Data stored in browser storage is accessible to any JavaScript running on the origin.",
                            key, filename
                        ),
                        vulnerability_class: VulnerabilityClass::XSS,
                        severity: Severity::High,
                        confidence: 0.75,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.1),
                        cve_id: None,
                        cwe_id: Some("CWE-922".into()),
                        evidence: serde_json::json!({
                            "file": filename,
                            "storage_type": "localStorage/sessionStorage",
                            "key_pattern": key,
                        }),
                        poc: None,
                        remediation: Some(
                            "Do not store sensitive data in browser storage. Use HttpOnly, Secure cookies with SameSite=Strict for session tokens."
                                .into(),
                        ),
                        location: serde_json::json!({
                            "file": filename,
                            "type": "browser-storage",
                        }),
                        false_positive_history: None,
                        tags: vec!["storage".into(), "browser".into(), "sensitive-data".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                    break;
                }
            }

            if (lower.contains("localstorage") || lower.contains("sessionstorage"))
                && !lower.contains("encrypt")
                && !lower.contains("hash")
                && !lower.contains("encode")
            {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: "Browser storage used without visible encryption".into(),
                    description: format!(
                        "Browser storage (localStorage/sessionStorage) is used in {} but no encryption or hashing was detected nearby. Data may be stored in plaintext.",
                        filename
                    ),
                    vulnerability_class: VulnerabilityClass::InsecureDeserialization,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    status: FindingStatus::Open,
                    cvss_score: Some(5.3),
                    cve_id: None,
                    cwe_id: Some("CWE-312".into()),
                    evidence: serde_json::json!({
                        "file": filename,
                        "has_encryption": false,
                    }),
                    poc: None,
                    remediation: Some(
                        "Encrypt any data stored in browser storage. Consider using IndexedDB with encryption or avoid client-side storage for sensitive data."
                            .into(),
                    ),
                    location: serde_json::json!({
                        "file": filename,
                        "type": "browser-storage",
                    }),
                    false_positive_history: None,
                    tags: vec!["storage".into(), "browser".into(), "cleartext".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        findings
    }

    fn analyze_websocket_security(&self, files: &[(String, String)]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        for (filename, content) in files {
            if !filename.ends_with(".js")
                && !filename.ends_with(".html")
                && !filename.ends_with(".ts")
            {
                continue;
            }

            for line in content.lines() {
                let line_lower = line.to_lowercase();

                if (line_lower.contains("new websocket") || line_lower.contains("websocket("))
                    && line_lower.contains("ws://")
                    && !line_lower.contains("wss://")
                {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: "Insecure WebSocket connection (ws://)".into(),
                        description: format!(
                            "Found an insecure WebSocket connection using ws:// in {}. Unencrypted WebSocket connections expose data to interception and tampering.",
                            filename
                        ),
                        vulnerability_class: VulnerabilityClass::WebSocketTamper,
                        severity: Severity::High,
                        confidence: 0.9,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.5),
                        cve_id: None,
                        cwe_id: Some("CWE-319".into()),
                        evidence: serde_json::json!({
                            "file": filename,
                            "protocol": "ws://",
                            "line_preview": line.trim().chars().take(200).collect::<String>(),
                        }),
                        poc: None,
                        remediation: Some(
                            "Use wss:// (WebSocket Secure) connections. Always encrypt WebSocket traffic with TLS."
                                .into(),
                        ),
                        location: serde_json::json!({
                            "file": filename,
                            "type": "websocket",
                        }),
                        false_positive_history: None,
                        tags: vec!["websocket".into(), "cleartext".into(), "tls".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }

            let ws_url_count = content.matches("ws://").count();
            let wss_url_count = content.matches("wss://").count();

            if ws_url_count > 0 && wss_url_count == 0 {
                let has_finding = findings
                    .iter()
                    .any(|f| f.evidence.get("file").and_then(|v| v.as_str()) == Some(filename));
                if !has_finding {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: "Multiple ws:// references with no wss://".into(),
                        description: format!(
                            "Found {} ws:// reference(s) with no wss:// usage in {}. All WebSocket connections should use encryption.",
                            ws_url_count, filename
                        ),
                        vulnerability_class: VulnerabilityClass::WebSocketTamper,
                        severity: Severity::Medium,
                        confidence: 0.7,
                        status: FindingStatus::Open,
                        cvss_score: Some(5.9),
                        cve_id: None,
                        cwe_id: Some("CWE-319".into()),
                        evidence: serde_json::json!({
                            "file": filename,
                            "ws_count": ws_url_count,
                            "wss_count": wss_url_count,
                        }),
                        poc: None,
                        remediation: Some("Replace all ws:// connections with wss://.".into()),
                        location: serde_json::json!({
                            "file": filename,
                            "type": "websocket",
                        }),
                        false_positive_history: None,
                        tags: vec!["websocket".into(), "cleartext".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }
        }

        findings
    }

    fn analyze_wasm_modules(&self, files: &[(String, String)]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let dangerous_imports = [
            ("env", "_emscripten_run_script"),
            ("env", "system"),
            ("env", "popen"),
            ("env", "exec"),
            ("wasi_snapshot_preview1", "proc_exit"),
        ];

        for (filename, content) in files {
            if !filename.ends_with(".wasm") && !filename.ends_with(".wat") {
                continue;
            }

            let is_valid_wasm = content.as_bytes().starts_with(b"\0asm")
                || (content.len() > 8 && &content.as_bytes()[0..4] == b"\0asm");

            if filename.ends_with(".wasm") && !is_valid_wasm {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("Invalid or corrupted WASM module: {}", filename),
                    description: "The file has a .wasm extension but does not contain a valid WASM magic number (\0asm). This could be a disguised malicious file.".into(),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: Severity::Medium,
                    confidence: 0.8,
                    status: FindingStatus::Open,
                    cvss_score: Some(4.0),
                    cve_id: None,
                    cwe_id: Some("CWE-506".into()),
                    evidence: serde_json::json!({
                        "file": filename,
                        "valid_wasm_magic": false,
                    }),
                    poc: None,
                    remediation: Some("Verify the WASM module source and ensure integrity checks are in place.".into()),
                    location: serde_json::json!({
                        "file": filename,
                        "type": "wasm",
                    }),
                    false_positive_history: None,
                    tags: vec!["wasm".into(), "integrity".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }

            if is_valid_wasm || filename.ends_with(".wat") {
                let content_lower = content.to_lowercase();
                let mut found_dangerous = false;

                for (module, func) in &dangerous_imports {
                    if content_lower.contains(module) && content_lower.contains(func) {
                        found_dangerous = true;
                        findings.push(Finding {
                            id: new_id(),
                            scan_id: String::new(),
                            target_id: String::new(),
                            title: format!(
                                "WASM module imports dangerous function: {}.{}",
                                module, func
                            ),
                            description: format!(
                                "WASM module '{}' imports '{}.{}', which could allow arbitrary code execution or system access from within the browser sandbox.",
                                filename, module, func
                            ),
                            vulnerability_class: VulnerabilityClass::CommandInjection,
                            severity: Severity::Critical,
                            confidence: 0.85,
                            status: FindingStatus::Open,
                            cvss_score: Some(9.0),
                            cve_id: None,
                            cwe_id: Some("CWE-94".into()),
                            evidence: serde_json::json!({
                                "file": filename,
                                "import_module": module,
                                "import_function": func,
                            }),
                            poc: None,
                            remediation: Some(
                                "Review the WASM module for untrusted imports. Use fine-grained WASM capabilities and Content Security Policy (CSP) to restrict WASM execution."
                                    .into(),
                            ),
                            location: serde_json::json!({
                                "file": filename,
                                "type": "wasm",
                            }),
                            false_positive_history: None,
                            tags: vec!["wasm".into(), "dangerous-imports".into()],
                            metadata: serde_json::json!({}),
                            discovered_at: now,
                            updated_at: now,
                        });
                    }
                }

                if !found_dangerous && !content.is_empty() {
                    let import_count = content_lower.matches("(import").count();
                    if import_count > 10 {
                        findings.push(Finding {
                            id: new_id(),
                            scan_id: String::new(),
                            target_id: String::new(),
                            title: format!(
                                "WASM module has high number of imports: {}",
                                filename
                            ),
                            description: format!(
                                "WASM module '{}' has {} imports, which may indicate a large attack surface. Review all imported functions for security implications.",
                                filename, import_count
                            ),
                            vulnerability_class: VulnerabilityClass::Unknown,
                            severity: Severity::Low,
                            confidence: 0.5,
                            status: FindingStatus::Open,
                            cvss_score: Some(3.5),
                            cve_id: None,
                            cwe_id: Some("CWE-1104".into()),
                            evidence: serde_json::json!({
                                "file": filename,
                                "import_count": import_count,
                            }),
                            poc: None,
                            remediation: Some("Audit all WASM imports and reduce the attack surface by limiting imported functions to only those strictly necessary.".into()),
                            location: serde_json::json!({
                                "file": filename,
                                "type": "wasm",
                            }),
                            false_positive_history: None,
                            tags: vec!["wasm".into(), "imports".into()],
                            metadata: serde_json::json!({}),
                            discovered_at: now,
                            updated_at: now,
                        });
                    }
                }
            }
        }

        findings
    }
}

fn collect_files(dir: &Path, files: &mut Vec<(String, String)>) -> Result<(), VestError> {
    if !dir.exists() {
        return Ok(());
    }

    if dir.is_file() {
        let content = std::fs::read_to_string(dir).map_err(VestError::Io)?;
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        files.push((name, content));
        return Ok(());
    }

    let entries = std::fs::read_dir(dir).map_err(VestError::Io)?;
    for entry in entries {
        let entry = entry.map_err(VestError::Io)?;
        let path = entry.path();
        if path.is_file() {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if let Ok(content) = std::fs::read_to_string(&path) {
                files.push((name, content));
            }
        } else if path.is_dir() {
            collect_files(&path, files)?;
        }
    }

    Ok(())
}

impl Default for BrowserScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for BrowserScanner {
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
            None => {
                return Err(VestError::Config(
                    "Browser target requires a path to scan directories or files".into(),
                ))
            }
        };

        if !path.exists() {
            return Err(VestError::Config(format!(
                "Browser target path not found: {}",
                path.display()
            )));
        }

        tracing::info!("Starting browser scan of: {}", path.display());

        let files = Self::read_target_files(path)?;
        tracing::info!("Found {} files to analyze", files.len());

        let mut all_findings = Vec::new();

        let set_target = |mut findings: Vec<Finding>, tid: &str| -> Vec<Finding> {
            for f in &mut findings {
                f.target_id = tid.to_string();
                if f.scan_id.is_empty() {
                    f.scan_id = "browser-scan".into();
                }
            }
            findings
        };

        if self.check_storage {
            tracing::info!("Analyzing browser storage safety");
            let storage_findings = self.analyze_storage_safety(&files);
            tracing::info!("Found {} storage-related issues", storage_findings.len());
            all_findings.extend(set_target(storage_findings, &target.id));
        }

        if self.check_websockets {
            tracing::info!("Analyzing WebSocket security");
            let ws_findings = self.analyze_websocket_security(&files);
            tracing::info!("Found {} WebSocket-related issues", ws_findings.len());
            all_findings.extend(set_target(ws_findings, &target.id));
        }

        if self.check_wasm {
            tracing::info!("Analyzing WASM modules");
            let wasm_findings = self.analyze_wasm_modules(&files);
            tracing::info!("Found {} WASM-related issues", wasm_findings.len());
            all_findings.extend(set_target(wasm_findings, &target.id));
        }

        tracing::info!(
            "Browser scan complete: {} total findings",
            all_findings.len()
        );
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(path: &str) -> Target {
        Target {
            id: "test-browser-target".into(),
            name: "browser-test".into(),
            target_type: vest_core::types::TargetType::Browser,
            path: Some(path.into()),
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_default_values() {
        let scanner = BrowserScanner::new();
        assert!(scanner.enabled);
        assert_eq!(scanner.name, "browser-scanner");
        assert!(scanner.check_storage);
        assert!(scanner.check_websockets);
        assert!(scanner.check_wasm);
    }

    #[test]
    fn test_storage_sensitive_data_detection() {
        let scanner = BrowserScanner::new();
        let files = vec![(
            "app.js".into(),
            "localStorage.setItem('password', 'secret123');".into(),
        )];
        let findings = scanner.analyze_storage_safety(&files);
        assert!(!findings.is_empty());
        let has_password = findings.iter().any(|f| f.title.contains("password"));
        assert!(has_password);
    }

    #[test]
    fn test_storage_no_encryption_detection() {
        let scanner = BrowserScanner::new();
        let files = vec![(
            "app.js".into(),
            "localStorage.setItem('prefs', JSON.stringify(prefs));".into(),
        )];
        let findings = scanner.analyze_storage_safety(&files);
        assert!(!findings.is_empty());
        let has_encryption_warning = findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("encryption"));
        assert!(has_encryption_warning);
    }

    #[test]
    fn test_websocket_insecure_ws_detection() {
        let scanner = BrowserScanner::new();
        let files = vec![(
            "app.js".into(),
            r#"const ws = new WebSocket("ws://evil.com/socket");"#.into(),
        )];
        let findings = scanner.analyze_websocket_security(&files);
        assert!(!findings.is_empty());
        let has_ws = findings.iter().any(|f| f.title.contains("ws://"));
        assert!(has_ws);
    }

    #[test]
    fn test_websocket_wss_ok() {
        let scanner = BrowserScanner::new();
        let files = vec![(
            "secure.js".into(),
            r#"const ws = new WebSocket("wss://safe.com/socket");"#.into(),
        )];
        let findings = scanner.analyze_websocket_security(&files);
        let has_ws_vuln = findings.iter().any(|f| f.title.contains("ws://"));
        assert!(!has_ws_vuln);
    }

    #[test]
    fn test_wasm_valid_module_detection() {
        let scanner = BrowserScanner::new();
        let mut content = vec![0x00, 0x61, 0x73, 0x6d]; // \0asm
        content.extend_from_slice(b"\x01\x00\x00\x00");
        content.extend_from_slice(
            b"some wasm binary data here (import \"env\" \"_emscripten_run_script\")",
        );

        let content_str = String::from_utf8_lossy(&content).to_string();
        let files = vec![("module.wasm".into(), content_str)];
        let findings = scanner.analyze_wasm_modules(&files);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_wasm_invalid_magic_detection() {
        let scanner = BrowserScanner::new();
        let files = vec![("fake.wasm".into(), "This is not a valid WASM module".into())];
        let findings = scanner.analyze_wasm_modules(&files);
        assert!(!findings.is_empty());
        let has_invalid = findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("invalid"));
        assert!(has_invalid);
    }

    #[test]
    fn test_scan_rejects_no_path() {
        let scanner = BrowserScanner::new();
        let target = Target {
            id: "test".into(),
            name: "nopath".into(),
            target_type: vest_core::types::TargetType::Browser,
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

    #[test]
    fn test_scan_rejects_nonexistent_path() {
        let scanner = BrowserScanner::new();
        let target = make_target("/definitely/not/a/real/path");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.scan(&target));
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_high_imports_detection() {
        let scanner = BrowserScanner::new();
        let mut content = String::from("\0asm\x01\x00\x00\x00");
        for i in 0..15 {
            content.push_str(&format!(" (import \"env\" \"func{}\" (func $f{}))\n", i, i));
        }
        let files = vec![("many_imports.wasm".into(), content)];
        let findings = scanner.analyze_wasm_modules(&files);
        let has_import_warning = findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("imports"));
        assert!(has_import_warning);
    }

    #[test]
    fn test_with_methods() {
        let scanner = BrowserScanner::new()
            .with_storage(false)
            .with_websockets(false)
            .with_wasm(false);
        assert!(!scanner.check_storage);
        assert!(!scanner.check_websockets);
        assert!(!scanner.check_wasm);
    }
}
