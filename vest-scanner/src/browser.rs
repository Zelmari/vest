#![cfg(feature = "browser")]

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
                "Scans browser-based targets for storage, WebSocket, and WASM vulnerabilities via Chrome DevTools Protocol"
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

    pub async fn inspect_page(url: &str) -> Result<serde_json::Value, String> {
        let ws_url = Self::get_chrome_ws_url()
            .await
            .map_err(|e| format!("Chrome not found: {}", e))?;

        let (mut browser, _handler) = chromiumoxide::Browser::connect(&ws_url)
            .await
            .map_err(|e| format!("Failed to connect to Chrome: {}", e))?;

        let page = browser
            .new_page(url)
            .await
            .map_err(|e| format!("Failed to navigate to {}: {}", url, e))?;

        // Wait for page to load
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let mut result = serde_json::json!({
            "url": url,
            "title": "loaded",
        });

        // Extract localStorage
        if let Ok(entries) = page
            .evaluate("JSON.stringify(Object.entries(localStorage))")
            .await
        {
            if let Ok(val) = entries.into_value::<serde_json::Value>() {
                if let Some(storage) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(storage) {
                        result["localStorage"] = parsed;
                    }
                }
            }
        }

        // Extract sessionStorage
        if let Ok(entries) = page
            .evaluate("JSON.stringify(Object.entries(sessionStorage))")
            .await
        {
            if let Ok(val) = entries.into_value::<serde_json::Value>() {
                if let Some(storage) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(storage) {
                        result["sessionStorage"] = parsed;
                    }
                }
            }
        }

        // Check for IndexedDB usage
        if let Ok(count) = page
            .evaluate("indexedDB.databases ? indexedDB.databases().then(dbs => dbs.length) : -1")
            .await
        {
            if let Ok(val) = count.into_value::<i32>() {
                result["indexedDB_databases"] = serde_json::json!(val);
            }
        }

        // Extract WebSocket URLs from page JS context
        if let Ok(ws_urls) = page
            .evaluate(
                r#"(function() {
                let urls = [];
                try {
                    let entries = performance.getEntriesByType('resource');
                    entries.forEach(e => {
                        if (e.name.startsWith('ws:') || e.name.startsWith('wss:')) {
                            urls.push(e.name);
                        }
                    });
                } catch(e) {}
                return JSON.stringify(urls);
            })()"#,
            )
            .await
        {
            if let Ok(val) = ws_urls.into_value::<serde_json::Value>() {
                if let Some(urls) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(urls) {
                        result["websocket_urls"] = serde_json::json!(parsed);
                    }
                }
            }
        }

        // Extract WASM module URLs the page is using
        if let Ok(wasm_urls) = page
            .evaluate(
                r#"(function() {
                let urls = [];
                try {
                    let entries = performance.getEntriesByType('resource');
                    entries.forEach(e => {
                        if (e.name.endsWith('.wasm')) {
                            urls.push(e.name);
                        }
                    });
                } catch(e) {}
                return JSON.stringify(urls);
            })()"#,
            )
            .await
        {
            if let Ok(val) = wasm_urls.into_value::<serde_json::Value>() {
                if let Some(urls) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(urls) {
                        result["wasm_modules"] = serde_json::json!(parsed);
                    }
                }
            }
        }

        // Extract security-relevant headers
        if let Ok(security_info) = page.evaluate(
            r#"(function() {
                let meta = document.querySelectorAll('meta[http-equiv]');
                let headers = {};
                meta.forEach(m => {
                    let name = m.getAttribute('http-equiv');
                    let content = m.getAttribute('content');
                    if (name) headers[name] = content;
                });
                return JSON.stringify({
                    hasCSP: !!(document.querySelector('meta[http-equiv="Content-Security-Policy"]')),
                    cookieCount: document.cookie.split(';').filter(c => c.trim()).length,
                    metaHeaders: headers
                });
            })()"#,
        ).await {
            if let Ok(val) = security_info.into_value::<serde_json::Value>() {
                if let Some(s) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                        result["security_info"] = parsed;
                    }
                }
            }
        }

        // Extract inline script content for analysis
        if let Ok(scripts) = page
            .evaluate(
                r#"(function() {
                let scripts = document.querySelectorAll('script:not([src])');
                return Array.from(scripts).map(s => s.textContent).join('\n').substring(0, 10000);
            })()"#,
            )
            .await
        {
            if let Ok(val) = scripts.into_value::<serde_json::Value>() {
                if let Some(js) = val.as_str() {
                    result["inline_scripts"] = serde_json::json!({
                        "content": js,
                        "length": js.len(),
                        "has_websocket": js.contains("ws://"),
                        "has_localstorage": js.to_lowercase().contains("localstorage"),
                        "has_indexeddb": js.to_lowercase().contains("indexeddb"),
                    });
                }
            }
        }

        // Close the page and browser
        page.close().await.ok();
        browser.close().await.ok();

        Ok(result)
    }

    async fn get_chrome_ws_url() -> Result<String, String> {
        let body = tokio::task::spawn_blocking(|| {
        ureq::get("http://localhost:9222/json/version")
            .call()
            .map_err(|e| format!("Cannot reach Chrome DevTools on port 9222: {}. Start Chrome with: chrome --remote-debugging-port=9222", e))
            .and_then(|resp| {
                resp.into_body().read_to_string()
                    .map_err(|e| format!("Failed to read response: {}", e))
            })
    }).await.map_err(|e| format!("Task join error: {}", e))??;

        let json: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON: {}", e))?;
        json.get("webSocketDebuggerUrl")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No webSocketDebuggerUrl in Chrome response. Is Chrome running with --remote-debugging-port=9222?".into())
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

    fn scan_files(
        &self,
        target: &Target,
        files: &[(String, String)],
    ) -> Result<Vec<Finding>, VestError> {
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
            let storage_findings = self.analyze_storage_safety(files);
            all_findings.extend(set_target(storage_findings, &target.id));
        }
        if self.check_websockets {
            let ws_findings = self.analyze_websocket_security(files);
            all_findings.extend(set_target(ws_findings, &target.id));
        }
        if self.check_wasm {
            let wasm_findings = self.analyze_wasm_modules(files);
            all_findings.extend(set_target(wasm_findings, &target.id));
        }

        Ok(all_findings)
    }

    async fn scan_url(&self, url: &str) -> Result<Vec<Finding>, VestError> {
        tracing::info!("Starting CDP browser scan of: {}", url);

        let page_data = Self::inspect_page(url)
            .await
            .map_err(|e| VestError::Provider(format!("Browser CDP error: {}", e)))?;

        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        // Check localStorage for sensitive data
        if let Some(storage) = page_data.get("localStorage") {
            if let Some(entries) = storage.as_array() {
                for entry in entries {
                    if let Some(key) = entry.get(0).and_then(|v| v.as_str()) {
                        let key_lower = key.to_lowercase();
                        let sensitive = [
                            "token",
                            "key",
                            "secret",
                            "password",
                            "jwt",
                            "auth",
                            "api",
                            "private",
                            "credential",
                        ];
                        if sensitive.iter().any(|s| key_lower.contains(s)) {
                            findings.push(Finding {
                                id: new_id(), scan_id: "browser-scan".into(), target_id: String::new(),
                                title: format!("Sensitive data in localStorage: {}", key),
                                description: format!("The key '{}' in localStorage may contain sensitive data. Client-side storage is accessible to any JavaScript on the origin.", key),
                                vulnerability_class: VulnerabilityClass::XSS,
                                severity: Severity::High, confidence: 0.8,
                                status: FindingStatus::Open, cvss_score: Some(7.1),
                                cve_id: None, cwe_id: Some("CWE-922".into()),
                                evidence: serde_json::json!({"storage": "localStorage", "key": key}),
                                poc: None,
                                remediation: Some("Do not store sensitive data in localStorage. Use HttpOnly, Secure cookies.".into()),
                                location: serde_json::json!({"url": url, "type": "localStorage"}),
                                false_positive_history: None,
                                tags: vec!["storage".into(), "browser".into()],
                                metadata: serde_json::json!({}),
                                discovered_at: now, updated_at: now,
                            });
                        }
                    }
                }
            }
        }

        // Check WebSocket URLs for insecure connections
        if let Some(ws_urls) = page_data.get("websocket_urls").and_then(|v| v.as_array()) {
            for addr in ws_urls {
                if let Some(ws) = addr.as_str() {
                    if ws.starts_with("ws://") {
                        findings.push(Finding {
                            id: new_id(), scan_id: "browser-scan".into(), target_id: String::new(),
                            title: format!("Insecure WebSocket: {}", ws),
                            description: "WebSocket connection uses unencrypted ws://. Data transmitted is visible to network observers.".into(),
                            vulnerability_class: VulnerabilityClass::WebSocketTamper,
                            severity: Severity::High, confidence: 0.95,
                            status: FindingStatus::Open, cvss_score: Some(7.5),
                            cve_id: None, cwe_id: Some("CWE-319".into()),
                            evidence: serde_json::json!({"url": ws, "protocol": "ws://"}),
                            poc: None,
                            remediation: Some("Use wss:// for all WebSocket connections.".into()),
                            location: serde_json::json!({"url": ws}),
                            false_positive_history: None,
                            tags: vec!["websocket".into(), "cleartext".into()],
                            metadata: serde_json::json!({}),
                            discovered_at: now, updated_at: now,
                        });
                    }
                }
            }
        }

        // Check WASM modules count
        if let Some(wasm) = page_data.get("wasm_modules").and_then(|v| v.as_array()) {
            if !wasm.is_empty() {
                findings.push(Finding {
                    id: new_id(), scan_id: "browser-scan".into(), target_id: String::new(),
                    title: format!("{} WASM modules detected", wasm.len()),
                    description: format!("Found {} WebAssembly modules loaded by the page. WASM modules should be reviewed for dangerous imports and memory safety issues.", wasm.len()),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: Severity::Medium, confidence: 0.6,
                    status: FindingStatus::Open, cvss_score: None,
                    cve_id: None, cwe_id: Some("CWE-1104".into()),
                    evidence: serde_json::json!({"count": wasm.len(), "modules": wasm}),
                    poc: None,
                    remediation: Some("Audit WASM modules. Use CSP to restrict WASM execution sources.".into()),
                    location: serde_json::json!({"url": url}),
                    false_positive_history: None,
                    tags: vec!["wasm".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now, updated_at: now,
                });
            }
        }

        // Check security headers via CSP detection
        if let Some(sec) = page_data.get("security_info") {
            let has_csp = sec.get("hasCSP").and_then(|v| v.as_bool()).unwrap_or(false);
            if !has_csp {
                findings.push(Finding {
                    id: new_id(), scan_id: "browser-scan".into(), target_id: String::new(),
                    title: "No Content Security Policy detected".into(),
                    description: "The page does not have a CSP meta tag. Without CSP, XSS attacks and data injection are harder to prevent.".into(),
                    vulnerability_class: VulnerabilityClass::XSS,
                    severity: Severity::Medium, confidence: 0.85,
                    status: FindingStatus::Open, cvss_score: Some(6.1),
                    cve_id: None, cwe_id: Some("CWE-1021".into()),
                    evidence: serde_json::json!({"url": url, "csp_enabled": false}),
                    poc: None,
                    remediation: Some("Add a Content-Security-Policy header or meta tag.".into()),
                    location: serde_json::json!({"url": url}),
                    false_positive_history: None,
                    tags: vec!["headers".into(), "csp".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now, updated_at: now,
                });
            }
        }

        // Check inline script content
        if let Some(scripts) = page_data.get("inline_scripts") {
            let js = scripts
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !js.is_empty() {
                let _has_ws = scripts
                    .get("has_websocket")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let has_ls = scripts
                    .get("has_localstorage")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if has_ls {
                    findings.push(Finding {
                        id: new_id(), scan_id: "browser-scan".into(), target_id: String::new(),
                        title: "localStorage usage detected in inline scripts".into(),
                        description: "Inline JavaScript uses localStorage. Review stored data for sensitive information.".into(),
                        vulnerability_class: VulnerabilityClass::InsecureDeserialization,
                        severity: Severity::Low, confidence: 0.5,
                        status: FindingStatus::Open, cvss_score: None,
                        cve_id: None, cwe_id: Some("CWE-922".into()),
                        evidence: serde_json::json!({"url": url, "has_localstorage": true}),
                        poc: None,
                        remediation: Some("Review localStorage usage. Encrypt sensitive stored data.".into()),
                        location: serde_json::json!({"url": url}),
                        false_positive_history: None,
                        tags: vec!["storage".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now, updated_at: now,
                    });
                }
            }
        }

        Ok(findings)
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
        if let Some(ref url) = target.url_str {
            return self.scan_url(url).await;
        }

        let path = match &target.path {
            Some(p) => Path::new(p),
            None => {
                return Err(VestError::Config(
                    "Browser target requires a URL or local path".into(),
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
        self.scan_files(target, &files)
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
