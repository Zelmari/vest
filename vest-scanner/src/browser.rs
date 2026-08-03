#![cfg(feature = "browser")]

//! Browser / CDP scanner with bounded filesystem walks and scoped navigation.
//!
//! # Limits
//! - Local path scans reuse [`crate::files::collect_files_bounded`] (depth / count /
//!   size / symlink policy).
//! - CDP navigate allows only `http`/`https` (rejects `file://` and other schemes).
//! - Chrome DevTools `json/version` HTTP body is capped ([`CDP_VERSION_BODY_MAX_BYTES`]).
//! - `webSocketDebuggerUrl` from `/json/version` must be loopback (`127.0.0.1` /
//!   `::1` / `localhost`); non-loopback hosts fail closed.

use async_trait::async_trait;
use futures_util::StreamExt;
use std::path::Path;
use url::Url;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

use crate::files::{collect_files_bounded, FileTraversalLimits};

/// Max bytes accepted from Chrome's `/json/version` endpoint (JSON is tiny).
pub const CDP_VERSION_BODY_MAX_BYTES: u64 = 64 * 1024;

/// Default traversal bounds for browser static analysis of a local tree.
pub fn browser_default_limits() -> FileTraversalLimits {
    FileTraversalLimits {
        max_depth: 16,
        max_files: 5_000,
        max_file_size_bytes: 32 * 1024 * 1024,
        max_total_bytes: 256 * 1024 * 1024,
        follow_symlinks: false,
        ignore_globs: Vec::new(),
    }
}

/// Reject dangerous or unsupported schemes before CDP navigate.
///
/// Only `http` and `https` are allowed. `file://` is explicitly rejected so a
/// browser target URL cannot open arbitrary local files via Chrome.
pub fn validate_navigate_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid navigate URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {
            if parsed.host_str().is_none() {
                return Err("Navigate URL missing host".into());
            }
            Ok(())
        }
        "file" => Err("Navigate URL scheme 'file' is not allowed".into()),
        scheme => Err(format!(
            "Navigate URL scheme '{scheme}' is not allowed (only http/https)"
        )),
    }
}

/// True when the CDP websocket host is loopback (`127.0.0.0/8`, `::1`, or `localhost`).
pub fn is_loopback_ws_debugger_host(url: &str) -> Result<bool, String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid webSocketDebuggerUrl: {e}"))?;
    match parsed.scheme() {
        "ws" | "wss" => {}
        scheme => {
            return Err(format!(
                "webSocketDebuggerUrl scheme '{scheme}' is not allowed (only ws/wss)"
            ));
        }
    }
    Ok(match parsed.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    })
}

/// Reject CDP websocket URLs that are not loopback (fail closed).
pub fn validate_chrome_ws_debugger_url(url: &str) -> Result<(), String> {
    if is_loopback_ws_debugger_host(url)? {
        Ok(())
    } else {
        Err(format!(
            "webSocketDebuggerUrl host is not loopback (refusing non-local CDP): {url}"
        ))
    }
}

/// Parse `webSocketDebuggerUrl` from a Chrome `/json/version` JSON body.
///
/// Only loopback websocket endpoints are accepted (`127.0.0.1` / `::1` / `localhost`).
pub fn parse_chrome_ws_debugger_url(body: &str) -> Result<String, String> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("Invalid JSON: {e}"))?;
    let ws = json
        .get("webSocketDebuggerUrl")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            "No webSocketDebuggerUrl in Chrome response. Is Chrome running with --remote-debugging-port=9222?".to_string()
        })?;
    validate_chrome_ws_debugger_url(&ws)?;
    Ok(ws)
}

pub struct BrowserScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub check_storage: bool,
    pub check_websockets: bool,
    pub check_wasm: bool,
    pub limits: FileTraversalLimits,
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
            limits: browser_default_limits(),
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

    pub fn with_limits(mut self, limits: FileTraversalLimits) -> Self {
        self.limits = limits;
        self
    }

    pub async fn inspect_page(url: &str) -> Result<serde_json::Value, String> {
        validate_navigate_url(url)?;

        let ws_url = Self::get_chrome_ws_url()
            .await
            .map_err(|e| format!("Chrome not found: {}", e))?;

        let (mut browser, mut handler) = chromiumoxide::Browser::connect(&ws_url)
            .await
            .map_err(|e| format!("Failed to connect to Chrome: {}", e))?;

        // Keep the CDP handler future alive for the lifetime of the session.
        let handler_task = tokio::spawn(async move {
            while let Some(h) = handler.next().await {
                if h.is_err() {
                    break;
                }
            }
        });

        let outcome = async {
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

            // Close the page
            page.close().await.ok();
            Ok::<_, String>(result)
        }
        .await;

        browser.close().await.ok();
        let _ = handler_task.await;
        outcome
    }

    async fn get_chrome_ws_url() -> Result<String, String> {
        let body = tokio::task::spawn_blocking(|| {
            ureq::get("http://localhost:9222/json/version")
                .call()
                .map_err(|e| {
                    format!(
                        "Cannot reach Chrome DevTools on port 9222: {}. Start Chrome with: chrome --remote-debugging-port=9222",
                        e
                    )
                })
                .and_then(|resp| {
                    resp.into_body()
                        .into_with_config()
                        .limit(CDP_VERSION_BODY_MAX_BYTES)
                        .read_to_string()
                        .map_err(|e| format!("Failed to read response: {e}"))
                })
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))??;

        parse_chrome_ws_debugger_url(&body)
    }

    fn read_target_files(&self, path: &Path) -> Result<Vec<(String, String)>, VestError> {
        read_target_files_bounded(path, &self.limits)
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
                        severity_score_estimate: Some(7.1),
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
                    severity_score_estimate: Some(5.3),
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
                        severity_score_estimate: Some(7.5),
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
                        severity_score_estimate: Some(5.9),
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
                    severity_score_estimate: Some(4.0),
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
                            severity_score_estimate: Some(9.0),
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
                            severity_score_estimate: Some(3.5),
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
        validate_navigate_url(url).map_err(VestError::Config)?;
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
                                status: FindingStatus::Open, severity_score_estimate: Some(7.1),
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
                            status: FindingStatus::Open, severity_score_estimate: Some(7.5),
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
                    status: FindingStatus::Open, severity_score_estimate: None,
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
                    status: FindingStatus::Open, severity_score_estimate: Some(6.1),
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
                        status: FindingStatus::Open, severity_score_estimate: None,
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

/// Bounded local-tree collect for browser static analysis.
///
/// Reuses [`collect_files_bounded`] for depth/count/size/symlink policy, then
/// reads each selected file (lossy UTF-8) up to the per-file size already enforced
/// by traversal limits.
pub fn read_target_files_bounded(
    path: &Path,
    limits: &FileTraversalLimits,
) -> Result<Vec<(String, String)>, VestError> {
    let outcome = collect_files_bounded(path, limits)?;
    if outcome.truncated {
        tracing::warn!(
            "Browser path traversal truncated under {}: {:?}",
            path.display(),
            outcome.truncation_reason
        );
    }
    for (skipped_path, reason) in &outcome.skipped {
        tracing::debug!(
            "Browser scan skipped {}: {:?}",
            skipped_path.display(),
            reason
        );
    }

    let mut files = Vec::new();
    for file_path in outcome.files {
        let data = match std::fs::read(&file_path) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("Unreadable {}: {}", file_path.display(), e);
                continue;
            }
        };
        if data.len() as u64 > limits.max_file_size_bytes {
            continue;
        }
        let content = String::from_utf8_lossy(&data).into_owned();
        let name = if path.is_file() {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        } else {
            file_path
                .strip_prefix(path)
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    file_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                })
        };
        files.push((name, content));
    }
    Ok(files)
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
        let files = self.read_target_files(path)?;
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

    #[test]
    fn validate_navigate_rejects_file_scheme() {
        let err = validate_navigate_url("file:///etc/passwd").unwrap_err();
        assert!(
            err.to_lowercase().contains("file"),
            "expected file scheme rejection: {err}"
        );
    }

    #[test]
    fn validate_navigate_rejects_javascript_and_data() {
        assert!(validate_navigate_url("javascript:alert(1)").is_err());
        assert!(validate_navigate_url("data:text/html,hi").is_err());
    }

    #[test]
    fn validate_navigate_allows_http_https() {
        assert!(validate_navigate_url("http://127.0.0.1:8080/").is_ok());
        assert!(validate_navigate_url("https://example.com/app").is_ok());
    }

    #[test]
    fn parse_chrome_ws_debugger_url_ok() {
        let body = r#"{"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/abc"}"#;
        let ws = parse_chrome_ws_debugger_url(body).unwrap();
        assert!(ws.starts_with("ws://"));
    }

    #[test]
    fn parse_chrome_ws_debugger_url_accepts_localhost_and_ipv6_loopback() {
        let local = r#"{"webSocketDebuggerUrl":"ws://localhost:9222/devtools/browser/abc"}"#;
        assert!(parse_chrome_ws_debugger_url(local).is_ok());
        let v6 = r#"{"webSocketDebuggerUrl":"ws://[::1]:9222/devtools/browser/abc"}"#;
        assert!(parse_chrome_ws_debugger_url(v6).is_ok());
    }

    #[test]
    fn parse_chrome_ws_debugger_url_rejects_non_loopback() {
        let remote = r#"{"webSocketDebuggerUrl":"ws://203.0.113.9:9222/devtools/browser/abc"}"#;
        let err = parse_chrome_ws_debugger_url(remote).unwrap_err();
        assert!(
            err.to_lowercase().contains("loopback"),
            "expected loopback rejection: {err}"
        );
        let lan = r#"{"webSocketDebuggerUrl":"ws://192.168.1.10:9222/devtools/browser/x"}"#;
        assert!(parse_chrome_ws_debugger_url(lan).is_err());
        let named = r#"{"webSocketDebuggerUrl":"ws://evil.example:9222/devtools/browser/x"}"#;
        assert!(parse_chrome_ws_debugger_url(named).is_err());
    }

    #[test]
    fn validate_chrome_ws_debugger_url_rejects_http_scheme() {
        let err = validate_chrome_ws_debugger_url("http://127.0.0.1:9222/json").unwrap_err();
        assert!(err.contains("scheme"), "{err}");
    }

    #[test]
    fn parse_chrome_ws_debugger_url_missing_field() {
        assert!(parse_chrome_ws_debugger_url(r#"{"Browser":"Chrome"}"#).is_err());
    }

    #[test]
    fn cdp_version_body_limit_is_tight() {
        const {
            assert!(CDP_VERSION_BODY_MAX_BYTES <= 64 * 1024);
            assert!(CDP_VERSION_BODY_MAX_BYTES >= 1024);
        }
    }

    #[test]
    fn browser_default_limits_do_not_follow_symlinks() {
        let limits = browser_default_limits();
        assert!(!limits.follow_symlinks);
        assert!(limits.max_depth > 0);
        assert!(limits.max_files > 0);
    }

    #[test]
    fn read_target_files_respects_max_depth() {
        let root = std::env::temp_dir().join(format!(
            "vest-brw-depth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut cur = root.clone();
        for i in 0..8 {
            cur = cur.join(format!("d{i}"));
            std::fs::create_dir_all(&cur).unwrap();
        }
        std::fs::write(
            cur.join("deep.js"),
            "localStorage.setItem('password', 'deep-secret');",
        )
        .unwrap();

        let limits = FileTraversalLimits {
            max_depth: 2,
            max_files: 100,
            max_file_size_bytes: 1024 * 1024,
            max_total_bytes: 10_000_000,
            follow_symlinks: false,
            ignore_globs: vec![],
        };
        let files = read_target_files_bounded(&root, &limits).unwrap();
        let blob = files
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !blob.contains("deep-secret"),
            "depth limit must stop before deep file: {blob:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_target_files_skips_symlink_escape_by_default() {
        let root = std::env::temp_dir().join(format!(
            "vest-brw-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let inside = root.join("in");
        let outside = root.join("out");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("leak.js"),
            "localStorage.setItem('password', 'outside-only-secret');",
        )
        .unwrap();
        std::fs::write(inside.join("ok.js"), "console.log('ok');").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, inside.join("link")).unwrap();

        let files = read_target_files_bounded(&inside, &browser_default_limits()).unwrap();
        let blob = files
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !blob.contains("outside-only-secret"),
            "symlink escape must not read outside content: {blob:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_url_rejects_file_scheme_without_chrome() {
        let scanner = BrowserScanner::new();
        let target = Target {
            id: "t".into(),
            name: "file-url".into(),
            target_type: vest_core::types::TargetType::Browser,
            path: None,
            url_str: Some("file:///tmp/x.html".into()),
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(scanner.scan(&target)).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("file") || msg.contains("scheme") || msg.contains("not allowed"),
            "expected file:// rejection, got: {msg}"
        );
    }
}
