use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashSet;
use std::time::Duration;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

pub struct WebScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub crawl_depth: u32,
    pub crawl_max_urls: usize,
    pub respect_robots_txt: bool,
    pub user_agent: String,
    pub timeout_seconds: u64,
    client: Client,
}

impl WebScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(10))
            .danger_accept_invalid_certs(false)
            .build()
            .unwrap_or_default();

        Self {
            name: "web-scanner".into(),
            description: "Scans web applications for OWASP Top 10 vulnerabilities".into(),
            enabled: true,
            crawl_depth: 10,
            crawl_max_urls: 10000,
            respect_robots_txt: true,
            user_agent: "VEST/0.1 Vulnerability Scanner".into(),
            timeout_seconds: 30,
            client,
        }
    }

    pub fn with_crawl_depth(mut self, depth: u32) -> Self {
        self.crawl_depth = depth;
        self
    }

    pub fn with_max_urls(mut self, max: usize) -> Self {
        self.crawl_max_urls = max;
        self
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct CrawledPage {
    url: String,
    status: u16,
    body: Option<String>,
    headers: Vec<(String, String)>,
    links: Vec<String>,
    forms: Vec<FormInfo>,
}

#[derive(Debug, Clone)]
struct FormInfo {
    action: String,
    method: String,
    inputs: Vec<(String, String)>,
}

impl WebScanner {
    async fn crawl(&self, base_url: &str) -> Result<Vec<CrawledPage>, VestError> {
        let mut pages = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = Vec::new();
        queue.push(base_url.to_string());

        while let Some(url) = queue.pop() {
            if visited.len() >= self.crawl_max_urls {
                break;
            }
            if visited.contains(&url) {
                continue;
            }
            visited.insert(url.clone());

            tokio::time::sleep(Duration::from_millis(100)).await;

            match self.fetch_page(&url).await {
                Ok(page) => {
                    let links = self.extract_links(&page, base_url);
                    for link in &links {
                        if !visited.contains(link) && visited.len() < self.crawl_max_urls {
                            queue.push(link.clone());
                        }
                    }
                    pages.push(page);
                }
                Err(e) => {
                    tracing::debug!("Crawl error for {}: {}", url, e);
                }
            }
        }

        Ok(pages)
    }

    async fn fetch_page(&self, url: &str) -> Result<CrawledPage, VestError> {
        let resp = self
            .client
            .get(url)
            .header("User-Agent", &self.user_agent)
            .send()
            .await
            .map_err(|e| VestError::Provider(format!("HTTP request failed for {}: {}", url, e)))?;

        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = resp.text().await.ok();
        let links = body
            .as_ref()
            .map(|b| self.parse_links(b, url))
            .unwrap_or_default();
        let forms = body
            .as_ref()
            .map(|b| self.parse_forms(b, url))
            .unwrap_or_default();

        Ok(CrawledPage {
            url: url.to_string(),
            status,
            body,
            headers,
            links,
            forms,
        })
    }

    fn extract_links(&self, page: &CrawledPage, base_url: &str) -> Vec<String> {
        page.links
            .iter()
            .filter(|l| l.starts_with(base_url) || l.starts_with('/'))
            .map(|l| {
                if l.starts_with('/') {
                    format!("{}{}", base_url.trim_end_matches('/'), l)
                } else {
                    l.clone()
                }
            })
            .collect()
    }

    fn parse_links(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut links = Vec::new();
        let re = regex::Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in re.captures_iter(html) {
            let href = cap[1].to_string();
            if href.starts_with("http") || href.starts_with('/') {
                if href.starts_with('/') {
                    links.push(format!("{}{}", base_url.trim_end_matches('/'), href));
                } else {
                    links.push(href);
                }
            }
        }
        links
    }

    fn parse_forms(&self, html: &str, base_url: &str) -> Vec<FormInfo> {
        let mut forms = Vec::new();
        let form_re =
            regex::Regex::new(r#"<form[^>]*action\s*=\s*["']([^"']*)["'][^>]*>"#).unwrap();
        let input_re = regex::Regex::new(
            r#"<input[^>]*name\s*=\s*["']([^"']*)["'][^>]*type\s*=\s*["']([^"']*)["']"#,
        )
        .unwrap();

        for cap in form_re.captures_iter(html) {
            let action = cap[1].to_string();
            let action_url = if action.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), action)
            } else if action.starts_with("http") {
                action.clone()
            } else {
                format!("{}/{}", base_url.trim_end_matches('/'), action)
            };

            let form_start = cap.get(0).unwrap().start();
            let remaining = &html[form_start..];
            let form_html = remaining
                .find("</form>")
                .map(|end| &remaining[..end])
                .unwrap_or(remaining);

            let inputs: Vec<(String, String)> = input_re
                .captures_iter(form_html)
                .map(|c| (c[1].to_string(), c[2].to_string()))
                .collect();

            forms.push(FormInfo {
                action: action_url,
                method: "POST".into(),
                inputs,
            });
        }

        forms
    }

    async fn scan_xss(&self, page: &CrawledPage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            "<script>alert('xss')</script>",
            "\"><script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "'><script>alert('xss')</script>",
        ];

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                for payload in &payloads {
                    let result = self
                        .submit_form(&form.action, &form.method, param_name, payload, &page.url)
                        .await;
                    if let Ok((_status, _body, reflected)) = result {
                        if reflected {
                            findings.push(self.make_finding(
                                format!(
                                    "Reflected XSS in parameter '{}' at {}",
                                    param_name, form.action
                                ),
                                VulnerabilityClass::XSS,
                                Severity::High,
                                0.8,
                                serde_json::json!({
                                    "url": form.action,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "reflected": true,
                                }),
                                Some("CWE-79".into()),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        if let Some(query_start) = page.url.find('?') {
            let query = &page.url[query_start + 1..];
            for param in query.split('&') {
                if let Some((name, _)) = param.split_once('=') {
                    let test_payload = "<script>alert(1)</script>";
                    let test_url = page
                        .url
                        .replace(param, &format!("{}={}", name, test_payload));
                    if let Ok((_status, _body, reflected)) =
                        self.fetch_page_for_xss(&test_url, test_payload).await
                    {
                        if reflected {
                            findings.push(self.make_finding(
                                format!("Reflected XSS in URL parameter '{}'", name),
                                VulnerabilityClass::XSS,
                                Severity::High,
                                0.75,
                                serde_json::json!({
                                    "url": page.url,
                                    "parameter": name,
                                    "payload": test_payload,
                                }),
                                Some("CWE-79".into()),
                            ));
                        }
                    }
                }
            }
        }

        findings
    }

    async fn scan_sqli(&self, page: &CrawledPage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            ("'", "SQL syntax error"),
            ("\" OR \"1\"=\"1", "SQL syntax"),
            ("1' OR '1'='1", "SQL syntax"),
            ("1; DROP TABLE users--", "DROP TABLE"),
            ("' UNION SELECT NULL--", "UNION SELECT"),
        ];

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                for (payload, signature) in &payloads {
                    let result = self
                        .submit_form(&form.action, &form.method, param_name, payload, &page.url)
                        .await;
                    if let Ok((status, body, _)) = result {
                        let body_lower = body.to_lowercase();
                        if body_lower.contains(&signature.to_lowercase()) || status == 500 {
                            findings.push(self.make_finding(
                                format!(
                                    "Potential SQL Injection in parameter '{}' at {}",
                                    param_name, form.action
                                ),
                                VulnerabilityClass::SQLInjection,
                                Severity::Critical,
                                0.7,
                                serde_json::json!({
                                    "url": form.action,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "signature": signature,
                                    "status": status,
                                }),
                                Some("CWE-89".into()),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    async fn scan_ssrf(&self, page: &CrawledPage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let ssrf_targets = vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://127.0.0.1:22",
            "file:///etc/passwd",
        ];

        for form in &page.forms {
            for (param_name, param_type) in &form.inputs {
                if param_type == "url"
                    || param_name.contains("url")
                    || param_name.contains("redirect")
                {
                    for target in &ssrf_targets {
                        let result = self
                            .submit_form(&form.action, &form.method, param_name, target, &page.url)
                            .await;
                        if let Ok((_status, body, _)) = result {
                            if body.contains("ami-id")
                                || body.contains("security-credentials")
                                || body.contains("root:")
                                || body.contains("SSH-2.0")
                            {
                                findings.push(self.make_finding(
                                    format!(
                                        "SSRF vulnerability in parameter '{}' at {}",
                                        param_name, form.action
                                    ),
                                    VulnerabilityClass::SSRF,
                                    Severity::Critical,
                                    0.85,
                                    serde_json::json!({
                                        "url": form.action,
                                        "parameter": param_name,
                                        "payload": target,
                                    }),
                                    Some("CWE-918".into()),
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    async fn scan_path_traversal(&self, page: &CrawledPage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ];

        let signatures = vec!["root:", "[boot loader]", "[extensions]"];

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                if param_name.contains("file")
                    || param_name.contains("path")
                    || param_name.contains("include")
                {
                    for payload in &payloads {
                        let result = self
                            .submit_form(&form.action, &form.method, param_name, payload, &page.url)
                            .await;
                        if let Ok((_, body, _)) = result {
                            for sig in &signatures {
                                if body.contains(sig) {
                                    findings.push(self.make_finding(
                                        format!(
                                            "Path traversal in parameter '{}' at {}",
                                            param_name, form.action
                                        ),
                                        VulnerabilityClass::PathTraversal,
                                        Severity::Critical,
                                        0.9,
                                        serde_json::json!({
                                            "url": form.action,
                                            "parameter": param_name,
                                            "payload": payload,
                                        }),
                                        Some("CWE-22".into()),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    async fn scan_command_injection(&self, page: &CrawledPage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            ("127.0.0.1; sleep 5", "timing"),
            ("127.0.0.1 | whoami", "whoami"),
            ("127.0.0.1 `id`", "uid="),
        ];

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                for (payload, _sig) in &payloads {
                    let start = std::time::Instant::now();
                    let result = self
                        .submit_form(&form.action, &form.method, param_name, payload, &page.url)
                        .await;
                    let elapsed = start.elapsed();

                    if let Ok((_status, body, _)) = result {
                        if elapsed.as_secs() >= 4 {
                            findings.push(self.make_finding(
                                format!(
                                    "Potential command injection (time-based) in '{}' at {}",
                                    param_name, form.action
                                ),
                                VulnerabilityClass::CommandInjection,
                                Severity::Critical,
                                0.65,
                                serde_json::json!({
                                    "url": form.action,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "elapsed_ms": elapsed.as_millis(),
                                }),
                                Some("CWE-77".into()),
                            ));
                            break;
                        }
                        if body.contains("uid=") || body.contains("gid=") {
                            findings.push(self.make_finding(
                                format!(
                                    "Command injection in parameter '{}' at {}",
                                    param_name, form.action
                                ),
                                VulnerabilityClass::CommandInjection,
                                Severity::Critical,
                                0.9,
                                serde_json::json!({
                                    "url": form.action,
                                    "parameter": param_name,
                                }),
                                Some("CWE-77".into()),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    async fn scan_misconfigurations(&self, page: &CrawledPage) -> Vec<Finding> {
        let mut findings = Vec::new();

        let security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ];

        let header_keys: HashSet<String> =
            page.headers.iter().map(|(k, _)| k.to_lowercase()).collect();

        let missing: Vec<&str> = security_headers
            .iter()
            .filter(|h| !header_keys.contains(&h.to_lowercase()))
            .copied()
            .collect();

        if !missing.is_empty() {
            findings.push(self.make_finding(
                format!("Missing security headers: {}", missing.join(", ")),
                VulnerabilityClass::CORS,
                Severity::Low,
                0.95,
                serde_json::json!({
                    "url": page.url,
                    "missing_headers": missing,
                }),
                Some("CWE-693".into()),
            ));
        }

        if let Some(cors) = page
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "access-control-allow-origin")
        {
            if cors.1 == "*" {
                findings.push(self.make_finding(
                    format!(
                        "CORS misconfiguration: Access-Control-Allow-Origin set to wildcard at {}",
                        page.url
                    ),
                    VulnerabilityClass::CORS,
                    Severity::Medium,
                    0.9,
                    serde_json::json!({
                        "url": page.url,
                        "header": "Access-Control-Allow-Origin: *",
                    }),
                    Some("CWE-942".into()),
                ));
            }
        }

        let git_url = format!("{}/.git/HEAD", page.url.trim_end_matches('/'));
        if let Ok(resp) = self
            .client
            .get(&git_url)
            .header("User-Agent", &self.user_agent)
            .send()
            .await
        {
            if resp.status().is_success() {
                findings.push(self.make_finding(
                    format!("Exposed .git directory at {}", git_url),
                    VulnerabilityClass::Unknown,
                    Severity::High,
                    0.95,
                    serde_json::json!({"url": git_url}),
                    Some("CWE-538".into()),
                ));
            }
        }

        let env_url = format!("{}/.env", page.url.trim_end_matches('/'));
        if let Ok(resp) = self
            .client
            .get(&env_url)
            .header("User-Agent", &self.user_agent)
            .send()
            .await
        {
            if resp.status().is_success() {
                findings.push(self.make_finding(
                    format!("Exposed .env file at {}", env_url),
                    VulnerabilityClass::Unknown,
                    Severity::Critical,
                    0.95,
                    serde_json::json!({"url": env_url}),
                    Some("CWE-538".into()),
                ));
            }
        }

        findings
    }

    async fn submit_form(
        &self,
        action: &str,
        _method: &str,
        param: &str,
        value: &str,
        _referer: &str,
    ) -> Result<(u16, String, bool), VestError> {
        let params = [(param, value)];
        let resp = self
            .client
            .post(action)
            .header("User-Agent", &self.user_agent)
            .form(&params)
            .send()
            .await
            .map_err(|e| VestError::Provider(format!("Form submit failed: {}", e)))?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let reflected = body.contains(value);

        Ok((status, body, reflected))
    }

    async fn fetch_page_for_xss(
        &self,
        url: &str,
        payload: &str,
    ) -> Result<(u16, String, bool), VestError> {
        let resp = self
            .client
            .get(url)
            .header("User-Agent", &self.user_agent)
            .send()
            .await
            .map_err(|e| VestError::Provider(format!("XSS check failed: {}", e)))?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let reflected = body.contains(payload);

        Ok((status, body, reflected))
    }

    fn make_finding(
        &self,
        title: String,
        vuln_class: VulnerabilityClass,
        severity: Severity,
        confidence: f64,
        evidence: serde_json::Value,
        cwe: Option<String>,
    ) -> Finding {
        let now = chrono::Utc::now();
        Finding {
            id: new_id(),
            scan_id: "web-scan".into(),
            target_id: String::new(),
            title,
            description: format!(
                "Detected {} vulnerability with confidence {:.2}",
                vuln_class,
                confidence
            ),
            vulnerability_class: vuln_class,
            severity,
            confidence,
            status: FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: cwe,
            evidence,
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec!["web".into()],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        }
    }
}

impl Default for WebScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for WebScanner {
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
        let url = match &target.url_str {
            Some(u) => u.clone(),
            None => {
                if let Some(host) = &target.host {
                    format!("https://{}", host)
                } else {
                    return Err(VestError::Config("Web target requires URL or host".into()));
                }
            }
        };

        tracing::info!("Starting web scan of: {}", url);
        let mut all_findings = Vec::new();

        let pages = self.crawl(&url).await?;
        tracing::info!("Crawled {} pages", pages.len());

        for page in &pages {
            let xss_findings = self.scan_xss(page).await;
            all_findings.extend(xss_findings);

            let sqli_findings = self.scan_sqli(page).await;
            all_findings.extend(sqli_findings);

            let ssrf_findings = self.scan_ssrf(page).await;
            all_findings.extend(ssrf_findings);

            let path_findings = self.scan_path_traversal(page).await;
            all_findings.extend(path_findings);

            let cmd_findings = self.scan_command_injection(page).await;
            all_findings.extend(cmd_findings);

            let config_findings = self.scan_misconfigurations(page).await;
            all_findings.extend(config_findings);
        }

        let mut seen: HashSet<String> = HashSet::new();
        all_findings.retain(|f| {
            let key = format!("{}:{}", f.title, f.vulnerability_class);
            seen.insert(key)
        });

        for f in &mut all_findings {
            f.target_id = target.id.clone();
        }

        tracing::info!("Web scan complete: {} total findings", all_findings.len());
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_links() {
        let scanner = WebScanner::new();
        let html = r#"<a href="/login">Login</a><a href="https://example.com/page">Page</a>"#;
        let links = scanner.parse_links(html, "https://example.com");
        assert!(links.iter().any(|l| l.contains("login")));
        assert!(links.iter().any(|l| l.contains("page")));
    }

    #[test]
    fn test_parse_forms() {
        let scanner = WebScanner::new();
        let html = r#"
        <form action="/login" method="POST">
            <input name="username" type="text">
            <input name="password" type="password">
        </form>
        "#;
        let forms = scanner.parse_forms(html, "https://example.com");
        assert_eq!(forms.len(), 1);
        assert!(forms[0].action.contains("login"));
        assert_eq!(forms[0].inputs.len(), 2);
    }

    #[test]
    fn test_parse_links_no_href() {
        let scanner = WebScanner::new();
        let html = "<p>No links here</p>";
        let links = scanner.parse_links(html, "https://example.com");
        assert!(links.is_empty());
    }

    #[test]
    fn test_parse_forms_no_form() {
        let scanner = WebScanner::new();
        let html = "<p>No forms here</p>";
        let forms = scanner.parse_forms(html, "https://example.com");
        assert!(forms.is_empty());
    }

    #[test]
    fn test_make_finding() {
        let scanner = WebScanner::new();
        let finding = scanner.make_finding(
            "Test Finding".into(),
            VulnerabilityClass::XSS,
            Severity::High,
            0.9,
            serde_json::json!({"test": true}),
            Some("CWE-79".into()),
        );
        assert_eq!(finding.title, "Test Finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, 0.9);
    }

    #[test]
    fn test_scanner_rejects_no_url_or_host() {
        let scanner = WebScanner::new();
        let target = Target {
            id: "t1".into(),
            name: "notarget".into(),
            target_type: vest_core::types::TargetType::Web,
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
    }

    #[test]
    fn test_default_values() {
        let scanner = WebScanner::new();
        assert!(scanner.enabled);
        assert_eq!(scanner.crawl_depth, 10);
        assert_eq!(scanner.crawl_max_urls, 10000);
    }
}
