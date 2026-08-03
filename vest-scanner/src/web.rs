//! Web application scanner with origin-scoped HTTP crawling.
//!
//! Network safety invariants:
//! - Only `http`/`https` URLs; structural origin matching via [`NetworkScope`]
//! - No automatic redirects; each hop is re-validated against scope
//! - Response bodies are capped; crawl concurrency and request budgets are enforced
//! - Active vulnerability probes are gated by [`WebScanner::allow_active_probes`]

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::LOCATION;
use reqwest::Client;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

/// Allowed origin for crawl/probe traffic (scheme + host + effective port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkScope {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl NetworkScope {
    pub fn from_url(url: &Url) -> Result<Self, VestError> {
        reject_disallowed_url(url)?;
        let host = url
            .host_str()
            .ok_or_else(|| VestError::Config("URL missing host".into()))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| VestError::Config("URL missing effective port".into()))?;
        Ok(Self {
            scheme: url.scheme().to_ascii_lowercase(),
            host,
            port,
        })
    }

    pub fn allows(&self, url: &Url) -> bool {
        if reject_disallowed_url(url).is_err() {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let Some(port) = url.port_or_known_default() else {
            return false;
        };
        self.scheme == url.scheme().to_ascii_lowercase()
            && self.host == host.to_ascii_lowercase()
            && self.port == port
    }

    pub fn origin_string(&self) -> String {
        match (self.scheme.as_str(), self.port) {
            ("http", 80) | ("https", 443) => format!("{}://{}", self.scheme, self.host),
            _ => format!("{}://{}:{}", self.scheme, self.host, self.port),
        }
    }
}

fn reject_disallowed_url(url: &Url) -> Result<(), VestError> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(VestError::Scan(format!(
                "disallowed URL scheme '{scheme}' (only http/https)"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(VestError::Scan(
            "URLs with userinfo are not allowed (credential/host confusion)".into(),
        ));
    }
    if url.host_str().is_none() {
        return Err(VestError::Scan("URL missing host".into()));
    }
    Ok(())
}

/// Resolve `href` against `base` and ensure the result stays in `scope`.
pub fn resolve_in_scope(base: &Url, href: &str, scope: &NetworkScope) -> Option<Url> {
    let joined = base.join(href).ok()?;
    if scope.allows(&joined) {
        Some(joined)
    } else {
        None
    }
}

#[derive(Debug, Clone, Default)]
struct RobotsRules {
    /// Path prefixes disallowed for User-agent `*`.
    disallows: Vec<String>,
}

impl RobotsRules {
    fn parse(body: &str) -> Self {
        let mut rules = RobotsRules::default();
        let mut in_star = false;
        for raw in body.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("user-agent:") {
                let ua = rest.trim();
                in_star = ua == "*";
                continue;
            }
            if !in_star {
                continue;
            }
            if lower.starts_with("disallow:") {
                if let Some((_, value)) = line.split_once(':') {
                    let path = value.trim();
                    if !path.is_empty() {
                        rules.disallows.push(path.to_string());
                    }
                }
            }
        }
        rules
    }

    fn allows_path(&self, path: &str) -> bool {
        let path = if path.is_empty() { "/" } else { path };
        for rule in &self.disallows {
            if rule == "/" {
                return false;
            }
            if path.starts_with(rule) {
                return false;
            }
        }
        true
    }
}

pub struct WebScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub crawl_depth: u32,
    pub crawl_max_urls: usize,
    pub respect_robots_txt: bool,
    pub user_agent: String,
    pub timeout_seconds: u64,
    pub connect_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub max_redirects: u32,
    pub allow_active_probes: bool,
    pub max_concurrent_requests: usize,
    client: Client,
    semaphore: Arc<Semaphore>,
}

impl WebScanner {
    fn build_client(timeout_seconds: u64, connect_timeout_ms: u64) -> Client {
        // Fail closed: never silently fall back to Client::default() (loses
        // redirect/timeout policy). Construction failure is a hard error.
        Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .connect_timeout(Duration::from_millis(connect_timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(false)
            .build()
            .expect("VEST web HTTP client construction failed; refusing weaker defaults")
    }

    pub fn new() -> Self {
        let timeout_seconds = 30;
        let connect_timeout_ms = 10_000;
        let max_concurrent_requests = 8;
        Self {
            name: "web-scanner".into(),
            description: "Scans web applications for OWASP Top 10 vulnerabilities".into(),
            enabled: true,
            crawl_depth: 10,
            crawl_max_urls: 10000,
            respect_robots_txt: true,
            user_agent: "VEST/0.1 Vulnerability Scanner".into(),
            timeout_seconds,
            connect_timeout_ms,
            max_response_bytes: 5_242_880,
            max_redirects: 5,
            allow_active_probes: false,
            max_concurrent_requests,
            client: Self::build_client(timeout_seconds, connect_timeout_ms),
            semaphore: Arc::new(Semaphore::new(max_concurrent_requests)),
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

    pub fn with_respect_robots_txt(mut self, respect: bool) -> Self {
        self.respect_robots_txt = respect;
        self
    }

    pub fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    pub fn with_max_redirects(mut self, max: u32) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn with_allow_active_probes(mut self, allow: bool) -> Self {
        self.allow_active_probes = allow;
        self
    }

    pub fn with_connect_timeout_ms(mut self, ms: u64) -> Self {
        self.connect_timeout_ms = ms;
        self.client = Self::build_client(self.timeout_seconds, self.connect_timeout_ms);
        self
    }

    pub fn with_timeout_seconds(mut self, secs: u64) -> Self {
        self.timeout_seconds = secs;
        self.client = Self::build_client(self.timeout_seconds, self.connect_timeout_ms);
        self
    }

    pub fn with_max_concurrent_requests(mut self, n: usize) -> Self {
        self.max_concurrent_requests = n.max(1);
        self.semaphore = Arc::new(Semaphore::new(self.max_concurrent_requests));
        self
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CrawledPage {
    pub url: String,
    pub status: u16,
    pub body: Option<String>,
    pub headers: Vec<(String, String)>,
    pub links: Vec<String>,
    pub forms: Vec<FormInfo>,
}

#[derive(Debug, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub inputs: Vec<(String, String)>,
}

impl WebScanner {
    async fn crawl(&self, base_url: &str) -> Result<Vec<CrawledPage>, VestError> {
        let base = Url::parse(base_url)
            .map_err(|e| VestError::Config(format!("invalid start URL: {e}")))?;
        let scope = NetworkScope::from_url(&base)?;

        let robots = if self.respect_robots_txt {
            self.fetch_robots(&scope).await
        } else {
            RobotsRules::default()
        };

        let mut pages = Vec::new();
        let mut visited = HashSet::new();
        let mut queue: Vec<(Url, u32)> = Vec::new();
        queue.push((base.clone(), 0));
        let request_count = AtomicUsize::new(0);

        while let Some((url, depth)) = queue.pop() {
            if visited.len() >= self.crawl_max_urls {
                break;
            }
            let url_key = url.as_str().to_string();
            if visited.contains(&url_key) {
                continue;
            }
            if !scope.allows(&url) {
                tracing::debug!("Skipping out-of-scope URL {}", url);
                continue;
            }
            if self.respect_robots_txt && !robots.allows_path(url.path()) {
                tracing::debug!("Skipping robots-disallowed path {}", url.path());
                continue;
            }
            visited.insert(url_key);

            match self.fetch_page_scoped(&url, &scope, &request_count).await {
                Ok(page) => {
                    if depth < self.crawl_depth {
                        for link in &page.links {
                            if visited.len() + queue.len() >= self.crawl_max_urls {
                                break;
                            }
                            if let Ok(link_url) = Url::parse(link) {
                                if scope.allows(&link_url)
                                    && (!self.respect_robots_txt
                                        || robots.allows_path(link_url.path()))
                                    && !visited.contains(link)
                                {
                                    queue.push((link_url, depth + 1));
                                }
                            }
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

    async fn fetch_robots(&self, scope: &NetworkScope) -> RobotsRules {
        let robots_url = match Url::parse(&format!("{}/robots.txt", scope.origin_string())) {
            Ok(u) => u,
            Err(_) => return RobotsRules::default(),
        };
        let counter = AtomicUsize::new(0);
        match self.fetch_page_scoped(&robots_url, scope, &counter).await {
            Ok(page) => RobotsRules::parse(page.body.as_deref().unwrap_or("")),
            Err(e) => {
                tracing::debug!("robots.txt fetch failed: {e}");
                RobotsRules::default()
            }
        }
    }

    async fn fetch_page_scoped(
        &self,
        start: &Url,
        scope: &NetworkScope,
        request_count: &AtomicUsize,
    ) -> Result<CrawledPage, VestError> {
        let (final_url, status, headers, body) = self
            .request_with_redirects("GET", start, scope, request_count, None)
            .await?;

        let body_str = body.and_then(|b| String::from_utf8(b).ok());
        let links = body_str
            .as_ref()
            .map(|b| self.parse_links_scoped(b, &final_url, scope))
            .unwrap_or_default();
        let forms = body_str
            .as_ref()
            .map(|b| self.parse_forms_scoped(b, &final_url, scope))
            .unwrap_or_default();

        Ok(CrawledPage {
            url: final_url.to_string(),
            status,
            body: body_str,
            headers,
            links,
            forms,
        })
    }

    async fn request_with_redirects(
        &self,
        method: &str,
        start: &Url,
        scope: &NetworkScope,
        request_count: &AtomicUsize,
        form: Option<&[(String, String)]>,
    ) -> Result<(Url, u16, Vec<(String, String)>, Option<Vec<u8>>), VestError> {
        let mut current = start.clone();
        let mut hops = 0u32;

        loop {
            if !scope.allows(&current) {
                return Err(VestError::Scan(format!(
                    "URL escapes network scope: {}",
                    current
                )));
            }
            if request_count.fetch_add(1, Ordering::Relaxed) >= self.crawl_max_urls {
                return Err(VestError::Scan("request budget exhausted".into()));
            }

            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|e| VestError::Internal(format!("semaphore closed: {e}")))?;

            let builder = match method {
                "POST" => {
                    let mut b = self
                        .client
                        .post(current.clone())
                        .header("User-Agent", &self.user_agent);
                    if let Some(fields) = form {
                        let owned: Vec<(String, String)> = fields.to_vec();
                        b = b.form(&owned);
                    }
                    b
                }
                _ => {
                    // GET (and any non-POST caller): fields go in the query string,
                    // never in a request body.
                    let request_url = if let Some(fields) = form {
                        let mut u = current.clone();
                        {
                            let mut pairs = u.query_pairs_mut();
                            for (k, v) in fields {
                                pairs.append_pair(k, v);
                            }
                        }
                        u
                    } else {
                        current.clone()
                    };
                    self.client
                        .get(request_url)
                        .header("User-Agent", &self.user_agent)
                }
            };

            let resp = builder.send().await.map_err(|e| {
                if e.is_timeout() || e.is_connect() {
                    VestError::Timeout(format!("HTTP {method} {} failed: {e}", current))
                } else {
                    VestError::Provider(format!("HTTP {method} {} failed: {e}", current))
                }
            })?;

            let status = resp.status();
            if status.is_redirection() {
                hops += 1;
                if hops > self.max_redirects {
                    return Err(VestError::Scan(format!(
                        "too many redirects (>{}) from {}",
                        self.max_redirects, start
                    )));
                }
                let loc = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        VestError::Scan(format!("redirect without Location from {current}"))
                    })?;
                let next = current.join(loc).map_err(|e| {
                    VestError::Scan(format!("invalid redirect Location '{loc}': {e}"))
                })?;
                // Drop body of redirect response.
                drop(resp);
                current = next;
                continue;
            }

            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let status_code = status.as_u16();
            let body = self.read_body_limited(resp).await?;
            return Ok((current, status_code, headers, body));
        }
    }

    async fn read_body_limited(
        &self,
        resp: reqwest::Response,
    ) -> Result<Option<Vec<u8>>, VestError> {
        if let Some(cl) = resp.content_length() {
            if cl > self.max_response_bytes as u64 {
                return Err(VestError::Scan(format!(
                    "response Content-Length {cl} exceeds limit {}",
                    self.max_response_bytes
                )));
            }
        }

        let mut stream = resp.bytes_stream();
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| VestError::Provider(format!("body read failed: {e}")))?;
            if buf.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(VestError::Scan(format!(
                    "response body exceeds limit {}",
                    self.max_response_bytes
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(Some(buf))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn extract_links(&self, page: &CrawledPage, base_url: &str) -> Vec<String> {
        let Ok(base) = Url::parse(base_url) else {
            return Vec::new();
        };
        let Ok(scope) = NetworkScope::from_url(&base) else {
            return Vec::new();
        };
        page.links
            .iter()
            .filter_map(|l| {
                let u = Url::parse(l).ok()?;
                if scope.allows(&u) {
                    Some(u.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn parse_links(&self, html: &str, base_url: &str) -> Vec<String> {
        let Ok(base) = Url::parse(base_url) else {
            return Vec::new();
        };
        let Ok(scope) = NetworkScope::from_url(&base) else {
            return Vec::new();
        };
        self.parse_links_scoped(html, &base, &scope)
    }

    fn parse_links_scoped(&self, html: &str, base: &Url, scope: &NetworkScope) -> Vec<String> {
        let mut links = Vec::new();
        let re = regex::Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in re.captures_iter(html) {
            let href = &cap[1];
            if href.starts_with('#')
                || href.starts_with("mailto:")
                || href.starts_with("javascript:")
            {
                continue;
            }
            if let Some(resolved) = resolve_in_scope(base, href, scope) {
                links.push(resolved.to_string());
            }
        }
        links
    }

    pub fn parse_forms(&self, html: &str, base_url: &str) -> Vec<FormInfo> {
        let Ok(base) = Url::parse(base_url) else {
            return Vec::new();
        };
        let Ok(scope) = NetworkScope::from_url(&base) else {
            return Vec::new();
        };
        self.parse_forms_scoped(html, &base, &scope)
    }

    fn parse_forms_scoped(&self, html: &str, base: &Url, scope: &NetworkScope) -> Vec<FormInfo> {
        let mut forms = Vec::new();
        let form_re = regex::Regex::new(r#"<form\b[^>]*>"#).unwrap();
        let action_re = regex::Regex::new(r#"action\s*=\s*["']([^"']*)["']"#).unwrap();
        let method_re = regex::Regex::new(r#"method\s*=\s*["']([^"']*)["']"#).unwrap();
        let input_tag_re = regex::Regex::new(r#"<input\b[^>]*>"#).unwrap();
        let name_re = regex::Regex::new(r#"name\s*=\s*["']([^"']*)["']"#).unwrap();
        let type_re = regex::Regex::new(r#"type\s*=\s*["']([^"']*)["']"#).unwrap();

        for cap in form_re.captures_iter(html) {
            let form_tag = cap.get(0).unwrap();
            let form_start = form_tag.start();
            let remaining = &html[form_start..];
            let form_html = remaining
                .find("</form>")
                .map(|end| &remaining[..end])
                .unwrap_or(remaining);

            let action_raw = action_re
                .captures(form_tag.as_str())
                .map(|c| c[1].to_string())
                .unwrap_or_default();

            let Some(action_url) = resolve_in_scope(base, &action_raw, scope) else {
                continue;
            };

            // HTML default for missing/empty method is GET.
            let method = method_re
                .captures(form_tag.as_str())
                .map(|c| c[1].trim().to_ascii_uppercase())
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "GET".into());

            let mut inputs: Vec<(String, String)> = Vec::new();
            for icap in input_tag_re.captures_iter(form_html) {
                let input_tag = icap.get(0).unwrap().as_str();
                if let Some(ncap) = name_re.captures(input_tag) {
                    let name = ncap[1].to_string();
                    let input_type = type_re
                        .captures(input_tag)
                        .map(|c| c[1].to_string())
                        .unwrap_or_else(|| "text".into());
                    inputs.push((name, input_type));
                }
            }

            forms.push(FormInfo {
                action: action_url.to_string(),
                method,
                inputs,
            });
        }

        forms
    }

    async fn scan_xss(&self, page: &CrawledPage, scope: &NetworkScope) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            "<script>alert('xss')</script>",
            "\"><script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "'><script>alert('xss')</script>",
        ];
        let counter = AtomicUsize::new(0);

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                for payload in &payloads {
                    let result = self
                        .submit_form_scoped(
                            &form.action,
                            &form.method,
                            param_name,
                            payload,
                            scope,
                            &counter,
                        )
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
                    if let Ok((_status, _body, reflected)) = self
                        .fetch_page_for_xss_scoped(&test_url, test_payload, scope, &counter)
                        .await
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

        let base_part = if let Some(pos) = page.url.find('?') {
            &page.url[..pos]
        } else {
            page.url.as_str()
        };
        let path_lower = base_part.to_lowercase();
        let mut candidate_params: Vec<String> = Vec::new();

        if path_lower.contains("search") || path_lower.contains("query") {
            for p in &["q", "query", "search"] {
                candidate_params.push(p.to_string());
            }
        }

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                candidate_params.push(param_name.clone());
            }
        }

        {
            let mut seen = HashSet::new();
            let test_payload = "<script>alert(1)</script>";
            for param_name in candidate_params {
                if !seen.insert(param_name.clone()) {
                    continue;
                }
                let test_url = format!("{}?{}={}", base_part, param_name, test_payload);
                if let Ok((_status, _body, reflected)) = self
                    .fetch_page_for_xss_scoped(&test_url, test_payload, scope, &counter)
                    .await
                {
                    if reflected {
                        findings.push(self.make_finding(
                            format!("Reflected XSS in URL parameter '{}'", param_name),
                            VulnerabilityClass::XSS,
                            Severity::High,
                            0.75,
                            serde_json::json!({
                                "url": page.url,
                                "parameter": param_name,
                                "payload": test_payload,
                            }),
                            Some("CWE-79".into()),
                        ));
                    }
                }
            }
        }

        findings
    }

    async fn scan_sqli(&self, page: &CrawledPage, scope: &NetworkScope) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            ("'", "SQL syntax error"),
            ("\" OR \"1\"=\"1", "SQL syntax"),
            ("1' OR '1'='1", "SQL syntax"),
            ("1; DROP TABLE users--", "DROP TABLE"),
            ("' UNION SELECT NULL--", "UNION SELECT"),
        ];
        let counter = AtomicUsize::new(0);

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                for (payload, signature) in &payloads {
                    let result = self
                        .submit_form_scoped(
                            &form.action,
                            &form.method,
                            param_name,
                            payload,
                            scope,
                            &counter,
                        )
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

    async fn scan_ssrf(&self, page: &CrawledPage, scope: &NetworkScope) -> Vec<Finding> {
        let mut findings = Vec::new();
        let ssrf_targets = vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://127.0.0.1:22",
            "file:///etc/passwd",
        ];
        let counter = AtomicUsize::new(0);

        for form in &page.forms {
            for (param_name, param_type) in &form.inputs {
                if param_type == "url"
                    || param_name.contains("url")
                    || param_name.contains("redirect")
                {
                    for target in &ssrf_targets {
                        let result = self
                            .submit_form_scoped(
                                &form.action,
                                &form.method,
                                param_name,
                                target,
                                scope,
                                &counter,
                            )
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

    async fn scan_path_traversal(&self, page: &CrawledPage, scope: &NetworkScope) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "/etc/passwd",
            "/etc/hosts",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ];

        let signatures = vec![
            "root:",
            "[boot loader]",
            "[extensions]",
            "User Database",
            "Host Database",
        ];
        let counter = AtomicUsize::new(0);

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                if param_name.contains("file")
                    || param_name.contains("path")
                    || param_name.contains("include")
                {
                    for payload in &payloads {
                        let result = self
                            .submit_form_scoped(
                                &form.action,
                                &form.method,
                                param_name,
                                payload,
                                scope,
                                &counter,
                            )
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

        let base_part = if let Some(pos) = page.url.find('?') {
            &page.url[..pos]
        } else {
            page.url.as_str()
        };

        {
            let mut url_param_names: Vec<String> = Vec::new();

            if let Some(query_start) = page.url.find('?') {
                let query = &page.url[query_start + 1..];
                for param in query.split('&') {
                    if let Some((name, _)) = param.split_once('=') {
                        url_param_names.push(name.to_string());
                    }
                }
            }

            for form in &page.forms {
                for (name, _) in &form.inputs {
                    url_param_names.push(name.clone());
                }
            }

            let mut seen = HashSet::new();
            for param_name in url_param_names {
                if !seen.insert(param_name.clone()) {
                    continue;
                }
                if param_name.contains("file")
                    || param_name.contains("path")
                    || param_name.contains("include")
                {
                    for payload in &payloads {
                        let test_url = format!("{}?{}={}", base_part, param_name, payload);
                        if let Ok(url) = Url::parse(&test_url) {
                            if !scope.allows(&url) {
                                continue;
                            }
                            if let Ok((_, _, _, Some(body))) = self
                                .request_with_redirects("GET", &url, scope, &counter, None)
                                .await
                            {
                                let body = String::from_utf8_lossy(&body);
                                for sig in &signatures {
                                    if body.contains(sig) {
                                        findings.push(self.make_finding(
                                            format!(
                                                "Path traversal in URL parameter '{}' at {}",
                                                param_name, page.url
                                            ),
                                            VulnerabilityClass::PathTraversal,
                                            Severity::Critical,
                                            0.9,
                                            serde_json::json!({
                                                "url": page.url,
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
        }

        findings
    }

    async fn scan_command_injection(
        &self,
        page: &CrawledPage,
        scope: &NetworkScope,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = vec![
            ("127.0.0.1; sleep 5", "timing"),
            ("127.0.0.1 | whoami", "whoami"),
            ("127.0.0.1 `id`", "uid="),
        ];
        let counter = AtomicUsize::new(0);

        for form in &page.forms {
            for (param_name, _) in &form.inputs {
                for (payload, _sig) in &payloads {
                    let start = std::time::Instant::now();
                    let result = self
                        .submit_form_scoped(
                            &form.action,
                            &form.method,
                            param_name,
                            payload,
                            scope,
                            &counter,
                        )
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

    /// Passive misconfiguration checks (response headers only).
    pub async fn scan_misconfigurations(&self, page: &CrawledPage) -> Vec<Finding> {
        self.scan_misconfigurations_inner(page, None).await
    }

    /// Fetch one in-scope page (redirect-safe) and run misconfiguration checks.
    ///
    /// Active exposure probes (`.env` / `.git`) run only when
    /// [`Self::allow_active_probes`] is true. Intended for agent `web_scan`
    /// so tools do not reimplement HTTP/probes outside this scanner.
    pub async fn inspect_url(&self, url: &str) -> Result<(CrawledPage, Vec<Finding>), VestError> {
        let start = Url::parse(url).map_err(|e| VestError::Config(format!("invalid URL: {e}")))?;
        let scope = NetworkScope::from_url(&start)?;
        let counter = AtomicUsize::new(0);
        let page = self.fetch_page_scoped(&start, &scope, &counter).await?;
        let findings = self.scan_misconfigurations_inner(&page, Some(&scope)).await;
        Ok((page, findings))
    }

    async fn scan_misconfigurations_inner(
        &self,
        page: &CrawledPage,
        scope: Option<&NetworkScope>,
    ) -> Vec<Finding> {
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

        if self.allow_active_probes {
            if let Some(scope) = scope {
                let counter = AtomicUsize::new(0);
                if let Ok(base) = Url::parse(&page.url) {
                    for (suffix, title, severity, cwe) in [
                        (
                            ".git/HEAD",
                            "Exposed .git directory",
                            Severity::High,
                            "CWE-538",
                        ),
                        (".env", "Exposed .env file", Severity::Critical, "CWE-538"),
                    ] {
                        if let Ok(probe_url) = base.join(suffix) {
                            if !scope.allows(&probe_url) {
                                continue;
                            }
                            if let Ok((_, status, _, _)) = self
                                .request_with_redirects("GET", &probe_url, scope, &counter, None)
                                .await
                            {
                                if (200..300).contains(&status) {
                                    findings.push(self.make_finding(
                                        format!("{title} at {probe_url}"),
                                        VulnerabilityClass::Unknown,
                                        severity,
                                        0.95,
                                        serde_json::json!({"url": probe_url.to_string()}),
                                        Some(cwe.into()),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    async fn submit_form_scoped(
        &self,
        action: &str,
        method: &str,
        param: &str,
        value: &str,
        scope: &NetworkScope,
        request_count: &AtomicUsize,
    ) -> Result<(u16, String, bool), VestError> {
        // Allowlist only HTML form methods we honour for probes.
        let method = match method.trim().to_ascii_uppercase().as_str() {
            "GET" => "GET",
            "POST" => "POST",
            other => {
                return Err(VestError::Scan(format!(
                    "unsupported form method '{other}' (only GET/POST allowed)"
                )));
            }
        };
        let url =
            Url::parse(action).map_err(|e| VestError::Scan(format!("invalid form action: {e}")))?;
        if !scope.allows(&url) {
            return Err(VestError::Scan(format!(
                "form action escapes scope: {action}"
            )));
        }
        let fields = vec![(param.to_string(), value.to_string())];
        let (_final, status, _headers, body) = self
            .request_with_redirects(method, &url, scope, request_count, Some(&fields))
            .await?;
        let body = body
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let reflected = body.contains(value);
        Ok((status, body, reflected))
    }

    async fn fetch_page_for_xss_scoped(
        &self,
        url: &str,
        payload: &str,
        scope: &NetworkScope,
        request_count: &AtomicUsize,
    ) -> Result<(u16, String, bool), VestError> {
        let parsed =
            Url::parse(url).map_err(|e| VestError::Scan(format!("invalid XSS probe URL: {e}")))?;
        if !scope.allows(&parsed) {
            return Err(VestError::Scan(format!("XSS probe escapes scope: {url}")));
        }
        let (_final, status, _headers, body) = self
            .request_with_redirects("GET", &parsed, scope, request_count, None)
            .await?;
        let body = body
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
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
                vuln_class, confidence
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

        let start =
            Url::parse(&url).map_err(|e| VestError::Config(format!("invalid target URL: {e}")))?;
        let scope = NetworkScope::from_url(&start)?;

        tracing::info!(
            "Starting web scan of: {} (active_probes={})",
            url,
            self.allow_active_probes
        );
        let mut all_findings = Vec::new();

        let pages = self.crawl(&url).await?;
        tracing::info!("Crawled {} pages", pages.len());

        for page in &pages {
            let config_findings = self.scan_misconfigurations_inner(page, Some(&scope)).await;
            all_findings.extend(config_findings);

            if self.allow_active_probes {
                all_findings.extend(self.scan_xss(page, &scope).await);
                all_findings.extend(self.scan_sqli(page, &scope).await);
                all_findings.extend(self.scan_ssrf(page, &scope).await);
                all_findings.extend(self.scan_path_traversal(page, &scope).await);
                all_findings.extend(self.scan_command_injection(page, &scope).await);
            }
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
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].inputs.len(), 2);
    }

    #[test]
    fn test_parse_forms_missing_method_defaults_to_get() {
        let scanner = WebScanner::new();
        let html = r#"<form action="/search">
            <input name="q" type="text">
        </form>"#;
        let forms = scanner.parse_forms(html, "https://example.com");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "GET");
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
        assert!(!scanner.allow_active_probes);
    }

    #[test]
    fn test_parse_forms_without_action() {
        let scanner = WebScanner::new();
        let html = r#"<form method="post">
            <input name="username" type="text" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
        </form>"#;
        let forms = scanner.parse_forms(html, "http://localhost:5555/login");
        assert_eq!(forms.len(), 1);
        assert!(forms[0].action.contains("login"));
        assert_eq!(forms[0].inputs.len(), 2);
    }

    #[test]
    fn test_parse_forms_input_without_type() {
        let scanner = WebScanner::new();
        let html = r#"<form action="/search" method="get">
            <input name="q" placeholder="Search...">
            <button type="submit">Search</button>
        </form>"#;
        let forms = scanner.parse_forms(html, "http://localhost:5555");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "GET");
        assert_eq!(forms[0].inputs.len(), 1);
        assert_eq!(forms[0].inputs[0].0, "q");
        assert_eq!(forms[0].inputs[0].1, "text");
    }

    #[test]
    fn test_parse_forms_login_form() {
        let scanner = WebScanner::new();
        let html = r#"<form method="post">
        <input name="username" placeholder="Username"><br>
        <input name="password" placeholder="Password" type="password"><br>
        <button type="submit">Login</button>
    </form>"#;
        let forms = scanner.parse_forms(html, "http://localhost:5555/login");
        assert_eq!(forms.len(), 1);
        assert!(forms[0].action.contains("login"));
        let input_names: Vec<&str> = forms[0].inputs.iter().map(|(n, _)| n.as_str()).collect();
        assert!(input_names.contains(&"username"));
        assert!(input_names.contains(&"password"));
        assert_eq!(forms[0].method, "POST");
    }

    #[test]
    fn test_scope_same_origin_and_prefix_attack() {
        let base = Url::parse("https://example.com/app").unwrap();
        let scope = NetworkScope::from_url(&base).unwrap();
        assert!(scope.allows(&Url::parse("https://example.com/other").unwrap()));
        assert!(!scope.allows(&Url::parse("https://example.com.evil.com/").unwrap()));
        assert!(!scope.allows(&Url::parse("https://evil.com/").unwrap()));
        assert!(!scope.allows(&Url::parse("http://example.com/").unwrap()));
    }

    #[test]
    fn test_scope_rejects_userinfo_port_scheme() {
        assert!(NetworkScope::from_url(&Url::parse("https://user@example.com/").unwrap()).is_err());
        assert!(NetworkScope::from_url(&Url::parse("file:///etc/passwd").unwrap()).is_err());
        assert!(NetworkScope::from_url(&Url::parse("ftp://example.com/").unwrap()).is_err());
        assert!(NetworkScope::from_url(&Url::parse("javascript:alert(1)").unwrap()).is_err());
        assert!(NetworkScope::from_url(&Url::parse("data:text/plain,hi").unwrap()).is_err());

        let scope = NetworkScope::from_url(&Url::parse("https://example.com/").unwrap()).unwrap();
        assert!(!scope.allows(&Url::parse("https://example.com:8443/").unwrap()));
        assert!(scope.allows(&Url::parse("https://example.com:443/").unwrap()));
    }

    #[test]
    fn test_relative_join_stays_in_scope() {
        let base = Url::parse("https://example.com/dir/page").unwrap();
        let scope = NetworkScope::from_url(&base).unwrap();
        let ok = resolve_in_scope(&base, "../ok", &scope).unwrap();
        assert_eq!(ok.path(), "/ok");
        assert!(resolve_in_scope(&base, "https://evil.com/", &scope).is_none());
        assert!(resolve_in_scope(&base, "//evil.com/path", &scope).is_none());
    }

    #[test]
    fn test_robots_parse_and_allow() {
        let body = "\
User-agent: *\n\
Disallow: /private\n\
Disallow: /tmp\n\
\n\
User-agent: Googlebot\n\
Disallow: /\n";
        let rules = RobotsRules::parse(body);
        assert!(rules.allows_path("/public"));
        assert!(!rules.allows_path("/private/secret"));
        assert!(!rules.allows_path("/tmp"));
    }

    type TestHandler = Arc<dyn Fn(String) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync>;

    async fn spawn_http_server(handler: TestHandler) -> (u16, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        tokio::spawn(async move {
            while !stop_flag.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) =
                    tokio::time::timeout(Duration::from_millis(50), listener.accept())
                        .await
                        .unwrap_or(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "timeout",
                        )))
                else {
                    continue;
                };
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, headers, body) = handler(req);
                let reason = match status {
                    200 => "OK",
                    302 => "Found",
                    404 => "Not Found",
                    _ => "OK",
                };
                let mut resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in headers {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("\r\n");
                let mut bytes = resp.into_bytes();
                bytes.extend_from_slice(&body);
                let _ = socket.write_all(&bytes).await;
            }
        });
        // Give the accept loop a moment.
        tokio::time::sleep(Duration::from_millis(20)).await;
        (port, stop)
    }

    fn hdr(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[tokio::test]
    async fn test_same_origin_crawl_and_reject_external_link() {
        let handler: TestHandler = Arc::new(|req: String| {
            if req.contains("GET / ") || req.contains("GET / HTTP") {
                (
                    200u16,
                    hdr(&[]),
                    b"<a href=\"/ok\">ok</a><a href=\"http://evil.example/x\">x</a>".to_vec(),
                )
            } else if req.contains("GET /ok") {
                (200u16, hdr(&[]), b"ok".to_vec())
            } else {
                (404u16, hdr(&[]), b"no".to_vec())
            }
        });
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scanner = WebScanner::new()
            .with_respect_robots_txt(false)
            .with_crawl_depth(2)
            .with_max_urls(10)
            .with_allow_active_probes(false);
        let pages = scanner.crawl(&base).await.unwrap();
        assert!(pages.iter().any(|p| p.url.ends_with('/')));
        assert!(pages.iter().any(|p| p.url.contains("/ok")));
        assert!(!pages.iter().any(|p| p.url.contains("evil.example")));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_redirect_escape_blocked() {
        let handler: TestHandler = Arc::new(|req: String| {
            if req.contains("GET /start") {
                (
                    302u16,
                    hdr(&[("Location", "http://127.0.0.1:9/evil")]),
                    vec![],
                )
            } else {
                (200u16, hdr(&[]), b"hi".to_vec())
            }
        });
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/start");
        let scanner = WebScanner::new().with_respect_robots_txt(false);
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let counter = AtomicUsize::new(0);
        let result = scanner
            .fetch_page_scoped(&Url::parse(&base).unwrap(), &scope, &counter)
            .await;
        assert!(result.is_err());
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_body_limit_enforced() {
        let handler: TestHandler = Arc::new(|_req: String| (200u16, hdr(&[]), vec![b'A'; 10_000]));
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scanner = WebScanner::new()
            .with_respect_robots_txt(false)
            .with_max_response_bytes(100);
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let counter = AtomicUsize::new(0);
        let result = scanner
            .fetch_page_scoped(&Url::parse(&base).unwrap(), &scope, &counter)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds limit"));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_redirect_loop_capped() {
        let handler: TestHandler = Arc::new(|req: String| {
            let loc = if req.contains("GET /a") { "/b" } else { "/a" };
            (302u16, hdr(&[("Location", loc)]), vec![])
        });
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/a");
        let scanner = WebScanner::new()
            .with_respect_robots_txt(false)
            .with_max_redirects(3);
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let counter = AtomicUsize::new(0);
        let result = scanner
            .fetch_page_scoped(&Url::parse(&base).unwrap(), &scope, &counter)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too many redirects"));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_request_cap_and_depth() {
        let handler: TestHandler = Arc::new(|req: String| {
            let body = if req.contains("GET /0") {
                b"<a href=\"/1\">1</a>".to_vec()
            } else if req.contains("GET /1") {
                b"<a href=\"/2\">2</a>".to_vec()
            } else {
                b"<a href=\"/3\">3</a>".to_vec()
            };
            (200u16, hdr(&[]), body)
        });
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/0");
        let scanner = WebScanner::new()
            .with_respect_robots_txt(false)
            .with_crawl_depth(1)
            .with_max_urls(2);
        let pages = scanner.crawl(&base).await.unwrap();
        assert!(pages.len() <= 2);
        assert!(!pages.iter().any(|p| p.url.ends_with("/2")));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_passive_does_not_run_active_probes() {
        let active_hit = Arc::new(AtomicBool::new(false));
        let active_hit2 = active_hit.clone();
        let handler: TestHandler = Arc::new(move |req: String| {
            if req.contains("POST") || req.contains("alert") || req.contains(".git") {
                active_hit2.store(true, Ordering::Relaxed);
            }
            (
                200u16,
                hdr(&[]),
                b"<form action=\"/login\" method=\"POST\"><input name=\"q\" type=\"text\"></form>"
                    .to_vec(),
            )
        });
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scanner = WebScanner::new()
            .with_respect_robots_txt(false)
            .with_allow_active_probes(false)
            .with_crawl_depth(1)
            .with_max_urls(5);
        let target = Target {
            id: "t".into(),
            name: "local".into(),
            target_type: vest_core::types::TargetType::Web,
            path: None,
            url_str: Some(base),
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let findings = scanner.scan(&target).await.unwrap();
        assert!(!active_hit.load(Ordering::Relaxed));
        assert!(findings.iter().all(|f| {
            f.vulnerability_class != VulnerabilityClass::XSS
                && f.vulnerability_class != VulnerabilityClass::SQLInjection
        }));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_robots_txt_respected() {
        let handler: TestHandler = Arc::new(|req: String| {
            if req.contains("GET /robots.txt") {
                (
                    200u16,
                    hdr(&[]),
                    b"User-agent: *\nDisallow: /hidden\n".to_vec(),
                )
            } else if req.contains("GET /hidden") {
                (200u16, hdr(&[]), b"secret".to_vec())
            } else {
                (
                    200u16,
                    hdr(&[]),
                    b"<a href=\"/hidden\">h</a><a href=\"/ok\">o</a>".to_vec(),
                )
            }
        });
        let (port, stop) = spawn_http_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scanner = WebScanner::new()
            .with_respect_robots_txt(true)
            .with_crawl_depth(2)
            .with_max_urls(10);
        let pages = scanner.crawl(&base).await.unwrap();
        assert!(!pages.iter().any(|p| p.url.contains("/hidden")));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        // Port with nothing listening — connect should time out / fail quickly.
        let scanner = WebScanner::new()
            .with_respect_robots_txt(false)
            .with_connect_timeout_ms(200)
            .with_timeout_seconds(1);
        let url = Url::parse("http://127.0.0.1:1/").unwrap();
        let scope = NetworkScope::from_url(&url).unwrap();
        let counter = AtomicUsize::new(0);
        let result = scanner.fetch_page_scoped(&url, &scope, &counter).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_submit_form_get_uses_query_string() {
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = seen.clone();
        let handler: TestHandler = Arc::new(move |req: String| {
            *seen2.lock().unwrap() = req.clone();
            (200u16, hdr(&[]), b"ok".to_vec())
        });
        let (port, stop) = spawn_http_server(handler).await;
        let action = format!("http://127.0.0.1:{port}/search");
        let scope = NetworkScope::from_url(&Url::parse(&action).unwrap()).unwrap();
        let scanner = WebScanner::new();
        let counter = AtomicUsize::new(0);
        let (status, _, _) = scanner
            .submit_form_scoped(&action, "GET", "q", "probe-value", &scope, &counter)
            .await
            .unwrap();
        assert_eq!(status, 200);
        let req = seen.lock().unwrap().clone();
        assert!(
            req.starts_with("GET /search?"),
            "expected GET with query, got: {req}"
        );
        assert!(req.contains("q=probe-value") || req.contains("q=probe%2Dvalue"));
        assert!(!req.contains("POST"));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_submit_form_post_uses_body() {
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = seen.clone();
        let handler: TestHandler = Arc::new(move |req: String| {
            *seen2.lock().unwrap() = req.clone();
            (200u16, hdr(&[]), b"ok".to_vec())
        });
        let (port, stop) = spawn_http_server(handler).await;
        let action = format!("http://127.0.0.1:{port}/login");
        let scope = NetworkScope::from_url(&Url::parse(&action).unwrap()).unwrap();
        let scanner = WebScanner::new();
        let counter = AtomicUsize::new(0);
        let (status, _, _) = scanner
            .submit_form_scoped(&action, "POST", "user", "alice", &scope, &counter)
            .await
            .unwrap();
        assert_eq!(status, 200);
        let req = seen.lock().unwrap().clone();
        assert!(req.starts_with("POST /login"), "expected POST, got: {req}");
        assert!(req.contains("user=alice"));
        assert!(!req.contains("GET /login?"));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_submit_form_rejects_non_allowlisted_method() {
        let handler: TestHandler = Arc::new(|_req: String| (200u16, hdr(&[]), b"ok".to_vec()));
        let (port, stop) = spawn_http_server(handler).await;
        let action = format!("http://127.0.0.1:{port}/x");
        let scope = NetworkScope::from_url(&Url::parse(&action).unwrap()).unwrap();
        let scanner = WebScanner::new();
        let counter = AtomicUsize::new(0);
        let err = scanner
            .submit_form_scoped(&action, "PUT", "a", "b", &scope, &counter)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported form method"));
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn test_extract_links_filters_scope() {
        let scanner = WebScanner::new();
        let page = CrawledPage {
            url: "https://example.com/".into(),
            status: 200,
            body: None,
            headers: vec![],
            links: vec![
                "https://example.com/a".into(),
                "https://example.com.evil.com/b".into(),
            ],
            forms: vec![],
        };
        let links = scanner.extract_links(&page, "https://example.com/");
        assert_eq!(links.len(), 1);
        assert!(links[0].contains("/a"));
    }
}
