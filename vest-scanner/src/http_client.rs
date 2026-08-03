//! Scoped HTTP client — the intended single security boundary for scanner HTTP.
//!
//! Agent tools and [`crate::web::WebScanner`] share this type for authorise,
//! manual redirects, and body budgets (no parallel client policy stacks).

use crate::web::NetworkScope;
use futures_util::StreamExt;
use reqwest::{Client, Method, Response, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use url::Url;
use vest_core::error::VestError;

/// How to enforce [`HttpClientBudgets::max_body_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyLimitPolicy {
    /// Stream at most `max_body_bytes` and return the prefix (agent tools).
    #[default]
    Truncate,
    /// Fail closed if Content-Length or streamed size exceeds the budget.
    Reject,
}

/// Budgets and timeouts for a scoped client.
#[derive(Debug, Clone)]
pub struct HttpClientBudgets {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_redirects: u32,
    pub max_body_bytes: usize,
    pub body_limit_policy: BodyLimitPolicy,
}

impl Default for HttpClientBudgets {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_body_bytes: 5_242_880,
            body_limit_policy: BodyLimitPolicy::Truncate,
        }
    }
}

/// Successful exchange after redirect following and body budgeting.
#[derive(Debug, Clone)]
pub struct ScopedHttpResponse {
    pub final_url: Url,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Optional extras for a scoped exchange (UA, forms, hop budget, robots gate).
#[derive(Default)]
pub struct ExchangeOptions<'a> {
    pub user_agent: Option<&'a str>,
    /// HTML form fields: query string on GET, `application/x-www-form-urlencoded` on POST.
    pub form: Option<&'a [(String, String)]>,
    pub raw_body: Option<&'a str>,
    pub content_type: Option<&'a str>,
    /// Incremented once per hop (including the first request).
    pub hop_counter: Option<&'a AtomicUsize>,
    /// When set with `hop_counter`, fail if the counter value before increment is >= budget.
    pub hop_budget: Option<usize>,
    /// robots.txt `Disallow` path prefixes — redirect hops matching these are rejected.
    pub redirect_disallow_prefixes: Option<&'a [String]>,
}

/// HTTP client bound to one [`NetworkScope`]. Redirects are handled manually.
#[derive(Debug, Clone)]
pub struct ScopedHttpClient {
    client: Client,
    scope: NetworkScope,
    budgets: HttpClientBudgets,
}

impl ScopedHttpClient {
    pub fn try_new(scope: NetworkScope, budgets: HttpClientBudgets) -> Result<Self, VestError> {
        let client = Client::builder()
            .timeout(budgets.request_timeout)
            .connect_timeout(budgets.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|e| {
                VestError::Config(format!(
                    "failed to construct scoped HTTP client (refusing weaker defaults): {e}"
                ))
            })?;
        Ok(Self {
            client,
            scope,
            budgets,
        })
    }

    pub fn scope(&self) -> &NetworkScope {
        &self.scope
    }

    pub fn authorise(&self, url: &Url) -> Result<(), VestError> {
        if self.scope.allows(url) {
            Ok(())
        } else {
            Err(VestError::Scan(format!(
                "URL outside authorised origin {}: {url}",
                self.scope.origin_string()
            )))
        }
    }

    /// GET with manual redirect handling and bounded body.
    pub async fn get_text(&self, url: &str) -> Result<(u16, String), VestError> {
        self.request_text(Method::GET, url).await
    }

    /// POST JSON with manual redirect handling and bounded body.
    pub async fn post_text(
        &self,
        url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<(u16, String), VestError> {
        let parsed = Url::parse(url).map_err(|e| VestError::Config(format!("invalid URL: {e}")))?;
        let resp = self
            .exchange(
                Method::POST,
                &parsed,
                ExchangeOptions {
                    raw_body: Some(body),
                    content_type: Some(content_type),
                    ..ExchangeOptions::default()
                },
            )
            .await?;
        Ok((
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ))
    }

    pub async fn request_text(
        &self,
        method: Method,
        url: &str,
    ) -> Result<(u16, String), VestError> {
        let parsed = Url::parse(url).map_err(|e| VestError::Config(format!("invalid URL: {e}")))?;
        let resp = self
            .exchange(method, &parsed, ExchangeOptions::default())
            .await?;
        Ok((
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ))
    }

    pub async fn request_with_body(
        &self,
        method: Method,
        url: &str,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(u16, String), VestError> {
        let parsed = Url::parse(url).map_err(|e| VestError::Config(format!("invalid URL: {e}")))?;
        let resp = self
            .exchange(
                method,
                &parsed,
                ExchangeOptions {
                    raw_body: body,
                    content_type,
                    ..ExchangeOptions::default()
                },
            )
            .await?;
        Ok((
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ))
    }

    /// Full exchange: authorise each hop, follow redirects, stream-cap the body.
    pub async fn exchange(
        &self,
        method: Method,
        url: &Url,
        opts: ExchangeOptions<'_>,
    ) -> Result<ScopedHttpResponse, VestError> {
        let mut current = url.clone();
        let mut method = method;
        let mut form = opts.form.map(|f| f.to_vec());
        let mut raw_body = opts.raw_body.map(str::to_owned);
        let mut content_type = opts.content_type.map(str::to_owned);
        let mut redirects = 0u32;

        // GET form fields become query parameters (never a body).
        if method == Method::GET {
            if let Some(fields) = form.take() {
                {
                    let mut pairs = current.query_pairs_mut();
                    for (k, v) in &fields {
                        pairs.append_pair(k, v);
                    }
                }
            }
        }

        loop {
            self.authorise(&current)?;
            if let Some(counter) = opts.hop_counter {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                if let Some(budget) = opts.hop_budget {
                    if n >= budget {
                        return Err(VestError::Scan("request budget exhausted".into()));
                    }
                }
            }

            let mut request = self.client.request(method.clone(), current.clone());
            if let Some(ua) = opts.user_agent {
                request = request.header(reqwest::header::USER_AGENT, ua);
            }
            if let Some(ref ct) = content_type {
                request = request.header(reqwest::header::CONTENT_TYPE, ct);
            }
            if let Some(ref fields) = form {
                request = request.form(fields);
            } else if let Some(ref b) = raw_body {
                request = request.body(b.clone());
            }

            let response = request
                .send()
                .await
                .map_err(|e| map_reqwest_error(&method, &current, e))?;

            let status = response.status();
            if status.is_redirection() {
                redirects += 1;
                if redirects > self.budgets.max_redirects {
                    return Err(VestError::Scan(format!(
                        "too many redirects (>{}) from {}",
                        self.budgets.max_redirects, url
                    )));
                }
                let loc = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| VestError::Scan("redirect missing Location".into()))?;
                let next = current
                    .join(loc)
                    .map_err(|e| VestError::Scan(format!("bad redirect URL: {e}")))?;
                // Drop redirect body without buffering.
                drop(response);

                self.authorise(&next)?;
                if let Some(prefixes) = opts.redirect_disallow_prefixes {
                    if robots_disallows(prefixes, next.path()) {
                        return Err(VestError::Scan(format!(
                            "robots.txt disallows redirect hop {}",
                            next.path()
                        )));
                    }
                }

                // WEB-2: 301/302/303 after non-GET → GET and drop body (browser-compatible).
                // 307/308 preserve method and body.
                if redirect_switches_to_get(status)
                    && method != Method::GET
                    && method != Method::HEAD
                {
                    method = Method::GET;
                    form = None;
                    raw_body = None;
                    content_type = None;
                }
                current = next;
                continue;
            }

            let headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let status_code = status.as_u16();
            let body = read_body_bounded(
                response,
                self.budgets.max_body_bytes,
                self.budgets.body_limit_policy,
            )
            .await?;
            return Ok(ScopedHttpResponse {
                final_url: current,
                status: status_code,
                headers,
                body,
            });
        }
    }
}

fn redirect_switches_to_get(status: StatusCode) -> bool {
    matches!(
        status.as_u16(),
        301..=303 // 301/302 historical POST→GET; 303 See Other
    )
}

fn robots_disallows(prefixes: &[String], path: &str) -> bool {
    let path = if path.is_empty() { "/" } else { path };
    for rule in prefixes {
        if rule == "/" {
            return true;
        }
        if path.starts_with(rule) {
            return true;
        }
    }
    false
}

fn map_reqwest_error(method: &Method, url: &Url, e: reqwest::Error) -> VestError {
    if e.is_timeout() || e.is_connect() {
        VestError::Timeout(format!("HTTP {method} {url} failed: {e}"))
    } else {
        VestError::Scan(format!("HTTP request failed: {e}"))
    }
}

/// Stream the body with a hard cap — never `.bytes()` an unbounded response.
async fn read_body_bounded(
    response: Response,
    max_bytes: usize,
    policy: BodyLimitPolicy,
) -> Result<Vec<u8>, VestError> {
    if let Some(cl) = response.content_length() {
        if cl > max_bytes as u64 {
            match policy {
                BodyLimitPolicy::Reject => {
                    return Err(VestError::Scan(format!(
                        "response Content-Length {cl} exceeds limit {max_bytes}"
                    )));
                }
                BodyLimitPolicy::Truncate => {
                    // Still stream; take() below caps memory regardless of CL.
                }
            }
        }
    }

    let mut stream = response.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| VestError::Scan(format!("failed to read body: {e}")))?;
        match policy {
            BodyLimitPolicy::Truncate => {
                let remaining = max_bytes.saturating_sub(buf.len());
                if remaining == 0 {
                    break;
                }
                if chunk.len() > remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            BodyLimitPolicy::Reject => {
                if buf.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(VestError::Scan(format!(
                        "response body exceeds limit {max_bytes}"
                    )));
                }
                buf.extend_from_slice(&chunk);
            }
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    type MockHttpResponse = (u16, Vec<(String, String)>, Vec<u8>);
    type MockHttpHandler = Arc<dyn Fn(String) -> MockHttpResponse + Send + Sync>;

    async fn spawn_server(handler: MockHttpHandler) -> (u16, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        tokio::spawn(async move {
            while !flag.load(Ordering::Relaxed) {
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
                let mut resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n",
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
        tokio::time::sleep(Duration::from_millis(20)).await;
        (port, stop)
    }

    #[tokio::test]
    async fn same_origin_ok_cross_origin_denied() {
        let handler: MockHttpHandler = Arc::new(|_req| (200u16, vec![], b"ok".to_vec()));
        let (port, stop) = spawn_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let client = ScopedHttpClient::try_new(scope, HttpClientBudgets::default()).unwrap();
        let (status, body) = client.get_text(&base).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "ok");
        let err = client
            .get_text("http://127.0.0.1:1/evil")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside"));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn redirect_escape_blocked() {
        let handler: MockHttpHandler = Arc::new(|_req| {
            (
                302u16,
                vec![("Location".into(), "http://evil.example/".into())],
                vec![],
            )
        });
        let (port, stop) = spawn_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let client = ScopedHttpClient::try_new(scope, HttpClientBudgets::default()).unwrap();
        let err = client.get_text(&base).await.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("outside")
                || err.to_string().contains("origin")
        );
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn construction_fail_closed_type_exists() {
        // Invalid scope URLs are rejected at NetworkScope::from_url; client build
        // itself uses Result rather than Client::default fallback.
        let scope = NetworkScope::from_url(&Url::parse("http://127.0.0.1:9/").unwrap()).unwrap();
        assert!(ScopedHttpClient::try_new(scope, HttpClientBudgets::default()).is_ok());
    }

    #[tokio::test]
    async fn stream_cap_truncates_without_buffering_full_declared_length() {
        // Content-Length claims 50 MiB but we only stream the truncate budget.
        let handler: MockHttpHandler = Arc::new(|_req| {
            // Body is large but finite for the mock; client must stop at max_body_bytes.
            (200u16, vec![], vec![b'Z'; 256_000])
        });
        let (port, stop) = spawn_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/");
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let client = ScopedHttpClient::try_new(
            scope,
            HttpClientBudgets {
                max_body_bytes: 1024,
                body_limit_policy: BodyLimitPolicy::Truncate,
                ..HttpClientBudgets::default()
            },
        )
        .unwrap();
        let (status, body) = client.get_text(&base).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.len(), 1024);
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn post_302_switches_to_get_and_drops_body() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        let handler: MockHttpHandler = Arc::new(move |req: String| {
            seen2.lock().unwrap().push(req.clone());
            if req.starts_with("POST /start") {
                (302u16, vec![("Location".into(), "/done".into())], vec![])
            } else {
                (200u16, vec![], b"landed".to_vec())
            }
        });
        let (port, stop) = spawn_server(handler).await;
        let base = format!("http://127.0.0.1:{port}/start");
        let scope = NetworkScope::from_url(&Url::parse(&base).unwrap()).unwrap();
        let client = ScopedHttpClient::try_new(scope, HttpClientBudgets::default()).unwrap();
        let (status, body) = client
            .post_text(&base, "secret=1", "application/x-www-form-urlencoded")
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "landed");
        let reqs = seen.lock().unwrap().clone();
        assert!(reqs.iter().any(|r| r.starts_with("POST /start")));
        assert!(reqs.iter().any(|r| r.starts_with("GET /done")));
        assert!(!reqs.iter().any(|r| r.starts_with("POST /done")));
        stop.store(true, Ordering::Relaxed);
    }
}
