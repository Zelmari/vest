//! Scoped HTTP client — the intended single security boundary for scanner HTTP.
//!
//! Agent tools in `vest-cli` should migrate onto this type (or a thin wrapper)
//! instead of calling `ureq`/`reqwest` directly.

use crate::web::NetworkScope;
use reqwest::{Client, Method, Response};
use std::time::Duration;
use url::Url;
use vest_core::error::VestError;

/// Budgets and timeouts for a scoped client.
#[derive(Debug, Clone)]
pub struct HttpClientBudgets {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_redirects: u32,
    pub max_body_bytes: usize,
}

impl Default for HttpClientBudgets {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_body_bytes: 5_242_880,
        }
    }
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

    pub async fn request_text(
        &self,
        method: Method,
        url: &str,
    ) -> Result<(u16, String), VestError> {
        let mut current =
            Url::parse(url).map_err(|e| VestError::Config(format!("invalid URL: {e}")))?;
        self.authorise(&current)?;

        let mut redirects = 0u32;
        loop {
            let response = self
                .client
                .request(method.clone(), current.clone())
                .send()
                .await
                .map_err(|e| VestError::Scan(format!("HTTP request failed: {e}")))?;

            let status = response.status();
            if status.is_redirection() {
                redirects += 1;
                if redirects > self.budgets.max_redirects {
                    return Err(VestError::Scan("redirect budget exhausted".into()));
                }
                let loc = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| VestError::Scan("redirect missing Location".into()))?;
                let next = current
                    .join(loc)
                    .map_err(|e| VestError::Scan(format!("bad redirect URL: {e}")))?;
                self.authorise(&next)?;
                current = next;
                continue;
            }

            let status_code = status.as_u16();
            let body = read_body_bounded(response, self.budgets.max_body_bytes).await?;
            return Ok((status_code, body));
        }
    }
}

async fn read_body_bounded(response: Response, max_bytes: usize) -> Result<String, VestError> {
    let bytes = response
        .bytes()
        .await
        .map_err(|e| VestError::Scan(format!("failed to read body: {e}")))?;
    let slice = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        &bytes
    };
    Ok(String::from_utf8_lossy(slice).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_server(
        handler: Arc<dyn Fn(String) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync>,
    ) -> (u16, Arc<AtomicBool>) {
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
                let mut buf = vec![0u8; 4096];
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
        let handler: Arc<dyn Fn(String) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync> =
            Arc::new(|_req| (200u16, vec![], b"ok".to_vec()));
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
        let handler: Arc<dyn Fn(String) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync> =
            Arc::new(|_req| {
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
}
