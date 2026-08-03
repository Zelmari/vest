use reqwest::Client;
use std::time::Duration;

/// Default HTTP timeout when `ProviderConfig.timeout_seconds` is unset.
pub const DEFAULT_PROVIDER_TIMEOUT_SECS: u64 = 120;

/// Build a reqwest client with a hard request timeout (PROV-3).
///
/// Automatic redirects are disabled (`Policy::none`), matching scanner
/// `ScopedHttpClient` — callers must not silently follow `Location` hops (B2).
pub fn build_provider_client(timeout_seconds: Option<u64>) -> Client {
    let secs = timeout_seconds
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_PROVIDER_TIMEOUT_SECS);
    Client::builder()
        .timeout(Duration::from_secs(secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build provider HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn build_provider_client_accepts_explicit_timeout() {
        let _ = build_provider_client(Some(1));
    }

    #[test]
    fn build_provider_client_defaults_when_none_or_zero() {
        let _ = build_provider_client(None);
        let _ = build_provider_client(Some(0));
    }

    #[tokio::test]
    async fn build_provider_client_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let followed_hits = Arc::new(AtomicUsize::new(0));
        let hits = followed_hits.clone();

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
                let req = String::from_utf8_lossy(&buf[..n]);
                let resp = if req.starts_with("GET /followed") {
                    hits.fetch_add(1, Ordering::Relaxed);
                    "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nsecret-followed"
                        .to_string()
                } else {
                    "HTTP/1.1 302 Found\r\nLocation: /followed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let client = build_provider_client(Some(5));
        let url = format!("http://127.0.0.1:{port}/start");
        let resp = client.get(&url).send().await.unwrap();
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        stop.store(true, Ordering::Relaxed);

        assert_eq!(
            status,
            reqwest::StatusCode::FOUND,
            "client must surface 302 instead of following"
        );
        assert!(
            !body.contains("secret-followed"),
            "must not return redirect-target body"
        );
        assert_eq!(
            followed_hits.load(Ordering::Relaxed),
            0,
            "redirect target must not be fetched"
        );
    }
}
