//! K3 regression: agent `http_get` / `http_post` must use ScopedHttpClient
//! (redirect re-auth) and never return a cross-origin evil body.

use super::{agent_http_get, agent_http_post, build_tool_registry};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vest_agent::{ApprovedFilesystemScope, ApprovedNetworkScope, ExecutionSession};

fn spawn_static_server(body: &'static [u8]) -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let mut bytes = resp.into_bytes();
                    bytes.extend_from_slice(body);
                    let _ = sock.write_all(&bytes);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    thread::sleep(Duration::from_millis(80));
    (port, stop)
}

fn spawn_redirect_escape_server(evil_port: u16) -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf);
                    let location = format!("http://127.0.0.1:{evil_port}/secret");
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(resp.as_bytes());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    thread::sleep(Duration::from_millis(80));
    (port, stop)
}

fn spawn_probe_counting_server(body: &'static [u8]) -> (u16, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let probe_hits = Arc::new(AtomicUsize::new(0));
    let hits = probe_hits.clone();
    thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let mut buf = [0u8; 8192];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.contains(".env") || req.contains(".git") {
                        hits.fetch_add(1, Ordering::Relaxed);
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let mut bytes = resp.into_bytes();
                    bytes.extend_from_slice(body);
                    let _ = sock.write_all(&bytes);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    thread::sleep(Duration::from_millis(80));
    (port, stop, probe_hits)
}

fn session_for_url(url: &str) -> Arc<ExecutionSession> {
    let net = ApprovedNetworkScope::new([url]).unwrap();
    ExecutionSession::new(ApprovedFilesystemScope::empty(), net, false).into_arc()
}

fn agent_http_get_with_retry(session: &Arc<ExecutionSession>, url: &str) -> serde_json::Value {
    let mut last = None;
    for attempt in 0..12 {
        match agent_http_get(session, url) {
            Ok(v) if v.get("status").and_then(|s| s.as_u64()) == Some(200) => return v,
            Ok(v) => {
                last = Some(format!("unexpected payload: {v}"));
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) if attempt + 1 < 12 => {
                last = Some(e.to_string());
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => panic!("agent_http_get failed after retries: {e}"),
        }
    }
    panic!(
        "agent_http_get produced no successful result: {}",
        last.unwrap_or_default()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_http_get_same_origin_ok() {
    let (port, stop) = spawn_static_server(b"hello-agent");
    let url = format!("http://127.0.0.1:{port}/");
    let session = session_for_url(&url);

    let out = agent_http_get_with_retry(&session, &url);
    stop.store(true, Ordering::Relaxed);

    assert_eq!(out["status"], 200);
    assert_eq!(out["body"], "hello-agent");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_http_get_cross_origin_redirect_does_not_return_evil_body() {
    let (evil_port, evil_stop) = spawn_static_server(b"SECRET_SHOULD_NOT_BE_FETCHED");
    let (port, stop) = spawn_redirect_escape_server(evil_port);
    let url = format!("http://127.0.0.1:{port}/");
    let session = session_for_url(&url);

    let err = agent_http_get(&session, &url).unwrap_err();
    stop.store(true, Ordering::Relaxed);
    evil_stop.store(true, Ordering::Relaxed);

    let err_s = err.to_string();
    let err_l = err_s.to_lowercase();
    assert!(
        err_l.contains("outside") || err_l.contains("origin") || err_l.contains("scope"),
        "expected scope/origin denial, got: {err_s}"
    );
    assert!(
        !err_s.contains("SECRET_SHOULD_NOT_BE_FETCHED"),
        "error must not include evil body: {err_s}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_http_post_cross_origin_redirect_does_not_return_evil_body() {
    let (evil_port, evil_stop) = spawn_static_server(b"SECRET_SHOULD_NOT_BE_FETCHED");
    let (port, stop) = spawn_redirect_escape_server(evil_port);
    let url = format!("http://127.0.0.1:{port}/");
    let session = session_for_url(&url);

    let err = agent_http_post(&session, &url, &serde_json::json!({"a": 1})).unwrap_err();
    stop.store(true, Ordering::Relaxed);
    evil_stop.store(true, Ordering::Relaxed);

    let err_s = err.to_string();
    assert!(
        !err_s.contains("SECRET_SHOULD_NOT_BE_FETCHED"),
        "error must not include evil body: {err_s}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_http_get_unicode_body_truncates_without_panic() {
    // Body larger than 8000 chars with multibyte scalars near the cut.
    let mut body = "你好".repeat(5000);
    body.push_str("世界");
    let body_bytes = body.into_bytes();
    // Leak for 'static server body.
    let leaked: &'static [u8] = Box::leak(body_bytes.into_boxed_slice());
    let (port, stop) = spawn_static_server(leaked);
    let url = format!("http://127.0.0.1:{port}/");
    let session = session_for_url(&url);

    let out = agent_http_get_with_retry(&session, &url);
    stop.store(true, Ordering::Relaxed);

    let returned = out["body"].as_str().unwrap();
    assert!(returned.chars().count() <= 8000);
    assert!(returned.is_char_boundary(returned.len()));
}

#[tokio::test(flavor = "multi_thread")]
async fn web_scan_tool_passive_by_default_skips_env_git_probes() {
    let html = b"<html><body>ok</body></html>";
    let (port, stop, hits) = spawn_probe_counting_server(html);
    let url = format!("http://127.0.0.1:{port}/");
    let session = session_for_url(&url);
    let registry = build_tool_registry(Arc::clone(&session), false);
    let tool = registry.get_tool("web_scan").unwrap();

    let out = invoke_web_scan_with_retry(&tool.handler, &url);
    stop.store(true, Ordering::Relaxed);

    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "passive web_scan must not hit .env/.git"
    );
    assert_eq!(out["active_probes"], false);
    assert_eq!(out["status"], 200);
}

fn invoke_web_scan_with_retry(
    handler: &Arc<
        dyn Fn(serde_json::Value) -> Result<serde_json::Value, vest_agent::ToolError> + Send + Sync,
    >,
    url: &str,
) -> serde_json::Value {
    let mut last_err = None;
    for attempt in 0..12 {
        match handler(serde_json::json!({"url": url})) {
            Ok(v) if v.get("status").and_then(|s| s.as_u64()) == Some(200) => return v,
            Ok(v) => {
                last_err = Some(format!("unexpected status payload: {v}"));
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) if attempt + 1 < 12 => {
                last_err = Some(e.to_string());
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => panic!("web_scan failed after retries: {e}"),
        }
    }
    panic!(
        "web_scan produced no successful result: {}",
        last_err.unwrap_or_default()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn web_scan_tool_active_probes_hit_env_git_when_granted() {
    let html = b"<html><body>ok</body></html>";
    let (port, stop, hits) = spawn_probe_counting_server(html);
    let url = format!("http://127.0.0.1:{port}/");
    let session = session_for_url(&url);
    let registry = build_tool_registry(Arc::clone(&session), true);
    let tool = registry.get_tool("web_scan").unwrap();

    let _out = invoke_web_scan_with_retry(&tool.handler, &url);
    stop.store(true, Ordering::Relaxed);

    assert!(
        hits.load(Ordering::Relaxed) > 0,
        "granted active probes must request .env/.git paths"
    );
}
