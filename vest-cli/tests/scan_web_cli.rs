//! Web scan via the real `vest` binary against a local loopback server.

mod common;

use common::*;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// HTML with a form so active XSS/SQLi probes have something to POST against when enabled.
const PROBE_BAIT_HTML: &[u8] =
    b"<html><body><form action=\"/login\" method=\"POST\"><input name=\"q\" type=\"text\"></form></body></html>";

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
    thread::sleep(Duration::from_millis(30));
    (port, stop)
}

/// Loopback server that counts classic active-probe request signatures.
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
                    // Paths / patterns exercised by WebScanner when allow_active_probes is true.
                    if req.contains(".env")
                        || req.contains(".git")
                        || req.contains("POST")
                        || req.contains("alert")
                    {
                        hits.fetch_add(1, Ordering::Relaxed);
                    }
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
    thread::sleep(Duration::from_millis(30));
    (port, stop, probe_hits)
}

fn write_config_with_active_probes(path: &std::path::Path, allow: bool) {
    write_minimal_config(path);
    let mut toml = fs::read_to_string(path).unwrap();
    toml = toml.replacen(
        "[scanner.web]\nenabled = true\n",
        &format!("[scanner.web]\nenabled = true\nallow_active_probes = {allow}\n"),
        1,
    );
    fs::write(path, toml).unwrap();
}

fn run_cli_web_scan(
    vest_home: &std::path::Path,
    cfg: &std::path::Path,
    url: &str,
    report: &std::path::Path,
    extra_args: &[&str],
) -> std::process::Output {
    let mut cmd = vest_cmd(vest_home);
    cmd.arg("-c")
        .arg(cfg)
        .arg("scan")
        .arg(url)
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("web")
        .arg("--provider")
        .arg("none")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(report);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.output().unwrap()
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
    thread::sleep(Duration::from_millis(30));
    (port, stop)
}

#[test]
fn cli_web_scan_against_local_server_succeeds() {
    let html = b"<html><body><h1>ok</h1><a href=\"/page\">p</a></body></html>";
    let (port, stop) = spawn_static_server(html);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-ok");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&url)
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("web")
        .arg("--provider")
        .arg("none")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();

    stop.store(true, Ordering::Relaxed);
    assert_success(&output);
    assert!(report.exists());
    let json = read_json(&report);
    assert_eq!(json["target"]["type"], "web");
}

#[test]
fn cli_web_scan_redirect_escape_does_not_crash_or_follow_off_origin() {
    // Victim origin redirects to a different port (different origin). Scanner must not crash.
    let (evil_port, evil_stop) = spawn_static_server(b"SECRET_SHOULD_NOT_BE_FETCHED");
    let (port, stop) = spawn_redirect_escape_server(evil_port);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-redir");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&url)
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("web")
        .arg("--provider")
        .arg("none")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();

    stop.store(true, Ordering::Relaxed);
    evil_stop.store(true, Ordering::Relaxed);

    // Success or graceful scanner-contained failure is acceptable; panic/hang is not.
    // Redirect escape must never dump the evil body into the report.
    if report.exists() {
        let body = fs::read_to_string(&report).unwrap();
        assert!(
            !body.contains("SECRET_SHOULD_NOT_BE_FETCHED"),
            "redirect escape must not fetch off-origin body into report"
        );
    } else {
        assert!(
            !output.status.success() || combined(&output).contains("redirect"),
            "unexpected outcome:\n{}",
            combined(&output)
        );
    }
}

#[test]
fn cli_web_scan_passive_by_default_does_not_hit_active_probe_paths() {
    let (port, stop, probe_hits) = spawn_probe_counting_server(PROBE_BAIT_HTML);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-passive");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    // Minimal config omits allow_active_probes → serde default false.
    write_minimal_config(&cfg);

    let output = run_cli_web_scan(&vest_home, &cfg, &url, &report, &[]);

    stop.store(true, Ordering::Relaxed);
    assert_success(&output);
    assert_eq!(
        probe_hits.load(Ordering::Relaxed),
        0,
        "default CLI web scan must not request .env/.git/POST/XSS probe paths"
    );
}

#[test]
fn cli_web_scan_allow_alone_does_not_hit_active_probe_paths() {
    let (port, stop, probe_hits) = spawn_probe_counting_server(PROBE_BAIT_HTML);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-allow-no-confirm");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = run_cli_web_scan(&vest_home, &cfg, &url, &report, &["--allow-active-probes"]);

    stop.store(true, Ordering::Relaxed);
    assert_success(&output);
    assert_eq!(
        probe_hits.load(Ordering::Relaxed),
        0,
        "--allow-active-probes without confirm must not run active probes"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not confirmed") || err.contains("confirm-active-probes"),
        "must warn that probes need second consent key:\n{err}"
    );
}

#[test]
fn cli_web_scan_config_alone_does_not_hit_active_probe_paths() {
    let (port, stop, probe_hits) = spawn_probe_counting_server(PROBE_BAIT_HTML);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-cfg-no-confirm");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_config_with_active_probes(&cfg, true);

    let output = run_cli_web_scan(&vest_home, &cfg, &url, &report, &[]);

    stop.store(true, Ordering::Relaxed);
    assert_success(&output);
    assert_eq!(
        probe_hits.load(Ordering::Relaxed),
        0,
        "config allow_active_probes alone must not run active probes without confirm"
    );
}

#[test]
fn cli_web_scan_allow_and_confirm_hits_probe_paths() {
    let (port, stop, probe_hits) = spawn_probe_counting_server(PROBE_BAIT_HTML);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-active-two-key");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = run_cli_web_scan(
        &vest_home,
        &cfg,
        &url,
        &report,
        &["--allow-active-probes", "--confirm-active-probes"],
    );

    stop.store(true, Ordering::Relaxed);
    assert_success(&output);
    assert!(
        probe_hits.load(Ordering::Relaxed) > 0,
        "allow + confirm must exercise active probe paths (.env/.git/POST/XSS)"
    );
    let err = stderr(&output);
    assert!(
        err.contains("CONSENT: active web probes ENABLED"),
        "must acknowledge two-key consent on stderr:\n{err}"
    );
}

#[test]
fn cli_web_scan_config_and_approve_exploits_hits_probe_paths() {
    let (port, stop, probe_hits) = spawn_probe_counting_server(PROBE_BAIT_HTML);
    let url = format!("http://127.0.0.1:{port}/");

    let root = temp_root("web-active-cfg-approve");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_config_with_active_probes(&cfg, true);

    let output = run_cli_web_scan(&vest_home, &cfg, &url, &report, &["--approve-exploits"]);

    // Let in-flight probe requests finish counting before stopping the listener.
    thread::sleep(Duration::from_millis(50));
    stop.store(true, Ordering::Relaxed);
    assert_success(&output);
    let err = stderr(&output);
    assert!(
        err.contains("CONSENT: active web probes ENABLED"),
        "must acknowledge two-key consent on stderr:\n{err}"
    );
    assert!(
        probe_hits.load(Ordering::Relaxed) > 0,
        "config allow + --approve-exploits must exercise active probe paths\nstderr:\n{err}"
    );
}

#[test]
fn cli_rejects_non_http_web_target() {
    let root = temp_root("web-file-scheme");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("file:///etc/passwd")
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("web")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "file:// web target must fail closed\n{}",
        combined(&output)
    );
    let text = combined(&output).to_lowercase();
    assert!(
        text.contains("scheme") || text.contains("http") || text.contains("invalid"),
        "should explain scheme rejection:\n{}",
        combined(&output)
    );
}
