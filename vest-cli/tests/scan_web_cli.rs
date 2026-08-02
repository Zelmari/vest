//! Web scan via the real `vest` binary against a local loopback server.

mod common;

use common::*;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
