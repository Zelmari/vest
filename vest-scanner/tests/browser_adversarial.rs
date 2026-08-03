//! Adversarial browser scanner bounds — walk limits, symlink policy, navigate schemes.
#![cfg(feature = "browser")]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use vest_core::traits::Scanner;
use vest_core::types::{Target, TargetType};
use vest_scanner::browser::{
    browser_default_limits, parse_chrome_ws_debugger_url, read_target_files_bounded,
    validate_chrome_ws_debugger_url, validate_navigate_url, BrowserScanner,
    CDP_VERSION_BODY_MAX_BYTES,
};
use vest_scanner::files::FileTraversalLimits;

#[cfg(unix)]
use std::os::unix::fs::symlink;

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("vest-brw-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&p).unwrap();
    p
}

fn browser_target(path: &std::path::Path) -> Target {
    Target {
        id: "t".into(),
        name: path.display().to_string(),
        target_type: TargetType::Browser,
        path: Some(path.display().to_string()),
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn navigate_rejects_file_scheme() {
    let err = validate_navigate_url("file:///etc/passwd").unwrap_err();
    assert!(err.contains("file"), "{err}");
}

#[test]
fn navigate_allows_http_https_only() {
    assert!(validate_navigate_url("https://example.com/").is_ok());
    assert!(validate_navigate_url("ftp://example.com/").is_err());
}

#[test]
fn cdp_version_body_cap_is_bounded() {
    const {
        assert!(CDP_VERSION_BODY_MAX_BYTES <= 64 * 1024);
    }
}

#[test]
fn cdp_ws_debugger_url_must_be_loopback() {
    assert!(validate_chrome_ws_debugger_url("ws://127.0.0.1:9222/devtools/browser/abc").is_ok());
    assert!(validate_chrome_ws_debugger_url("ws://[::1]:9222/devtools/browser/abc").is_ok());
    assert!(validate_chrome_ws_debugger_url("ws://localhost:9222/devtools/browser/abc").is_ok());

    let err = parse_chrome_ws_debugger_url(
        r#"{"webSocketDebuggerUrl":"ws://203.0.113.50:9222/devtools/browser/hijack"}"#,
    )
    .unwrap_err();
    assert!(
        err.to_lowercase().contains("loopback"),
        "non-loopback CDP must fail closed: {err}"
    );
}

#[tokio::test]
async fn max_depth_stops_deep_nesting() {
    let root = temp_root("depth");
    let mut cur = root.clone();
    for i in 0..10 {
        cur = cur.join(format!("d{i}"));
        fs::create_dir_all(&cur).unwrap();
    }
    fs::write(
        cur.join("deep.js"),
        "localStorage.setItem('password', 'deep-browser-secret');",
    )
    .unwrap();

    let scanner = BrowserScanner::new().with_limits(FileTraversalLimits {
        max_depth: 2,
        max_files: 100,
        max_file_size_bytes: 1024 * 1024,
        max_total_bytes: 10_000_000,
        follow_symlinks: false,
        ignore_globs: vec![],
    });
    let findings = scanner.scan(&browser_target(&root)).await.unwrap();
    let blob = serde_json::to_string(&findings).unwrap();
    assert!(
        !blob.contains("deep-browser-secret"),
        "depth limit must stop traversal: {blob}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn symlink_to_outside_root_is_not_scanned_by_default() {
    let root = temp_root("symlink");
    let inside = root.join("in");
    let outside = root.join("out");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join("leak.js"),
        "localStorage.setItem('password', 'outside-browser-secret');",
    )
    .unwrap();
    fs::write(inside.join("ok.js"), "console.log(1);").unwrap();
    #[cfg(unix)]
    symlink(&outside, inside.join("link")).unwrap();

    let scanner = BrowserScanner::new().with_limits(browser_default_limits());
    let findings = scanner.scan(&browser_target(&inside)).await.unwrap();
    let blob = serde_json::to_string(&findings).unwrap();
    assert!(
        !blob.contains("outside-browser-secret"),
        "symlink escape must not surface outside secrets: {blob}"
    );

    let files = read_target_files_bounded(&inside, &browser_default_limits()).unwrap();
    let joined = files
        .iter()
        .map(|(_, c)| c.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!joined.contains("outside-browser-secret"));
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn max_files_truncates_collection() {
    let root = temp_root("maxfiles");
    for i in 0..20 {
        fs::write(
            root.join(format!("f{i}.js")),
            format!("localStorage.setItem('token', 'secret-{i}');"),
        )
        .unwrap();
    }
    let limits = FileTraversalLimits {
        max_depth: 4,
        max_files: 3,
        max_file_size_bytes: 1024 * 1024,
        max_total_bytes: 10_000_000,
        follow_symlinks: false,
        ignore_globs: vec![],
    };
    let files = read_target_files_bounded(&root, &limits).unwrap();
    assert!(
        files.len() <= 3,
        "expected at most 3 files, got {}",
        files.len()
    );
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn scan_rejects_file_url_target() {
    let scanner = BrowserScanner::new();
    let target = Target {
        id: "t".into(),
        name: "file".into(),
        target_type: TargetType::Browser,
        path: None,
        url_str: Some("file:///etc/passwd".into()),
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let err = scanner.scan(&target).await.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("file"),
        "got: {err}"
    );
}
