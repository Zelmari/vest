//! Adversarial filesystem traversal — symlink escapes, depth bombs, ignore rules.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use vest_core::traits::Scanner;
use vest_core::types::{Target, TargetType};
use vest_scanner::files::{FileScanner, FileTraversalLimits};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("vest-files-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&p).unwrap();
    p
}

fn file_target(path: &std::path::Path) -> Target {
    Target {
        id: "t".into(),
        name: path.display().to_string(),
        target_type: TargetType::File,
        path: Some(path.display().to_string()),
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn symlink_to_outside_root_is_not_scanned_by_default() {
    let root = temp_root("symlink");
    let inside = root.join("in");
    let outside = root.join("out");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join("leak.env"),
        "password = \"outside-only-secret\"\n",
    )
    .unwrap();
    fs::write(inside.join("ok.txt"), "hello\n").unwrap();
    symlink(&outside, inside.join("link")).unwrap();

    let scanner = FileScanner::new().with_limits(FileTraversalLimits {
        max_file_size_bytes: 8 * 1024 * 1024,
        max_depth: 8,
        max_files: 100,
        max_total_bytes: 10_000_000,
        follow_symlinks: false,
        ignore_globs: vec![],
    });
    let findings = scanner.scan(&file_target(&inside)).await.unwrap();
    let blob = serde_json::to_string(&findings).unwrap();
    assert!(
        !blob.contains("outside-only-secret"),
        "symlink escape must not surface outside secrets: {blob}"
    );
}

/// K9: with `follow_symlinks: true`, a link into a sibling `/tmp` tree outside the
/// canonical scan root must not pull secrets into findings.
#[tokio::test]
async fn follow_symlinks_true_does_not_escape_to_tmp_outside_root() {
    let root = temp_root("symlink-follow");
    let inside = root.join("in");
    fs::create_dir_all(&inside).unwrap();

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let outside = std::env::temp_dir().join(format!(
        "vest-files-escape-target-{}-{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join("leak.env"),
        "password = \"tmp-escape-secret\"\n",
    )
    .unwrap();
    fs::write(inside.join("ok.env"), "password = \"inside-ok-secret\"\n").unwrap();
    symlink(&outside, inside.join("escape")).unwrap();

    let scanner = FileScanner::new().with_limits(FileTraversalLimits {
        max_file_size_bytes: 8 * 1024 * 1024,
        max_depth: 8,
        max_files: 100,
        max_total_bytes: 10_000_000,
        follow_symlinks: true,
        ignore_globs: vec![],
    });
    let findings = scanner.scan(&file_target(&inside)).await.unwrap();
    let blob = serde_json::to_string(&findings).unwrap();
    assert!(
        !blob.contains("tmp-escape-secret"),
        "follow_symlinks=true must contain under root; /tmp escape must not surface: {blob}"
    );
    assert!(
        blob.contains("inside-ok-secret"),
        "in-root secrets must still be scanned when follow_symlinks=true: {blob}"
    );

    let _ = fs::remove_dir_all(&outside);
}

#[tokio::test]
async fn max_depth_stops_deep_nesting() {
    let root = temp_root("depth");
    let mut cur = root.clone();
    for i in 0..12 {
        cur = cur.join(format!("d{i}"));
        fs::create_dir_all(&cur).unwrap();
    }
    fs::write(cur.join("deep.env"), "password = \"deep-secret\"\n").unwrap();

    let scanner = FileScanner::new().with_limits(FileTraversalLimits {
        max_file_size_bytes: 8 * 1024 * 1024,
        max_depth: 3,
        max_files: 1000,
        max_total_bytes: 10_000_000,
        follow_symlinks: false,
        ignore_globs: vec![],
    });
    let findings = scanner.scan(&file_target(&root)).await.unwrap();
    let blob = serde_json::to_string(&findings).unwrap();
    assert!(
        !blob.contains("deep-secret"),
        "depth limit must stop traversal before deep secret: {blob}"
    );
}

#[tokio::test]
async fn ignore_globs_skip_matching_files() {
    let root = temp_root("ignore");
    fs::write(root.join("keep.env"), "password = \"keep-me\"\n").unwrap();
    fs::write(root.join("skip.env"), "password = \"skip-me\"\n").unwrap();

    let scanner = FileScanner::new().with_limits(FileTraversalLimits {
        max_file_size_bytes: 8 * 1024 * 1024,
        max_depth: 4,
        max_files: 100,
        max_total_bytes: 10_000_000,
        follow_symlinks: false,
        ignore_globs: vec!["skip.env".into()],
    });
    let findings = scanner.scan(&file_target(&root)).await.unwrap();
    let blob = serde_json::to_string(&findings).unwrap();
    assert!(
        !blob.contains("skip-me"),
        "ignored file must not contribute findings: {blob}"
    );
}
