//! N1 dry-run contract: validate config/target/scopes, print plan, no side effects.

mod common;

use common::*;
use std::fs;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

#[test]
fn dry_run_prints_plan_and_skips_side_effects() {
    let root = temp_root("dry-run-plan");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "password = \"test-only-secret\"\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("file")
        .arg("--scanner")
        .arg("files")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(out.contains("DRY RUN"), "stdout:\n{out}");
    assert!(out.contains("files"), "scanners missing:\n{out}");
    assert!(
        out.contains("Active probes: off") || out.contains("Active probes:"),
        "probes line missing:\n{out}"
    );
    assert!(out.contains("none"), "provider missing:\n{out}");
    assert!(
        out.contains("FS scope:") && !out.contains("FS scope:    (none)"),
        "fs scope should be resolved:\n{out}"
    );
    assert!(out.contains("Net scope:"), "net scope line missing:\n{out}");
    assert!(
        !vest_home.join("vest.db").exists(),
        "dry-run must not create the database"
    );
}

#[test]
fn dry_run_invalid_target_type_is_nonzero() {
    let root = temp_root("dry-run-bad-type");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let fixture = root.join("fixture.txt");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);
    fs::write(&fixture, "x\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg(&fixture)
        .arg("--target-type")
        .arg("not-a-real-type")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "invalid --target-type must fail on dry-run\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_exit_code(&output, 2); // INVALID_INPUT
    assert!(!vest_home.join("vest.db").exists());
}

#[test]
fn dry_run_bad_config_is_nonzero() {
    let root = temp_root("dry-run-bad-cfg");
    let vest_home = root.join("home");
    let bad = root.join("bad.toml");

    fs::create_dir_all(&vest_home).unwrap();
    fs::write(&bad, "not = {{{ toml\n").unwrap();

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&bad)
        .arg("scan")
        .arg("ignored")
        .arg("--target-type")
        .arg("file")
        .arg("--provider")
        .arg("none")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "bad config must fail on dry-run\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_exit_code(&output, 3); // CONFIG
    assert!(!vest_home.join("vest.db").exists());
}

#[test]
fn dry_run_web_plan_shows_probes_and_net_scope_without_hitting_listener() {
    let root = temp_root("dry-run-web");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit_flag = std::sync::Arc::clone(&hit);
    let _accept = thread::spawn(move || {
        // Brief accept window: any connection means dry-run made a network request.
        let _ = listener.set_nonblocking(true);
        for _ in 0..20 {
            if listener.accept().is_ok() {
                hit_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    });

    let url = format!("http://127.0.0.1:{port}/");
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
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(out.contains("DRY RUN"), "stdout:\n{out}");
    assert!(out.contains("web"), "scanners missing:\n{out}");
    assert!(
        out.contains("Active probes: off"),
        "probes should be off by default:\n{out}"
    );
    assert!(
        out.contains("Net scope:") && out.contains("127.0.0.1"),
        "net scope should include target origin:\n{out}"
    );
    assert!(
        !hit.load(std::sync::atomic::Ordering::SeqCst),
        "dry-run must not open a network connection to the target"
    );
    assert!(!vest_home.join("vest.db").exists());
}

#[test]
fn dry_run_reflects_allow_active_probes_flag() {
    let root = temp_root("dry-run-probes-on");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");

    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("https://example.com")
        .arg("--target-type")
        .arg("web")
        .arg("--scanner")
        .arg("web")
        .arg("--provider")
        .arg("none")
        .arg("--allow-active-probes")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert_exit_code(&output, 0);
    let out = stdout(&output);
    assert!(
        out.contains("Active probes: on"),
        "CLI flag should turn probes on in the plan:\n{out}"
    );
}
