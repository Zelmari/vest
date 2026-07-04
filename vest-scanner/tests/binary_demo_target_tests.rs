use chrono::Utc;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use vest_core::types::{Target, TargetType};
use vest_core::Scanner;
use vest_scanner::binary::BinaryScanner;

static COMPILE_LOCK: Mutex<()> = Mutex::new(());

fn compile_demo_binary() -> Option<String> {
    let _lock = COMPILE_LOCK.lock().unwrap();

    let makefile_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("examples")
        .join("demo-target")
        .join("vulnerable-binary");

    let output_path = makefile_dir.join("vuln");

    if output_path.exists() {
        return Some(output_path.to_string_lossy().to_string());
    }

    let has_gcc = Command::new("gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !has_gcc {
        return None;
    }

    let source = makefile_dir.join("vuln.c");
    let status = Command::new("gcc")
        .args([
            "-fno-stack-protector",
            "-no-pie",
            "-o",
            output_path.to_str().unwrap(),
            source.to_str().unwrap(),
        ])
        .status()
        .ok()?;

    if status.success() {
        Some(output_path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn create_sink_catalog() -> (String, std::path::PathBuf) {
    let dir = std::env::temp_dir();
    let path = dir.join("vest_demo_sinks.txt");
    let mut f = std::fs::File::create(&path).expect("Failed to create sink catalog");
    writeln!(f, "gets").unwrap();
    writeln!(f, "strcpy").unwrap();
    writeln!(f, "system").unwrap();
    writeln!(f, "printf").unwrap();
    writeln!(f, "sprintf").unwrap();
    writeln!(f, "popen").unwrap();
    (path.to_string_lossy().to_string(), path)
}

fn make_target(binary_path: &str, id: &str) -> Target {
    Target {
        id: id.into(),
        name: "vuln".into(),
        target_type: TargetType::Binary,
        path: Some(binary_path.to_string()),
        url_str: None,
        pid: None,
        host: None,
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_compile_demo_binary() {
    let binary_path = compile_demo_binary();
    match binary_path {
        Some(ref p) => {
            assert!(
                Path::new(p).exists(),
                "Compiled binary should exist at {}",
                p
            );
        }
        None => {
            eprintln!("SKIP: gcc not available — cannot compile demo binary");
        }
    }
}

#[test]
fn test_scan_demo_binary_finds_dangerous_sinks() {
    let binary_path = match compile_demo_binary() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: gcc not available or compilation failed");
            return;
        }
    };

    let (sink_catalog_path, _sink_file) = create_sink_catalog();

    let scanner = BinaryScanner::new().with_sink_catalogs(vec![sink_catalog_path]);

    let target = make_target(&binary_path, "test-sink-scan");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let findings = rt
        .block_on(scanner.scan(&target))
        .expect("Scan should succeed");

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    let titles_str = titles.join(", ");

    let has_gets = findings.iter().any(|f| f.title.contains("gets"));
    let has_strcpy = findings.iter().any(|f| f.title.contains("strcpy"));
    let has_system = findings.iter().any(|f| f.title.contains("system"));
    let has_printf = findings.iter().any(|f| f.title.contains("printf"));

    assert!(
        has_gets || has_strcpy || has_system || has_printf,
        "Should find at least one dangerous sink function. Found titles: {}",
        titles_str
    );

    let _ = std::fs::remove_file(_sink_file);
}

#[test]
fn test_scan_demo_binary_mitigation_check() {
    let binary_path = match compile_demo_binary() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: gcc not available or compilation failed");
            return;
        }
    };

    let scanner = BinaryScanner::new();

    let target = make_target(&binary_path, "test-mitigations");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let findings = rt
        .block_on(scanner.scan(&target))
        .expect("Scan should succeed");

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    let titles_str = titles.join(" | ");

    let has_no_pie = findings.iter().any(|f| f.title.contains("ASLR/PIE"));
    let has_no_canary = findings.iter().any(|f| f.title.contains("Stack canaries"));

    assert!(
        has_no_pie || has_no_canary,
        "Should find at least one missing mitigation (no PIE or no canary). Found: {}",
        titles_str
    );
}

#[test]
fn test_scan_demo_binary_rop_scan_runs() {
    let binary_path = match compile_demo_binary() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: gcc not available or compilation failed");
            return;
        }
    };

    let scanner = BinaryScanner::new().with_rop(true);

    let target = make_target(&binary_path, "test-rop");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let findings = rt
        .block_on(scanner.scan(&target))
        .expect("Scan should succeed");

    let has_rop = findings.iter().any(|f| f.title.contains("ROP gadgets"));
    if cfg!(target_arch = "x86_64") {
        assert!(
            has_rop,
            "On x86_64, should find ROP gadgets. Found: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    } else {
        eprintln!(
            "ROP gadgets found on non-x86_64: {}",
            if has_rop {
                "yes"
            } else {
                "no (expected for ARM64)"
            }
        );
    }
}

#[test]
fn test_scan_demo_binary_extracts_symbols() {
    let binary_path = match compile_demo_binary() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: gcc not available or compilation failed");
            return;
        }
    };

    let scanner = BinaryScanner::new();

    let target = make_target(&binary_path, "test-symbols");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(scanner.scan(&target));
    assert!(
        result.is_ok(),
        "Binary scan should succeed and extract symbols. Error: {:?}",
        result.err()
    );
}
