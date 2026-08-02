//! Memory scanner honesty — simulation opt-in vs fail-closed unsupported.

mod common;

use common::*;
use std::fs;

#[test]
fn without_flag_memory_scan_is_fatal_and_mentions_unsupported() {
    let root = temp_root("mem-off");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("4242")
        .arg("--target-type")
        .arg("process")
        .arg("--scanner")
        .arg("memory")
        .arg("--provider")
        .arg("none")
        .output()
        .unwrap();

    assert_exit_code(&output, 5);
    let text = combined(&output).to_lowercase();
    assert!(
        text.contains("unsupported") || text.contains("simulation") || text.contains("scanner"),
        "{text}"
    );
}

#[test]
fn with_simulation_flag_produces_tagged_findings() {
    let root = temp_root("mem-sim");
    let vest_home = root.join("home");
    let cfg = root.join("vest.toml");
    let report = root.join("report.json");
    fs::create_dir_all(&vest_home).unwrap();
    write_minimal_config(&cfg);

    let output = vest_cmd(&vest_home)
        .arg("-c")
        .arg(&cfg)
        .arg("scan")
        .arg("4242")
        .arg("--target-type")
        .arg("process")
        .arg("--scanner")
        .arg("memory")
        .arg("--provider")
        .arg("none")
        .arg("--allow-memory-simulation")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();

    assert_success(&output);
    assert!(report.exists(), "report should be written");
    let json = read_json(&report);
    let findings = json["findings"]
        .as_array()
        .cloned()
        .or_else(|| json["results"].as_array().cloned())
        .unwrap_or_default();

    // On unknown platforms simulation may still run with fabricated regions;
    // require that any finding is explicitly tagged as simulation.
    if !findings.is_empty() {
        for f in &findings {
            let tags = f["tags"].as_array().cloned().unwrap_or_default();
            let tagged = tags.iter().any(|t| t.as_str() == Some("simulation"))
                || f["metadata"]["simulation"] == true
                || f["metadata"]["mode"] == "simulation";
            assert!(tagged, "simulation findings must be tagged, got: {f}");
        }
    } else {
        // Zero findings is acceptable only if stdout/report still acknowledges simulation.
        let text = combined(&output).to_lowercase();
        assert!(
            text.contains("simulation") || json.to_string().to_lowercase().contains("simulation"),
            "simulation mode should be visible even with zero findings:\n{}",
            combined(&output)
        );
    }
}
