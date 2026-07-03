use vest_config::{load_config, VestConfig};

#[test]
fn test_load_config_with_binary_data() {
    let tmp = std::env::temp_dir().join("binary_config.toml");
    std::fs::write(&tmp, &[0x00u8, 0x01, 0xFF, 0xFE]).unwrap();
    let result = load_config(&tmp);
    assert!(result.is_err());
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn test_load_config_with_only_whitespace() {
    let tmp = std::env::temp_dir().join("whitespace.toml");
    std::fs::write(&tmp, "   \n  \n  \n").unwrap();
    let result = load_config(&tmp);
    assert!(result.is_err());
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn test_load_config_very_large_file() {
    let tmp = std::env::temp_dir().join("large_config.toml");
    let mut content = String::from("[general]\n[agent]\n[scanner]\n");
    for i in 0..1000 {
        content.push_str(&format!(
            "[profiles.profile_{}]\ndescription = \"Profile {}\"\n",
            i, i
        ));
    }
    std::fs::write(&tmp, &content).unwrap();
    let config = load_config(&tmp).unwrap();
    assert_eq!(config.profiles.len(), 1000);
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn test_parse_config_with_windows_line_endings() {
    let toml_str = "[general]\r\n[agent]\r\n[scanner]\r\n";
    let config: VestConfig = toml::from_str(toml_str).unwrap();
    assert!(config.scanner.memory.enabled);
}

#[test]
fn test_parse_config_with_duplicate_sections() {
    let toml_str = r#"
[general]
[agent]
[scanner]
[general]
"#;
    let result: Result<VestConfig, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_profile_name_with_special_characters() {
    let toml_str = r#"
[general]
[agent]
[scanner]
[profiles."my-profile-v2"]
description = "Has hyphens"
[profiles."profile.with.dots"]
description = "Has dots"
"#;
    let config: VestConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.profiles.len(), 2);
}

#[test]
fn test_parse_config_with_bom() {
    let mut toml = vec![0xEF, 0xBB, 0xBF];
    toml.extend(b"[general]\n[agent]\n[scanner]\n");
    let result: Result<VestConfig, _> = toml::from_str(std::str::from_utf8(&toml).unwrap());
    let _ = result;
}

#[test]
fn test_parse_config_with_comments_everywhere() {
    let toml_str = r#"
# Top-level comment
[general]
workspace_dir = "/custom" # inline comment
[agent] # section comment
# blank line comment

[scanner]
[scanner.memory]
enabled = false
# Disabled for testing
"#;
    let config: VestConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.general.workspace_dir, "/custom");
    assert!(!config.scanner.memory.enabled);
}

#[test]
fn test_parse_config_safety_edge_values() {
    let toml_str = r#"
[general]
[agent]
[scanner]
[safety]
write_approval = false
rate_limit_requests_per_second = 0
rate_limit_burst = 0
max_scan_duration_seconds = 1
max_concurrent_exploits = 0
allowed_targets = []
blocked_targets = []
allowed_networks = []
"#;
    let config: VestConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.safety.write_approval);
    assert_eq!(config.safety.rate_limit_requests_per_second, 0);
    assert_eq!(config.safety.max_concurrent_exploits, 0);
}

#[test]
fn test_parse_config_empty_profiles_section() {
    let toml_str = r#"
[general]
[agent]
[scanner]
"#;
    let config: VestConfig = toml::from_str(toml_str).unwrap();
    assert!(config.profiles.is_empty());
}

#[test]
fn test_parse_config_all_scanner_modules_individually_disabled() {
    let toml_str = r#"
[general]
[agent]
[scanner.memory]
enabled = false
[scanner.binary]
enabled = false
[scanner.web]
enabled = false
[scanner.browser]
enabled = false
[scanner.network]
enabled = false
[scanner.files]
enabled = false
"#;
    let config: VestConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.scanner.memory.enabled);
    assert!(!config.scanner.binary.enabled);
    assert!(!config.scanner.web.enabled);
    assert!(!config.scanner.browser.enabled);
    assert!(!config.scanner.network.enabled);
    assert!(!config.scanner.files.enabled);
}

#[test]
fn test_parse_config_extremely_long_value() {
    let toml_str = format!(
        r#"
[general]
workspace_dir = "{}"
[agent]
[scanner]
"#,
        "A".repeat(100000)
    );
    let config: VestConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(config.general.workspace_dir.len(), 100000);
}
