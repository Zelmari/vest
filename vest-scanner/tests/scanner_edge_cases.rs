use vest_scanner::memory::MemoryRegion;
use vest_scanner::memory::MemoryScanner;

#[test]
fn test_pattern_scan_odd_length_pattern() {
    let data = vec![0x41, 0x42, 0x43, 0x44];
    let matches = MemoryScanner::scan_pattern(&data, "41");
    assert!(!matches.is_empty());
}

#[test]
fn test_pattern_scan_mixed_case_and_formatting() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let patterns = ["DE AD BE EF", "de ad be ef", "De Ad Be Ef"];
    for p in &patterns {
        let matches = MemoryScanner::scan_pattern(&data, p);
        assert_eq!(matches, vec![0], "Failed for pattern: {}", p);
    }
}

#[test]
fn test_pattern_scan_invalid_hex_graceful() {
    let data = vec![0x00, 0x01];
    let weird_patterns = [
        "GG HH",
        "## $$",
        "12 ZZ 34",
        "",
        "   ",
        "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ];
    for p in &weird_patterns {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MemoryScanner::scan_pattern(&data, p)
        }));
        assert!(result.is_ok(), "Panicked on pattern: {}", p);
    }
}

#[test]
fn test_memory_region_edge_cases() {
    let r = MemoryRegion {
        name: "".into(),
        base_address: 0,
        size: 0,
        permissions: "".into(),
        module_name: None,
    };
    assert!(!r.is_rwx());
    assert!(!r.is_executable());

    let r = MemoryRegion {
        name: "max".into(),
        base_address: u64::MAX,
        size: 1,
        permissions: "R".into(),
        module_name: None,
    };
    assert!(r.is_readable());
    assert_eq!(r.base_address, u64::MAX);

    let r = MemoryRegion {
        name: "A".repeat(10000),
        base_address: 0x1000,
        size: 4096,
        permissions: "RX".into(),
        module_name: Some("B".repeat(10000)),
    };
    assert!(r.is_executable());
    assert_eq!(r.name.len(), 10000);
}

#[test]
fn test_suspicious_regions_empty_list() {
    let findings = MemoryScanner::check_suspicious_regions(&[]);
    assert!(findings.is_empty());
}

#[test]
fn test_check_suspicious_regions_all_rwx() {
    let regions: Vec<MemoryRegion> = (0..100)
        .map(|i| MemoryRegion {
            name: format!("region-{}", i),
            base_address: 0x1000 + (i * 4096) as u64,
            size: 4096,
            permissions: "RWX".into(),
            module_name: None,
        })
        .collect();

    let findings = MemoryScanner::check_suspicious_regions(&regions);
    assert_eq!(findings.len(), 100);
}

#[test]
fn test_hook_detection_empty_data() {
    let region = MemoryRegion {
        name: "test".into(),
        base_address: 0x1000,
        size: 0,
        permissions: "RX".into(),
        module_name: None,
    };
    let region_data: Vec<(&MemoryRegion, Vec<u8>)> = vec![(&region, vec![])];
    let findings = MemoryScanner::detect_hooks(&region_data);
    assert!(findings.is_empty());
}

#[test]
fn test_hook_detection_large_data_no_hooks() {
    let region = MemoryRegion {
        name: "clean".into(),
        base_address: 0x1000,
        size: 100000,
        permissions: "RX".into(),
        module_name: None,
    };
    let data = vec![0x90u8; 100000];
    let region_data = vec![(&region, data)];
    let findings = MemoryScanner::detect_hooks(&region_data);
    assert!(findings.is_empty());
}

#[test]
fn test_simulated_regions_unknown_platform() {
    let regions = MemoryScanner::get_simulated_regions("haiku");
    assert!(regions.is_empty());
}

#[test]
fn test_platform_detection_is_valid() {
    let platform = MemoryScanner::detect_platform();
    let valid = ["windows", "linux", "macos", "unknown"];
    assert!(
        valid.contains(&platform),
        "Unexpected platform: {}",
        platform
    );
}

#[test]
fn test_read_memory_at_boundary_addresses() {
    let data = MemoryScanner::read_memory(0, 0);
    assert!(data.is_empty());

    let data = MemoryScanner::read_memory(0, 1);
    assert_eq!(data.len(), 1);

    let data = MemoryScanner::read_memory(u64::MAX, 1);
    assert!(data.len() <= 1);
}

#[test]
fn test_pattern_scan_all_wildcards() {
    let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let pattern = "?? ?? ??";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert!(!matches.is_empty());
}

#[test]
fn test_pattern_scan_longer_than_data() {
    let data = vec![0x01, 0x02];
    let pattern = "01 02 03 04 05";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert!(matches.is_empty());
}

#[test]
fn test_pattern_scan_fast_with_wildcards() {
    let data = vec![0x00, 0x01, 0xFF, 0x03, 0x01, 0x02, 0x03];
    let pattern = "01 ?? 03";
    let matches = MemoryScanner::scan_pattern_fast(&data, pattern);
    assert!(!matches.is_empty());
    assert!(matches.contains(&1));
}

#[test]
fn test_scan_value_empty_needle() {
    let data = vec![0x41, 0x42, 0x43];
    let matches = MemoryScanner::scan_value(&data, &[]);
    assert!(matches.is_empty());
}

#[test]
fn test_find_pointers_empty_data() {
    let data: Vec<u8> = vec![];
    let pointers = MemoryScanner::find_pointers(&data, 0xDEADBEEF, 0x1000);
    assert!(pointers.is_empty());
}

#[test]
fn test_find_pointers_data_smaller_than_8() {
    let data = vec![0x00, 0x01, 0x02];
    let pointers = MemoryScanner::find_pointers(&data, 0x000102, 0x1000);
    assert!(pointers.is_empty());
}

#[test]
fn test_memory_region_permission_edge_cases() {
    let r = MemoryRegion {
        name: "r".into(),
        base_address: 0,
        size: 0,
        permissions: "R".into(),
        module_name: None,
    };
    assert!(r.is_readable());
    assert!(!r.is_executable());
    assert!(!r.is_writable());
    assert!(!r.is_rwx());

    let r = MemoryRegion {
        name: "w".into(),
        base_address: 0,
        size: 0,
        permissions: "W".into(),
        module_name: None,
    };
    assert!(r.is_writable());

    let r = MemoryRegion {
        name: "e".into(),
        base_address: 0,
        size: 0,
        permissions: "E".into(),
        module_name: None,
    };
    assert!(r.is_executable());

    let r = MemoryRegion {
        name: "rwx".into(),
        base_address: 0,
        size: 0,
        permissions: "RWX".into(),
        module_name: None,
    };
    assert!(r.is_rwx());

    let r = MemoryRegion {
        name: "exec_read_write".into(),
        base_address: 0,
        size: 0,
        permissions: "EXECUTE_READWRITE".into(),
        module_name: None,
    };
    assert!(r.is_rwx());
}

#[test]
fn test_get_simulated_regions_all_known_platforms() {
    for platform in &["windows", "linux", "macos"] {
        let regions = MemoryScanner::get_simulated_regions(platform);
        assert!(!regions.is_empty(), "No regions for platform: {}", platform);
    }
}
