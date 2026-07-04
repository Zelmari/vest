use vest_scanner::memory::MemoryScanner;

#[test]
fn test_pattern_scan_on_megabytes_of_data() {
    let data: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    let pattern = "41 42 43 44";

    let start = std::time::Instant::now();
    let matches = MemoryScanner::scan_pattern_fast(&data, pattern);
    let duration = start.elapsed();

    assert!(
        duration.as_secs() < 1,
        "Pattern scan on 1MB took {:?}",
        duration
    );

    assert!(!matches.is_empty(), "Expected to find pattern in 1MB data");
}

#[test]
fn test_pattern_scan_empty_data() {
    let data: Vec<u8> = vec![];
    let matches = MemoryScanner::scan_pattern(&data, "41 42");
    assert!(matches.is_empty());

    let matches = MemoryScanner::scan_pattern_fast(&data, "41 42");
    assert!(matches.is_empty());
}

#[test]
fn test_pattern_scan_single_byte() {
    let data = vec![0x41, 0x42, 0x43, 0x41];
    let matches = MemoryScanner::scan_pattern(&data, "41");
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0], 0);
    assert_eq!(matches[1], 3);
}

#[test]
fn test_pattern_scan_all_wildcards() {
    let data = vec![0x00, 0x01, 0x02, 0x03];
    let pattern = "?? ?? ?? ??";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_pattern_scan_overlapping_matches() {
    let data = vec![0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
    let matches = MemoryScanner::scan_pattern(&data, "AA AA");
    assert_eq!(matches.len(), 4);
}

#[test]
fn test_pattern_scan_at_end_of_data() {
    let data = vec![0x00, 0x00, 0x41, 0x42];
    let matches = MemoryScanner::scan_pattern(&data, "41 42");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], 2);
}

#[test]
fn test_pattern_scan_near_boundary() {
    let data = vec![0x41, 0x42];
    let matches = MemoryScanner::scan_pattern(&data, "41 42");
    assert_eq!(matches, vec![0]);

    let matches = MemoryScanner::scan_pattern(&data, "41 42 43");
    assert!(matches.is_empty());
}

#[test]
fn test_pattern_scan_hex_case_insensitivity() {
    let data = vec![0xAA, 0xBB];
    let matches_lower = MemoryScanner::scan_pattern(&data, "aa bb");
    let matches_upper = MemoryScanner::scan_pattern(&data, "AA BB");
    assert_eq!(matches_lower, vec![0]);
    assert_eq!(matches_upper, vec![0]);
}

#[test]
fn test_scan_value_exact_match() {
    let data = vec![0x00, 0x42, 0x00, 0x42, 0x42];
    let matches = MemoryScanner::scan_value(&data, &[0x42]);
    assert_eq!(matches.len(), 3);
}

#[test]
fn test_find_pointers_empty_data() {
    let data = vec![];
    let pointers = MemoryScanner::find_pointers(&data, 0xDEADBEEF, 0x1000);
    assert!(pointers.is_empty());
}

#[test]
fn test_memory_region_boundaries() {
    use vest_scanner::memory::MemoryRegion;

    let r = MemoryRegion {
        name: "".into(),
        base_address: u64::MAX,
        size: u64::MAX,
        permissions: "RWX".into(),
        module_name: None,
    };
    assert!(r.is_rwx());

    let r = MemoryRegion {
        name: "".into(),
        base_address: 0,
        size: 0,
        permissions: "".into(),
        module_name: None,
    };
    assert!(!r.is_rwx());
    assert!(!r.is_executable());
    assert!(!r.is_writable());
    assert!(!r.is_readable());
}

#[test]
fn test_memory_region_rwx_edge_cases() {
    use vest_scanner::memory::MemoryRegion;

    let rx = MemoryRegion {
        name: "code".into(),
        base_address: 0x1000,
        size: 4096,
        permissions: "RX".into(),
        module_name: None,
    };
    assert!(!rx.is_rwx());
    assert!(rx.is_executable());
    assert!(!rx.is_writable());
    assert!(rx.is_readable());

    let rw = MemoryRegion {
        name: "data".into(),
        base_address: 0x2000,
        size: 4096,
        permissions: "RW".into(),
        module_name: None,
    };
    assert!(!rw.is_rwx());
    assert!(!rw.is_executable());
    assert!(rw.is_writable());
    assert!(rw.is_readable());

    let exec_readwrite = MemoryRegion {
        name: "".into(),
        base_address: 0x5000,
        size: 4096,
        permissions: "EXECUTE_READWRITE".into(),
        module_name: None,
    };
    assert!(exec_readwrite.is_rwx());
    assert!(exec_readwrite.is_executable());
    assert!(exec_readwrite.is_writable());
}

#[test]
fn test_fast_vs_slow_pattern_scan_consistency() {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        let len = 16 + (rng.next_u32() as usize % 4096);
        let mut data = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut data);

        let pat_len = 1 + (rng.next_u32() as usize % 8);
        let has_leading_wc = rng.next_u32().is_multiple_of(4);
        let pattern: String = {
            let mut parts: Vec<String> = Vec::new();
            if has_leading_wc {
                parts.push("??".to_string());
            }
            parts.push(format!("{:02X}", rand::random::<u8>()));
            for _ in 0..pat_len.saturating_sub(1) {
                if rand::random::<bool>() {
                    parts.push("??".to_string());
                } else {
                    parts.push(format!("{:02X}", rand::random::<u8>()));
                }
            }
            parts.join(" ")
        };

        let slow = MemoryScanner::scan_pattern(&data, &pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, &pattern);
        assert_eq!(
            slow, fast,
            "Mismatch for pattern '{}' on {} bytes",
            pattern, len
        );
    }
}

#[test]
fn test_pattern_scan_100mb_stress() {
    let size = 10 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let pattern = "DE AD BE EF";

    let start = std::time::Instant::now();
    let matches = MemoryScanner::scan_pattern_fast(&data, pattern);
    let duration = start.elapsed();

    assert!(
        duration.as_secs() < 3,
        "Pattern scan on 10MB took {:?} ({} matches)",
        duration,
        matches.len()
    );
}

#[test]
fn test_find_pointers_at_extremes() {
    let mut data = vec![0u8; 100];
    let target: u64 = 0xFFFFFFFFFFFFFFFF;
    let bytes = target.to_le_bytes();
    data[0..8].copy_from_slice(&bytes);

    let pointers = MemoryScanner::find_pointers(&data, target, 0);
    assert_eq!(pointers.len(), 1);
    assert_eq!(pointers[0], 0);
}

#[test]
fn test_find_pointers_overlapping() {
    let mut data = vec![0u8; 200];
    let target: u64 = 0x41;
    let bytes = target.to_le_bytes();
    data[0..8].copy_from_slice(&bytes);
    data[16..24].copy_from_slice(&bytes);
    data[32..40].copy_from_slice(&bytes);

    let pointers = MemoryScanner::find_pointers(&data, target, 0x1000);
    assert_eq!(pointers.len(), 3, "Expected 3 pointer matches");
    assert_eq!(pointers[0], 0x1000);
    assert_eq!(pointers[1], 0x1000 + 16);
    assert_eq!(pointers[2], 0x1000 + 32);
}

#[test]
fn test_pattern_scan_with_many_wildcards() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xCA, 0xFE];
    let pattern = "DE AD ?? ??";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0], 0);
    assert_eq!(matches[1], 4);
}

#[test]
fn test_pattern_scan_starts_with_wildcard() {
    let data = vec![0x00, 0x41, 0x42, 0x00, 0x41, 0x42];
    let pattern = "?? 41 42";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0], 0);
    assert_eq!(matches[1], 3);
}

#[test]
fn test_pattern_scan_fast_empty_data() {
    let data: Vec<u8> = vec![];
    let matches = MemoryScanner::scan_pattern_fast(&data, "?? 41 ??");
    assert!(matches.is_empty());
}

#[test]
fn test_scan_value_empty_value() {
    let data = vec![0x41, 0x42, 0x43];
    let matches = MemoryScanner::scan_value(&data, &[]);
    assert!(matches.is_empty());
}

#[test]
fn test_scan_value_multibyte() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
    let matches = MemoryScanner::scan_value(&data, &[0xDE, 0xAD]);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0], 0);
    assert_eq!(matches[1], 4);
}

#[test]
fn test_pattern_scan_fast_no_fixed_bytes() {
    let data = vec![0x11, 0x22, 0x33, 0x44];
    let pattern = "?? ??";
    let slow = MemoryScanner::scan_pattern(&data, pattern);
    let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
    assert_eq!(slow, fast);
}
