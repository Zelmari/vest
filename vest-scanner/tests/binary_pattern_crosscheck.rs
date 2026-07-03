use vest_scanner::memory::MemoryScanner;

#[test]
fn test_fast_vs_bruteforce_on_binary_patterns() {
    let patterns = vec![
        ("JMP near", "E9 ?? ?? ?? ??"),
        ("INT3", "CC"),
        ("NOP sled", "90 90 90"),
        ("Function prologue x64", "55 48 89 E5"),
        ("Function prologue x86", "55 89 E5"),
        ("RET", "C3"),
        ("CALL rel32", "E8 ?? ?? ?? ??"),
        ("MOV RAX, imm64", "48 B8 ?? ?? ?? ?? ?? ?? ?? ??"),
    ];

    for (name, pattern) in &patterns {
        let mut data = vec![0x00u8; 4096];

        match *name {
            "JMP near" => {
                data[100] = 0xE9;
                data[101..105].copy_from_slice(&[0x45, 0x23, 0x01, 0x00]);
                data[200] = 0xE9;
            }
            "INT3" => {
                data[500] = 0xCC;
                data[501] = 0xCC;
            }
            "NOP sled" => {
                data[300] = 0x90;
                data[301] = 0x90;
                data[302] = 0x90;
            }
            "Function prologue x64" => {
                data[0] = 0x55;
                data[1] = 0x48;
                data[2] = 0x89;
                data[3] = 0xE5;
            }
            "Function prologue x86" => {
                data[16] = 0x55;
                data[17] = 0x89;
                data[18] = 0xE5;
            }
            "RET" => {
                data[400] = 0xC3;
                data[401] = 0xC3;
            }
            _ => {}
        }

        let slow = MemoryScanner::scan_pattern(&data, pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, pattern);

        assert_eq!(
            slow, fast,
            "Mismatch for pattern '{}' ({}): slow={:?}, fast={:?}",
            name, pattern, slow, fast
        );
    }
}

#[test]
fn test_pattern_scan_on_all_zero_data() {
    let data = vec![0x00u8; 10000];
    let pattern = "00 00 00 00";
    let slow = MemoryScanner::scan_pattern(&data, pattern);
    let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
    assert_eq!(slow, fast);
    assert_eq!(slow.len(), 9997);
}

#[test]
fn test_pattern_scan_on_all_ones_data() {
    let data = vec![0xFFu8; 10000];
    let pattern = "FF FF FF FF";
    let slow = MemoryScanner::scan_pattern(&data, pattern);
    let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
    assert_eq!(slow, fast);
    assert_eq!(slow.len(), 9997);
}

#[test]
fn test_wildcard_matches_everything() {
    // A single wildcard byte matches EVERY position (including the last byte)
    let data = vec![0xAAu8; 100];
    let pattern = "??";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert_eq!(matches.len(), 100);
}

#[test]
fn test_pattern_scan_with_consecutive_wildcards() {
    let data = vec![0x41, 0x42, 0x43, 0x44, 0x45];

    // "41 ?? ?? 44" matches: 41 XX XX 44 at position 0
    let pattern = "41 ?? ?? 44";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert_eq!(matches, vec![0]);

    // "41 ?? ?? 45" should NOT match since position 3 is 44, not 45
    let pattern = "41 ?? ?? 45";
    let matches = MemoryScanner::scan_pattern(&data, pattern);
    assert!(matches.is_empty());
}

#[test]
fn test_pattern_scan_on_random_data() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..2048).map(|_| rng.gen()).collect();

    // Test 50 random patterns against both implementations
    for _ in 0..50 {
        let start = rng.gen_range(0..(data.len() - 4));
        let pat_bytes = &data[start..start + 4];
        let pattern = format!(
            "{:02X} {:02X} {:02X} {:02X}",
            pat_bytes[0], pat_bytes[1], pat_bytes[2], pat_bytes[3]
        );

        let slow = MemoryScanner::scan_pattern(&data, &pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, &pattern);
        assert_eq!(slow, fast, "Mismatch for pattern: {}", pattern);
    }
}

#[test]
fn test_pattern_scan_at_boundaries() {
    let data = vec![0x42u8; 10];
    // Pattern at the very end - one byte only
    let matches = MemoryScanner::scan_pattern(&data, "42");
    assert_eq!(matches.len(), 10);

    // Pattern longer than data
    let matches = MemoryScanner::scan_pattern(&data, "42 42");
    assert_eq!(matches.len(), 9);

    // Pattern exactly the length of data
    let matches = MemoryScanner::scan_pattern(&data, "42 42 42 42 42 42 42 42 42 42");
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_pattern_scan_single_wildcard() {
    let data = vec![0x01, 0x02, 0x03];
    let matches = MemoryScanner::scan_pattern(&data, "01 ?? 03");
    assert_eq!(matches, vec![0]);
}

#[test]
fn test_pattern_scan_leading_wildcard() {
    let data = vec![0x01, 0x02, 0x03];
    let matches = MemoryScanner::scan_pattern(&data, "?? 02");
    // At pos 0: [01, 02] matches [??, 02] -- 01 wildcards, 02 == 02 ✓
    // At pos 1: [02, 03] -- 03 != 02 ✗
    assert_eq!(matches, vec![0]);
}

#[test]
fn test_pattern_scan_fast_wildcard_only_pattern() {
    // Single wildcard on single-byte data -- every position matches
    let data = vec![0xABu8; 50];
    let slow = MemoryScanner::scan_pattern(&data, "??");
    let fast = MemoryScanner::scan_pattern_fast(&data, "??");
    assert_eq!(slow, fast);
    assert_eq!(slow.len(), 50);
}

#[test]
fn test_pattern_scan_empty_data() {
    let data: Vec<u8> = vec![];
    let matches = MemoryScanner::scan_pattern(&data, "AB CD");
    assert!(matches.is_empty());
    let matches = MemoryScanner::scan_pattern_fast(&data, "AB CD");
    assert!(matches.is_empty());
}

#[test]
fn test_pattern_scan_data_too_short() {
    let data = vec![0xABu8];
    let matches = MemoryScanner::scan_pattern(&data, "AB CD EF");
    assert!(matches.is_empty());
    let matches = MemoryScanner::scan_pattern_fast(&data, "AB CD EF");
    assert!(matches.is_empty());
}
