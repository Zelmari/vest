pub struct MemoryPayloads;

impl MemoryPayloads {
    pub fn common_values() -> Vec<u32> {
        vec![0, 1, 10, 100, 999, 9999, 100, 1000, 255, 256, 65535, 65536]
    }

    pub fn flag_patterns() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("noclip_flag", vec![0x01]),
            ("godmode_flag", vec![0x01]),
            ("invisibility_flag", vec![0x01]),
            ("speed_multiplier_1", 1.0f32.to_le_bytes().to_vec()),
            ("speed_multiplier_2", 2.0f32.to_le_bytes().to_vec()),
        ]
    }

    pub fn cheat_engine_scan_types() -> Vec<&'static str> {
        vec![
            "exact_value",
            "bigger_than",
            "smaller_than",
            "value_between",
            "unknown_initial_value",
            "increased_value",
            "decreased_value",
            "changed_value",
            "unchanged_value",
        ]
    }

    pub fn hook_bytes() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("jmp_rel32", &[0xE9]),
            ("jmp_rm32", &[0xFF, 0x25]),
            ("call_rel32", &[0xE8]),
            ("push_ret", &[0x68]),
            ("int3_breakpoint", &[0xCC]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_values_not_empty() {
        assert!(!MemoryPayloads::common_values().is_empty());
    }

    #[test]
    fn test_flag_patterns_not_empty() {
        assert!(!MemoryPayloads::flag_patterns().is_empty());
    }

    #[test]
    fn test_cheat_engine_scan_types() {
        let types = MemoryPayloads::cheat_engine_scan_types();
        assert!(types.contains(&"exact_value"));
        assert!(types.contains(&"unknown_initial_value"));
    }

    #[test]
    fn test_hook_bytes() {
        let hooks = MemoryPayloads::hook_bytes();
        assert!(hooks.iter().any(|(name, _)| *name == "jmp_rel32"));
    }
}
