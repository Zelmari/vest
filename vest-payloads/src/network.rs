pub struct NetworkPayloads;

impl NetworkPayloads {
    pub fn malformed_packets() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty_tcp", vec![]),
            ("max_size_tcp", vec![0xFFu8; 65535]),
            ("null_bytes_1k", vec![0x00u8; 1024]),
            ("format_string_udp", b"%n%n%n%n".to_vec()),
        ]
    }

    pub fn protocol_fuzzing_mutations() -> Vec<&'static str> {
        vec![
            "bit_flip",
            "byte_increment",
            "byte_decrement",
            "random_byte",
        ]
    }

    pub fn dns_attacks() -> Vec<(&'static str, &'static str)> {
        vec![
            ("zone_transfer", "AXFR"),
            ("amplification", "ANY"),
            ("cache_poison", "spoofed_response"),
        ]
    }

    pub fn common_service_probes() -> Vec<(&'static str, u16, &'static [u8])> {
        vec![
            ("http_get", 80, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            ("ssh_banner", 22, b"\x00"),
            ("mysql_greeting", 3306, b"\x00"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_packets_not_empty() {
        assert!(!NetworkPayloads::malformed_packets().is_empty());
    }

    #[test]
    fn test_dns_attacks() {
        let attacks = NetworkPayloads::dns_attacks();
        assert!(attacks.iter().any(|(name, _)| *name == "zone_transfer"));
    }

    #[test]
    fn test_service_probes() {
        let probes = NetworkPayloads::common_service_probes();
        assert!(probes.iter().any(|(name, _, _)| *name == "http_get"));
    }

    #[test]
    fn test_fuzzing_mutations() {
        let mutations = NetworkPayloads::protocol_fuzzing_mutations();
        assert!(!mutations.is_empty());
    }
}
