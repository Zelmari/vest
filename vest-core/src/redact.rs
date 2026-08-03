//! Best-effort secret redaction for logs, model egress, and reports.
//!
//! Pattern matching cannot guarantee detection of every secret format.
//! Prefer omitting secret-bearing fields by default over relying on regex alone.

use regex::Regex;
use std::sync::OnceLock;

/// Redact configured secrets and common credential patterns.
///
/// Limits: pattern matching is best-effort and will miss novel secret formats.
pub fn redact_secrets(text: &str, known_secrets: &[String]) -> String {
    let mut out = text.to_string();
    for secret in known_secrets {
        if secret.len() >= 8 {
            out = out.replace(secret.as_str(), "[REDACTED_SECRET]");
        }
    }
    static BEARER: OnceLock<Regex> = OnceLock::new();
    static COOKIE: OnceLock<Regex> = OnceLock::new();
    static ASSIGN: OnceLock<Regex> = OnceLock::new();
    let bearer = BEARER.get_or_init(|| {
        Regex::new(r"(?i)(authorization\s*:\s*bearer\s+)(\S+)").expect("bearer regex")
    });
    let cookie =
        COOKIE.get_or_init(|| Regex::new(r"(?i)(cookie\s*:\s*)([^\r\n]+)").expect("cookie regex"));
    let assign = ASSIGN.get_or_init(|| {
        Regex::new(r#"(?i)((?:api[_-]?key|secret|password|token)\s*[=:]\s*["']?)([^\s"']+)"#)
            .expect("assign regex")
    });
    out = bearer.replace_all(&out, "$1[REDACTED]").into_owned();
    out = cookie.replace_all(&out, "$1[REDACTED]").into_owned();
    out = assign.replace_all(&out, "$1[REDACTED]").into_owned();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sentinel_and_bearer() {
        let text = "key=SUPER_SECRET_TEST_KEY_123 Authorization: Bearer SECRET_TOKEN cookie: a=b";
        let out = redact_secrets(text, &["SUPER_SECRET_TEST_KEY_123".into()]);
        assert!(!out.contains("SUPER_SECRET_TEST_KEY_123"));
        assert!(!out.contains("SECRET_TOKEN"));
        assert!(out.contains("REDACTED"));
    }
}
