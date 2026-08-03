//! Report-time redaction: omit or mask secret-bearing evidence by default.

use serde_json::{json, Value};
use vest_core::redact_secrets;

/// Options controlling how findings are rendered into reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportOptions {
    /// When false (default), evidence and PoC are omitted from JSON/Markdown.
    /// When true, they are included after redacting common secret patterns and
    /// masking `match_preview` fields.
    pub include_evidence: bool,
}

impl ReportOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn include_evidence(mut self, include: bool) -> Self {
        self.include_evidence = include;
        self
    }
}

/// Placeholder written into JSON reports when evidence is omitted.
pub fn omitted_evidence_value() -> Value {
    json!({
        "omitted": true,
        "reason": "Evidence omitted by default. Pass --include-evidence (or set general.include_report_evidence) to include; secrets are still redacted best-effort."
    })
}

/// Sanitize finding evidence for report output.
pub fn sanitize_evidence(evidence: &Value, options: ReportOptions) -> Value {
    if !options.include_evidence {
        return omitted_evidence_value();
    }
    let mut value = evidence.clone();
    sanitize_value(&mut value);
    value
}

/// Sanitize optional PoC text for report output.
pub fn sanitize_poc(poc: Option<&str>, options: ReportOptions) -> Option<String> {
    if !options.include_evidence {
        return None;
    }
    poc.map(|text| redact_secrets(text, &[]))
}

/// Neutralize markdown code-fence breakouts in untrusted finding text (REP-2).
///
/// Breaks every triple-backtick sequence with zero-width spaces so content
/// embedded inside ` ``` ` / ` ```json ` blocks cannot close the surrounding fence.
pub fn escape_markdown_fences(text: &str) -> String {
    text.replace("```", "`\u{200b}`\u{200b}`")
}

fn sanitize_value(value: &mut Value) {
    match value {
        Value::String(s) => {
            *s = redact_secrets(s, &[]);
        }
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key == "match_preview" {
                    if let Some(raw) = child.as_str() {
                        *child = Value::String(mask_secret_snippet(raw));
                    } else {
                        *child = Value::String("[REDACTED]".into());
                    }
                } else if is_sensitive_key(key) {
                    if child.is_string() {
                        *child = Value::String("[REDACTED]".into());
                    } else {
                        sanitize_value(child);
                    }
                } else {
                    sanitize_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_value(item);
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "api_key"
            | "apikey"
            | "secret"
            | "password"
            | "token"
            | "authorization"
            | "cookie"
            | "credential"
            | "credentials"
    ) || lower.contains("password")
        || lower.contains("secret")
        || lower.ends_with("_token")
        || lower.ends_with("_key")
}

fn mask_secret_snippet(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "[REDACTED]".into();
    }
    let prefix: String = chars.iter().take(2).collect();
    let suffix: String = chars.iter().rev().take(2).rev().collect();
    format!("{prefix}…{suffix} [REDACTED]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_omits_evidence_and_poc() {
        let evidence = json!({
            "match_preview": "VEST_REPORT_SECRET_SENTINEL_9f3a",
            "api_key": "VEST_REPORT_SECRET_SENTINEL_9f3a"
        });
        let out = sanitize_evidence(&evidence, ReportOptions::default());
        let s = out.to_string();
        assert!(out.get("omitted").and_then(|v| v.as_bool()).unwrap());
        assert!(!s.contains("VEST_REPORT_SECRET_SENTINEL_9f3a"));
        assert!(sanitize_poc(
            Some("VEST_REPORT_SECRET_SENTINEL_9f3a"),
            ReportOptions::default()
        )
        .is_none());
    }

    #[test]
    fn include_evidence_masks_preview_and_patterns() {
        let evidence = json!({
            "file": "secrets.env",
            "match_preview": "VEST_REPORT_SECRET_SENTINEL_9f3a",
            "note": "Authorization: Bearer VEST_REPORT_SECRET_SENTINEL_9f3a"
        });
        let out = sanitize_evidence(&evidence, ReportOptions::default().include_evidence(true));
        let s = out.to_string();
        assert!(!s.contains("VEST_REPORT_SECRET_SENTINEL_9f3a"));
        assert_eq!(out["file"], "secrets.env");
        assert!(out["match_preview"].as_str().unwrap().contains("REDACTED"));
        assert!(s.contains("REDACTED"));

        let poc = sanitize_poc(
            Some("token=VEST_REPORT_SECRET_SENTINEL_9f3a"),
            ReportOptions::default().include_evidence(true),
        )
        .unwrap();
        assert!(!poc.contains("VEST_REPORT_SECRET_SENTINEL_9f3a"));
        assert!(poc.contains("REDACTED"));
    }

    #[test]
    fn escape_markdown_fences_breaks_triple_backticks() {
        let escaped = escape_markdown_fences("before\n```\nafter\n``````done");
        assert!(!escaped.contains("```"));
        assert!(escaped.contains("`\u{200b}`\u{200b}`"));
        assert_eq!(escape_markdown_fences("no fences here"), "no fences here");
    }
}
