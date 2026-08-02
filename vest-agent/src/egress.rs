//! Model-egress boundary: action authorisation ≠ data leaving the machine.
//!
//! Regex redaction cannot guarantee detection of every secret. Prefer
//! allowlisted DTOs and explicit egress flags over hoping patterns catch all.

use crate::policy::AuthorisationContext;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;
use vest_core::auth::{DataEgressClass, ToolEffect};
use vest_core::types::Finding;

const DEFAULT_MAX_TOOL_RESULT_CHARS: usize = 8_192;
const MAX_EVIDENCE_EXCERPT: usize = 512;

/// Classify a tool result for egress purposes.
pub fn classify_tool_result(effect: ToolEffect, _value: &Value) -> DataEgressClass {
    match effect {
        ToolEffect::PureComputation => DataEgressClass::PublicNonSensitive,
        ToolEffect::LocalMetadataRead | ToolEffect::ProcessMetadataRead => {
            DataEgressClass::LocalMetadata
        }
        ToolEffect::LocalFileContentRead => DataEgressClass::LocalContent,
        ToolEffect::NetworkMetadataRead => DataEgressClass::TargetMetadata,
        ToolEffect::PassiveNetworkRequest
        | ToolEffect::ActiveNetworkProbe
        | ToolEffect::StateChangingNetworkRequest => DataEgressClass::TargetContent,
        ToolEffect::ProcessMemoryRead => DataEgressClass::ProcessMemory,
        ToolEffect::CredentialAccess => DataEgressClass::CredentialMaterial,
        ToolEffect::LocalWrite | ToolEffect::CommandExecution => {
            DataEgressClass::PotentiallySecretBearing
        }
        ToolEffect::Unknown => DataEgressClass::Prohibited,
    }
}

/// Bound tool result size before it can enter model context.
pub fn bound_tool_result(value: &Value, max_chars: usize) -> Value {
    let s = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    if s.len() <= max_chars {
        return value.clone();
    }
    json!({
        "truncated": true,
        "original_chars": s.len(),
        "max_chars": max_chars,
        "preview": s.chars().take(max_chars).collect::<String>(),
    })
}

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

/// Filter a tool result for insertion into remote model context.
pub fn filter_for_model(
    value: &Value,
    class: DataEgressClass,
    ctx: &AuthorisationContext,
) -> Result<Value, String> {
    if class.is_prohibited() {
        return Err("egress prohibited for this data class".into());
    }
    if matches!(class, DataEgressClass::ProcessMemory) && !ctx.allow_process_memory_egress {
        return Ok(json!({
            "egress_denied": true,
            "reason": "process memory is not sent to remote models by default",
            "class": "process_memory",
        }));
    }
    if matches!(class, DataEgressClass::LocalContent) && !ctx.allow_local_content_egress {
        return Ok(json!({
            "egress_denied": true,
            "reason": "local file content is not sent to remote models by default",
            "class": "local_content",
            "metadata": value.as_object().map(|o| {
                json!({
                    "path": o.get("path"),
                    "size": o.get("size"),
                    "files_scanned": o.get("files_scanned"),
                    "total_findings": o.get("total_findings"),
                })
            }),
        }));
    }
    if matches!(class, DataEgressClass::CredentialMaterial) {
        return Err("credential material must not egress to models".into());
    }

    let bounded = bound_tool_result(value, DEFAULT_MAX_TOOL_RESULT_CHARS);
    let text = serde_json::to_string(&bounded).unwrap_or_default();
    let redacted = redact_secrets(&text, &ctx.known_secrets);
    serde_json::from_str(&redacted).or(Ok(json!({"redacted_text": redacted})))
}

/// Allowlisted finding DTO for remote validation (no raw evidence by default).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingEgressDto {
    pub id: String,
    pub title: String,
    pub vulnerability_class: String,
    pub severity: String,
    pub description: String,
    pub confidence: f64,
    pub cwe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_excerpt: Option<String>,
}

pub fn build_provider_finding_dto(finding: &Finding, allow_evidence: bool) -> FindingEgressDto {
    FindingEgressDto {
        id: finding.id.clone(),
        title: finding.title.chars().take(512).collect(),
        vulnerability_class: finding.vulnerability_class.to_string(),
        severity: finding.severity.to_string(),
        description: finding.description.chars().take(2_048).collect(),
        confidence: finding.confidence,
        cwe_id: finding.cwe_id.clone(),
        evidence_excerpt: if allow_evidence {
            let raw = serde_json::to_string(&finding.evidence).unwrap_or_default();
            let excerpt: String = raw.chars().take(MAX_EVIDENCE_EXCERPT).collect();
            Some(redact_secrets(&excerpt, &[]))
        } else {
            None
        },
    }
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

    #[test]
    fn local_content_blocked_by_default() {
        let ctx = AuthorisationContext::new("s");
        let value =
            json!({"path": "/home/example/.ssh/id_ed25519", "content": "PRIVATE_SOURCE_SENTINEL"});
        let filtered = filter_for_model(&value, DataEgressClass::LocalContent, &ctx).unwrap();
        let s = filtered.to_string();
        assert!(!s.contains("PRIVATE_SOURCE_SENTINEL"));
        assert!(filtered
            .get("egress_denied")
            .and_then(|v| v.as_bool())
            .unwrap());
    }

    #[test]
    fn process_memory_blocked_by_default() {
        let ctx = AuthorisationContext::new("s");
        let value = json!({"bytes": "MEMORY_SENTINEL_AABBCC"});
        let filtered = filter_for_model(&value, DataEgressClass::ProcessMemory, &ctx).unwrap();
        assert!(!filtered.to_string().contains("MEMORY_SENTINEL"));
    }

    #[test]
    fn finding_dto_excludes_evidence_by_default() {
        let mut f = vest_core::types::Finding {
            id: "f1".into(),
            scan_id: "s".into(),
            target_id: "t".into(),
            title: "t".into(),
            description: "d".into(),
            vulnerability_class: vest_core::types::VulnerabilityClass::XSS,
            severity: vest_core::types::Severity::High,
            confidence: 0.9,
            status: vest_core::types::FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: json!({"Authorization": "Bearer SECRET"}),
            poc: None,
            remediation: None,
            location: json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let dto = build_provider_finding_dto(&f, false);
        let s = serde_json::to_string(&dto).unwrap();
        assert!(!s.contains("Bearer SECRET"));
        assert!(dto.evidence_excerpt.is_none());
        f.evidence = json!({"x": 1});
        let dto2 = build_provider_finding_dto(&f, true);
        assert!(dto2.evidence_excerpt.is_some());
    }

    #[test]
    fn bound_truncates() {
        let v = json!({"content": "x".repeat(20_000)});
        let b = bound_tool_result(&v, 100);
        assert!(b.get("truncated").and_then(|x| x.as_bool()).unwrap());
    }
}
