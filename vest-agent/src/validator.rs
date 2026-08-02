use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::traits::LlmProvider;
use vest_core::types::{Finding, FindingStatus, Severity, VulnerabilityClass};

/// Maximum length for LLM reasoning strings accepted during validation.
const MAX_REASONING_LEN: usize = 4_096;
/// Maximum length for finding description included in the validation prompt DTO.
const MAX_DTO_DESCRIPTION_LEN: usize = 2_048;
/// Maximum length for a redacted evidence excerpt when enabled.
const MAX_EVIDENCE_EXCERPT_LEN: usize = 512;

const ALLOWED_DECISIONS: &[&str] = &["confirmed", "downgraded", "false_positive", "uncertain"];
const ALLOWED_SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

pub struct Validator {
    provider: Option<Arc<dyn LlmProvider>>,
    model: String,
    strict_mode: bool,
    /// When true, include a bounded redacted evidence excerpt in the LLM prompt.
    /// Default false — evidence/location are not sent to the provider.
    include_evidence_excerpt: bool,
}

/// Questions the validator asks for each finding
const VALIDATION_QUESTIONS: &[&str] = &[
    "Is the evidence concrete and reproducible, not just inferred?",
    "Could a security control (auth, sandbox, validation) mitigate this?",
    "Is the severity correct for the actual impact?",
    "Has this finding been verified with a different tool or approach?",
    "Are there any environmental factors that could produce a false positive?",
    "Would this finding be accepted in a bug bounty submission?",
    "Is the attack vector actually reachable by an attacker?",
];

/// Allowlisted fields sent to a remote validator provider (no raw evidence/location).
#[derive(Debug, Clone, serde::Serialize)]
struct FindingValidationDto {
    id: String,
    title: String,
    vulnerability_class: String,
    severity: String,
    description: String,
    confidence: f64,
    cwe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_excerpt: Option<String>,
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect::<String>() + "…"
}

fn redacted_evidence_excerpt(evidence: &serde_json::Value) -> String {
    let raw = match evidence {
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    // Redact common secret-like substrings before bounding length.
    let mut redacted = raw;
    for pattern in [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
    ] {
        if redacted.to_lowercase().contains(pattern) {
            redacted = format!("[redacted: contains '{pattern}']");
            break;
        }
    }
    truncate_str(&redacted, MAX_EVIDENCE_EXCERPT_LEN)
}

fn severity_score_estimate(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 9.0,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

/// Heuristically enrich a finding with vulnerability class and a severity score estimate
/// when the LLM hasn't provided them.
///
/// The estimate is stored in `metadata["severity_score_estimate"]` and is **not** a CVSS
/// score. `cvss_score` is left unchanged (typically `None` unless a real vector exists).
pub fn enrich_finding_heuristic(finding: &mut Finding) {
    let title_lower = finding.title.to_lowercase();

    // Guess vulnerability class from title patterns
    // Order matters: check specific patterns before generic ones
    if finding.vulnerability_class == VulnerabilityClass::Unknown {
        let guessed = if title_lower.contains("xss")
            || title_lower.contains("cross-site")
            || title_lower.contains("script")
        {
            VulnerabilityClass::XSS
        } else if title_lower.contains("command injection") {
            VulnerabilityClass::CommandInjection
        } else if title_lower.contains("sql") {
            VulnerabilityClass::SQLInjection
        } else if title_lower.contains("ssrf") {
            VulnerabilityClass::SSRF
        } else if title_lower.contains("path traversal")
            || title_lower.contains("directory traversal")
        {
            VulnerabilityClass::PathTraversal
        } else if title_lower.contains("password")
            || title_lower.contains("credential")
            || title_lower.contains("secret")
            || title_lower.contains("key")
            || title_lower.contains("token")
            || title_lower.contains("api key")
        {
            VulnerabilityClass::HardcodedCredentials
        } else if title_lower.contains("buffer overflow")
            || title_lower.contains("stack") && title_lower.contains("overflow")
        {
            VulnerabilityClass::BufferOverflow
        } else if title_lower.contains("cors") {
            VulnerabilityClass::CORS
        } else if title_lower.contains("injection") {
            VulnerabilityClass::SQLInjection
        } else {
            VulnerabilityClass::Unknown
        };

        if guessed != VulnerabilityClass::Unknown {
            finding.vulnerability_class = guessed;
        }
    }

    // Store a naive severity estimate in metadata — not a CVSS score.
    if finding
        .metadata
        .get("severity_score_estimate")
        .and_then(|v| v.as_f64())
        .is_none()
    {
        if !finding.metadata.is_object() {
            finding.metadata = serde_json::json!({});
        }
        if let Some(obj) = finding.metadata.as_object_mut() {
            obj.insert(
                "severity_score_estimate".into(),
                serde_json::json!(severity_score_estimate(finding.severity)),
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub finding_id: String,
    pub original_severity: Severity,
    pub validated_severity: Option<Severity>,
    pub status: ValidationDecision,
    pub reasoning: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationDecision {
    Confirmed,
    Downgraded,
    FalsePositive,
    Uncertain,
}

impl Validator {
    pub fn new() -> Self {
        Self {
            provider: None,
            model: "default".into(),
            strict_mode: false,
            include_evidence_excerpt: false,
        }
    }

    pub fn with_provider(
        mut self,
        provider: Arc<dyn LlmProvider>,
        model: impl Into<String>,
    ) -> Self {
        self.provider = Some(provider);
        self.model = model.into();
        self
    }

    pub fn strict(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Include a bounded redacted evidence excerpt in remote validator prompts.
    /// Default is false (allowlist DTO without raw evidence/location).
    pub fn include_evidence_excerpt(mut self, include: bool) -> Self {
        self.include_evidence_excerpt = include;
        self
    }

    /// Validate a batch of findings. Returns validated findings (FPs removed), enriched.
    ///
    /// Provider failures and malformed LLM responses preserve the original local finding
    /// so a single bad item cannot erase the rest of the batch.
    pub async fn validate(&self, findings: &[Finding]) -> Result<Vec<Finding>, VestError> {
        let mut validated = Vec::new();

        for finding in findings {
            if let Some(provider) = &self.provider {
                match self.llm_validate(provider, finding).await {
                    Ok(result) => match result.status {
                        ValidationDecision::Confirmed => {
                            let mut confirmed = finding.clone();
                            confirmed.status = FindingStatus::Confirmed;
                            if let Some(sev) = result.validated_severity {
                                confirmed.severity = sev;
                            }
                            confirmed.confidence = result.confidence;
                            confirmed = self.apply_llm_enrichment(confirmed, &result);
                            validated.push(confirmed);
                        }
                        ValidationDecision::Downgraded => {
                            let mut downgraded = finding.clone();
                            downgraded.status = FindingStatus::Confirmed;
                            if let Some(sev) = result.validated_severity {
                                downgraded.severity = sev;
                            }
                            downgraded.confidence = result.confidence;
                            downgraded = self.apply_llm_enrichment(downgraded, &result);
                            validated.push(downgraded);
                        }
                        ValidationDecision::FalsePositive => {
                            // Don't add to validated list
                        }
                        ValidationDecision::Uncertain => {
                            if !self.strict_mode {
                                let mut enriched = finding.clone();
                                if let Some(sev) = result.validated_severity {
                                    enriched.severity = sev;
                                }
                                enriched.confidence = result.confidence;
                                enrich_finding_heuristic(&mut enriched);
                                validated.push(enriched);
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            finding_id = %finding.id,
                            error = %e,
                            "LLM validation failed; preserving original local finding"
                        );
                        let mut preserved = finding.clone();
                        enrich_finding_heuristic(&mut preserved);
                        validated.push(preserved);
                    }
                }
            } else {
                // No LLM for validation - apply heuristic rules
                let (result, enriched) = self.heuristic_validate(finding);
                match result.status {
                    ValidationDecision::Confirmed | ValidationDecision::Downgraded => {
                        validated.push(enriched);
                    }
                    ValidationDecision::FalsePositive => {
                        // Skip
                    }
                    ValidationDecision::Uncertain => {
                        if !self.strict_mode {
                            validated.push(enriched);
                        }
                    }
                }
            }
        }

        Ok(validated)
    }

    fn apply_llm_enrichment(&self, mut finding: Finding, _result: &ValidationResult) -> Finding {
        enrich_finding_heuristic(&mut finding);
        finding
    }

    fn build_validation_dto(&self, finding: &Finding) -> FindingValidationDto {
        FindingValidationDto {
            id: finding.id.clone(),
            title: truncate_str(&finding.title, 512),
            vulnerability_class: finding.vulnerability_class.to_string(),
            severity: finding.severity.to_string(),
            description: truncate_str(&finding.description, MAX_DTO_DESCRIPTION_LEN),
            confidence: finding.confidence,
            cwe_id: finding.cwe_id.clone(),
            evidence_excerpt: if self.include_evidence_excerpt {
                Some(redacted_evidence_excerpt(&finding.evidence))
            } else {
                None
            },
        }
    }

    /// Build the user prompt for LLM validation (allowlisted DTO, no raw evidence by default).
    pub fn build_validation_prompt(&self, finding: &Finding) -> String {
        let dto = self.build_validation_dto(finding);
        let dto_json = serde_json::to_string_pretty(&dto).unwrap_or_else(|_| "{}".into());
        let questions = VALIDATION_QUESTIONS.join("\n");
        format!(
            "You are a SKEPTICAL security validator. Your job is to CHALLENGE every finding.\n\
             \nFinding (allowlisted fields only):\n\
             {dto_json}\n\
             \nChallenge this finding by answering these questions:\n\
             {questions}\n\
             \nRespond with a JSON object:\n\
             {{\n  \"finding_id\": \"{id}\",\n  \"decision\": \"confirmed\" | \"downgraded\" | \"false_positive\" | \"uncertain\",\n  \"severity\": \"critical\" | \"high\" | \"medium\" | \"low\" | \"info\" | null,\n  \"reasoning\": \"Your skeptical analysis\",\n  \"confidence\": 0.0-1.0\n}}\n\
             \nOnly respond with the JSON object, no other text.",
            id = finding.id,
        )
    }

    /// Parse and structurally validate an LLM validator JSON response.
    pub fn parse_llm_validation_response(
        &self,
        finding: &Finding,
        response: &str,
    ) -> Result<ValidationResult, String> {
        let json_str = self
            .extract_json_object(response)
            .ok_or_else(|| "no JSON object found in response".to_string())?;

        let v: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|e| format!("JSON parse error: {e}"))?;

        let obj = v
            .as_object()
            .ok_or_else(|| "response root must be a JSON object".to_string())?;

        // Optional finding_id: if present must match the finding under validation.
        if let Some(id_val) = obj.get("finding_id") {
            let id = id_val
                .as_str()
                .ok_or_else(|| "finding_id must be a string".to_string())?;
            if id != finding.id {
                return Err(format!(
                    "finding_id mismatch: expected {}, got {}",
                    finding.id, id
                ));
            }
        }

        let decision_str = obj
            .get("decision")
            .and_then(|d| d.as_str())
            .ok_or_else(|| "missing or non-string decision".to_string())?;
        if !ALLOWED_DECISIONS.contains(&decision_str) {
            return Err(format!("unknown decision: {decision_str}"));
        }
        let decision = match decision_str {
            "confirmed" => ValidationDecision::Confirmed,
            "downgraded" => ValidationDecision::Downgraded,
            "false_positive" => ValidationDecision::FalsePositive,
            "uncertain" => ValidationDecision::Uncertain,
            _ => unreachable!(),
        };

        let severity = match obj.get("severity") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) => {
                let lower = s.to_ascii_lowercase();
                if !ALLOWED_SEVERITIES.contains(&lower.as_str()) {
                    return Err(format!("unknown severity: {s}"));
                }
                Some(
                    lower
                        .parse::<Severity>()
                        .map_err(|_| format!("failed to parse severity: {s}"))?,
                )
            }
            Some(_) => return Err("severity must be a string or null".into()),
        };

        let reasoning = obj
            .get("reasoning")
            .and_then(|r| r.as_str())
            .ok_or_else(|| "missing or non-string reasoning".to_string())?;
        if reasoning.len() > MAX_REASONING_LEN {
            return Err(format!(
                "reasoning exceeds max length ({MAX_REASONING_LEN})"
            ));
        }

        let confidence = obj
            .get("confidence")
            .and_then(|c| c.as_f64())
            .ok_or_else(|| "missing or non-numeric confidence".to_string())?;
        if !(0.0..=1.0).contains(&confidence) {
            return Err(format!("confidence out of range [0,1]: {confidence}"));
        }

        Ok(ValidationResult {
            finding_id: finding.id.clone(),
            original_severity: finding.severity,
            validated_severity: severity,
            status: decision,
            reasoning: reasoning.into(),
            confidence,
        })
    }

    /// LLM-based skeptical validation
    async fn llm_validate(
        &self,
        provider: &Arc<dyn LlmProvider>,
        finding: &Finding,
    ) -> Result<ValidationResult, VestError> {
        let prompt = self.build_validation_prompt(finding);

        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are a skeptical security validator. Respond with JSON only. You are biased toward finding issues with reported vulnerabilities."}),
            serde_json::json!({"role": "user", "content": prompt}),
        ];

        let response = provider.chat(&messages, &self.model).await?;

        match self.parse_llm_validation_response(finding, &response) {
            Ok(result) => Ok(result),
            Err(parse_error) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    response_len = response.len(),
                    parse_error = %parse_error,
                    "Failed to parse LLM validator response"
                );
                Err(VestError::Agent(format!(
                    "malformed validator response for finding {}: {parse_error}",
                    finding.id
                )))
            }
        }
    }

    /// Heuristic validation (no LLM needed). Returns (result, enriched_finding).
    ///
    /// Applies `validated_severity` and adjusted `confidence` onto the returned finding
    /// for Confirmed, Downgraded, and Uncertain paths.
    pub fn heuristic_validate(&self, finding: &Finding) -> (ValidationResult, Finding) {
        let mut enriched = finding.clone();
        enrich_finding_heuristic(&mut enriched);

        let mut confidence = enriched.confidence;
        let mut reasons: Vec<String> = Vec::new();
        let mut decision = ValidationDecision::Confirmed;
        let mut severity = enriched.severity;

        // Rule 1: Very low confidence findings are suspect
        if confidence < 0.3 {
            reasons.push("Confidence below 0.3 threshold".into());
            decision = ValidationDecision::Uncertain;
        }

        // Rule 2: Info severity with no evidence is likely noise
        if enriched.severity == Severity::Info && enriched.evidence == serde_json::json!({}) {
            reasons.push("Info severity with empty evidence".into());
            confidence -= 0.3;
        }

        // Rule 3: Critical severity with low confidence should be downgraded
        if enriched.severity == Severity::Critical && confidence < 0.5 {
            reasons.push("Critical severity with low confidence downgraded to High".into());
            severity = Severity::High;
            decision = ValidationDecision::Downgraded;
        }

        // Rule 4: Unknown vulnerability class is suspect
        if enriched.vulnerability_class == VulnerabilityClass::Unknown {
            reasons.push("Unknown vulnerability class".into());
            confidence -= 0.2;
        }

        // Rule 5: Very low confidence after heuristic checks -> false positive
        // Don't override Uncertain from Rule 1 unless confidence is truly negligible
        if confidence < 0.1 {
            if decision == ValidationDecision::Uncertain {
                // Only escalate to FalsePositive if initial confidence was already < 0.1
                if finding.confidence < 0.1 {
                    decision = ValidationDecision::FalsePositive;
                }
            } else {
                decision = ValidationDecision::FalsePositive;
            }
        }

        let confidence = confidence.max(0.0);

        let result = ValidationResult {
            finding_id: enriched.id.clone(),
            original_severity: finding.severity,
            validated_severity: Some(severity),
            status: decision,
            reasoning: reasons.join("; "),
            confidence,
        };

        // Apply validated severity/confidence onto the finding for non-FP paths.
        match decision {
            ValidationDecision::Confirmed
            | ValidationDecision::Downgraded
            | ValidationDecision::Uncertain => {
                enriched.severity = severity;
                enriched.confidence = confidence;
                if decision == ValidationDecision::Confirmed
                    || decision == ValidationDecision::Downgraded
                {
                    enriched.status = FindingStatus::Confirmed;
                }
                // Refresh severity estimate after possible downgrade.
                if let Some(obj) = enriched.metadata.as_object_mut() {
                    obj.insert(
                        "severity_score_estimate".into(),
                        serde_json::json!(severity_score_estimate(severity)),
                    );
                }
            }
            ValidationDecision::FalsePositive => {}
        }

        (result, enriched)
    }

    fn extract_json_object(&self, text: &str) -> Option<String> {
        let trimmed = text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return Some(trimmed.to_string());
        }
        if let Some(start) = trimmed.find("```json") {
            let start = start + 7;
            if let Some(end) = trimmed[start..].find("```") {
                let inner = trimmed[start..start + end].trim();
                if inner.starts_with('{') {
                    return Some(inner.to_string());
                }
            }
        }
        // Fallback: first {...} span
        if let Some(start) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                if end > start {
                    return Some(trimmed[start..=end].to_string());
                }
            }
        }
        None
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_finding(
        severity: Severity,
        confidence: f64,
        vuln_class: VulnerabilityClass,
    ) -> Finding {
        Finding {
            id: "f1".into(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: "Test".into(),
            description: "test".into(),
            vulnerability_class: vuln_class,
            severity,
            confidence,
            status: FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({"test": true}),
            poc: None,
            remediation: None,
            location: serde_json::json!({"url": "http://test.com"}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_heuristic_validate_low_confidence_uncertain() {
        let validator = Validator::new();
        let finding = make_finding(Severity::Medium, 0.2, VulnerabilityClass::XSS);
        let (result, enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::Uncertain);
        assert!((enriched.confidence - result.confidence).abs() < f64::EPSILON);
    }

    #[test]
    fn test_heuristic_validate_critical_low_confidence_downgraded() {
        let validator = Validator::new();
        let finding = make_finding(Severity::Critical, 0.4, VulnerabilityClass::BufferOverflow);
        let (result, enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::Downgraded);
        assert_eq!(result.validated_severity, Some(Severity::High));
        assert_eq!(enriched.severity, Severity::High);
        assert!((enriched.confidence - result.confidence).abs() < f64::EPSILON);
    }

    #[test]
    fn test_heuristic_validate_high_confidence_confirmed() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::SQLInjection);
        let (result, enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::Confirmed);
        assert_eq!(enriched.severity, Severity::High);
        assert!((enriched.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_heuristic_validate_unknown_class_reduces_confidence() {
        let validator = Validator::new();
        let finding = make_finding(Severity::Medium, 0.5, VulnerabilityClass::Unknown);
        let (result, enriched) = validator.heuristic_validate(&finding);
        assert!(result.confidence < 0.5);
        assert!((enriched.confidence - result.confidence).abs() < f64::EPSILON);
    }

    #[test]
    fn test_strict_mode_false_positive_very_low_confidence() {
        let validator = Validator::new().strict(true);
        let finding = make_finding(Severity::Low, 0.05, VulnerabilityClass::Unknown);
        let (result, _enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::FalsePositive);
    }

    #[test]
    fn test_enrich_finding_xss() {
        let mut finding = make_finding(Severity::High, 0.8, VulnerabilityClass::Unknown);
        finding.title = "Reflected XSS in query parameter".into();
        enrich_finding_heuristic(&mut finding);
        assert_eq!(finding.vulnerability_class, VulnerabilityClass::XSS);
        assert!(finding.cvss_score.is_none());
        assert_eq!(
            finding.metadata["severity_score_estimate"].as_f64(),
            Some(7.5)
        );
    }

    #[test]
    fn test_enrich_finding_unknown_stays_unknown() {
        let mut finding = make_finding(Severity::Low, 0.5, VulnerabilityClass::Unknown);
        finding.title = "some generic observation".into();
        enrich_finding_heuristic(&mut finding);
        assert_eq!(finding.vulnerability_class, VulnerabilityClass::Unknown);
        assert!(finding.cvss_score.is_none());
        assert_eq!(
            finding.metadata["severity_score_estimate"].as_f64(),
            Some(3.0)
        );
    }

    #[test]
    fn test_enrich_finding_already_has_class() {
        let mut finding = make_finding(Severity::Medium, 0.7, VulnerabilityClass::BufferOverflow);
        finding.title = "XSS in parameter".into();
        enrich_finding_heuristic(&mut finding);
        assert_eq!(
            finding.vulnerability_class,
            VulnerabilityClass::BufferOverflow
        );
    }

    #[test]
    fn test_prompt_excludes_raw_evidence_by_default() {
        let validator = Validator::new();
        let mut finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        finding.evidence = serde_json::json!({"secret": "SENTINEL_EVIDENCE_RAW"});
        finding.location = serde_json::json!({"path": "SENTINEL_LOCATION_RAW"});
        let prompt = validator.build_validation_prompt(&finding);
        assert!(!prompt.contains("SENTINEL_EVIDENCE_RAW"));
        assert!(!prompt.contains("SENTINEL_LOCATION_RAW"));
        assert!(!prompt.contains("\"evidence\""));
        assert!(prompt.contains("allowlisted fields only"));
    }

    #[test]
    fn test_prompt_optional_evidence_excerpt_is_bounded() {
        let validator = Validator::new().include_evidence_excerpt(true);
        let mut finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        finding.evidence = serde_json::json!({"note": "x".repeat(2_000)});
        let prompt = validator.build_validation_prompt(&finding);
        assert!(prompt.contains("evidence_excerpt"));
        assert!(!prompt.contains(&"x".repeat(2_000)));
    }

    #[test]
    fn test_parse_valid_llm_response() {
        let validator = Validator::new();
        let finding = make_finding(Severity::Critical, 0.9, VulnerabilityClass::XSS);
        let response = r#"{
            "finding_id": "f1",
            "decision": "downgraded",
            "severity": "high",
            "reasoning": "Impact is limited",
            "confidence": 0.7
        }"#;
        let result = validator
            .parse_llm_validation_response(&finding, response)
            .unwrap();
        assert_eq!(result.status, ValidationDecision::Downgraded);
        assert_eq!(result.validated_severity, Some(Severity::High));
        assert!((result.confidence - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_rejects_bad_confidence() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        let response =
            r#"{"decision":"confirmed","severity":"high","reasoning":"ok","confidence":1.5}"#;
        let err = validator
            .parse_llm_validation_response(&finding, response)
            .unwrap_err();
        assert!(err.contains("confidence"));
    }

    #[test]
    fn test_parse_rejects_unknown_decision() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        let response =
            r#"{"decision":"maybe","severity":"high","reasoning":"ok","confidence":0.5}"#;
        let err = validator
            .parse_llm_validation_response(&finding, response)
            .unwrap_err();
        assert!(err.contains("unknown decision"));
    }

    #[test]
    fn test_parse_rejects_unknown_severity() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        let response =
            r#"{"decision":"confirmed","severity":"extreme","reasoning":"ok","confidence":0.5}"#;
        let err = validator
            .parse_llm_validation_response(&finding, response)
            .unwrap_err();
        assert!(err.contains("unknown severity"));
    }

    #[test]
    fn test_parse_rejects_finding_id_mismatch() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        let response = r#"{"finding_id":"other","decision":"confirmed","severity":"high","reasoning":"ok","confidence":0.5}"#;
        let err = validator
            .parse_llm_validation_response(&finding, response)
            .unwrap_err();
        assert!(err.contains("finding_id mismatch"));
    }

    #[test]
    fn test_parse_rejects_oversized_reasoning() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        let reasoning = "r".repeat(MAX_REASONING_LEN + 1);
        let response = format!(
            r#"{{"decision":"confirmed","severity":"high","reasoning":"{reasoning}","confidence":0.5}}"#
        );
        let err = validator
            .parse_llm_validation_response(&finding, &response)
            .unwrap_err();
        assert!(err.contains("reasoning exceeds"));
    }

    enum ScriptedResponse {
        Ok(String),
        Err(&'static str),
    }

    struct ScriptedProvider {
        responses: Vec<ScriptedResponse>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl LlmProvider for ScriptedProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            match self.responses.get(i) {
                Some(ScriptedResponse::Ok(s)) => Ok(s.clone()),
                Some(ScriptedResponse::Err(msg)) => Err(VestError::Provider((*msg).into())),
                None => Err(VestError::Provider("no more scripted responses".into())),
            }
        }
        async fn chat_stream(
            &self,
            messages: &[serde_json::Value],
            model: &str,
        ) -> Result<String, VestError> {
            self.chat(messages, model).await
        }
        async fn list_models(&self) -> Result<Vec<String>, VestError> {
            Ok(vec!["scripted".into()])
        }
        async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
            Ok(true)
        }
        async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_validate_preserves_batch_on_provider_failure() {
        let provider = Arc::new(ScriptedProvider {
            responses: vec![
                ScriptedResponse::Ok(
                    r#"{"decision":"confirmed","severity":"high","reasoning":"ok","confidence":0.9}"#
                        .into(),
                ),
                ScriptedResponse::Err("boom"),
                ScriptedResponse::Ok(
                    r#"{"decision":"confirmed","severity":"medium","reasoning":"ok","confidence":0.8}"#
                        .into(),
                ),
            ],
            calls: AtomicUsize::new(0),
        });
        let validator = Validator::new().with_provider(provider, "m");
        let findings = vec![
            {
                let mut f = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
                f.id = "a".into();
                f
            },
            {
                let mut f = make_finding(Severity::Medium, 0.8, VulnerabilityClass::SSRF);
                f.id = "b".into();
                f.title = "SSRF via URL parameter".into();
                f
            },
            {
                let mut f = make_finding(Severity::Low, 0.7, VulnerabilityClass::CORS);
                f.id = "c".into();
                f
            },
        ];
        let out = validator.validate(&findings).await.unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().any(|f| f.id == "b"));
        let preserved = out.iter().find(|f| f.id == "b").unwrap();
        assert_eq!(preserved.severity, Severity::Medium);
    }

    #[tokio::test]
    async fn test_validate_preserves_on_malformed_response() {
        let provider = Arc::new(ScriptedProvider {
            responses: vec![ScriptedResponse::Ok("NOT JSON AT ALL".into())],
            calls: AtomicUsize::new(0),
        });
        let validator = Validator::new().with_provider(provider, "m");
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::XSS);
        let out = validator
            .validate(std::slice::from_ref(&finding))
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, finding.id);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn test_llm_validate_applies_severity_and_confidence() {
        let provider = Arc::new(ScriptedProvider {
            responses: vec![ScriptedResponse::Ok(
                r#"{"decision":"downgraded","severity":"medium","reasoning":"limited impact","confidence":0.55}"#
                    .into(),
            )],
            calls: AtomicUsize::new(0),
        });
        let validator = Validator::new().with_provider(provider, "m");
        let finding = make_finding(Severity::Critical, 0.95, VulnerabilityClass::XSS);
        let out = validator.validate(&[finding]).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Medium);
        assert!((out[0].confidence - 0.55).abs() < f64::EPSILON);
    }
}
