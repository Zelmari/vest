use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::traits::LlmProvider;
use vest_core::types::{Finding, FindingStatus, Severity, VulnerabilityClass};

pub struct Validator {
    provider: Option<Arc<dyn LlmProvider>>,
    model: String,
    strict_mode: bool,
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

/// Heuristically enrich a finding with vulnerability class and CVSS score
/// when the LLM hasn't provided them.
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

    // Assign CVSS score based on severity if not already set
    if finding.cvss_score.is_none() {
        let score = match finding.severity {
            Severity::Critical => 9.0,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        };
        finding.cvss_score = Some(score);
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

    /// Validate a batch of findings. Returns validated findings (FPs removed), enriched.
    pub async fn validate(&self, findings: &[Finding]) -> Result<Vec<Finding>, VestError> {
        let mut validated = Vec::new();

        for finding in findings {
            if let Some(provider) = &self.provider {
                let result = self.llm_validate(provider, finding).await?;
                match result.status {
                    ValidationDecision::Confirmed => {
                        let mut confirmed = finding.clone();
                        confirmed.status = FindingStatus::Confirmed;
                        if let Some(sev) = result.validated_severity {
                            confirmed.severity = sev;
                        }
                        confirmed = self.apply_llm_enrichment(confirmed, &result);
                        validated.push(confirmed);
                    }
                    ValidationDecision::Downgraded => {
                        let mut downgraded = finding.clone();
                        downgraded.status = FindingStatus::Confirmed;
                        if let Some(sev) = result.validated_severity {
                            downgraded.severity = sev;
                        }
                        downgraded = self.apply_llm_enrichment(downgraded, &result);
                        validated.push(downgraded);
                    }
                    ValidationDecision::FalsePositive => {
                        // Don't add to validated list
                    }
                    ValidationDecision::Uncertain => {
                        // In strict mode, reject uncertain findings
                        if !self.strict_mode {
                            let mut enriched = finding.clone();
                            enrich_finding_heuristic(&mut enriched);
                            validated.push(enriched);
                        }
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

    /// LLM-based skeptical validation
    async fn llm_validate(
        &self,
        provider: &Arc<dyn LlmProvider>,
        finding: &Finding,
    ) -> Result<ValidationResult, VestError> {
        let questions = VALIDATION_QUESTIONS.join("\n");
        let prompt = format!(
            "You are a SKEPTICAL security validator. Your job is to CHALLENGE every finding.\n\
             \nFinding:\n\
             Title: {}\n\
             Vulnerability Class: {:?}\n\
             Severity: {:?}\n\
             Description: {}\n\
             Confidence: {:.2}\n\
             Evidence: {}\n\
             Location: {}\n\
             CWE: {}\n\
             CVSS: {:?}\n\
             \nChallenge this finding by answering these questions:\n\
             {}\n\
             \nRespond with a JSON object:\n\
             {{\n  \"decision\": \"confirmed\" | \"downgraded\" | \"false_positive\" | \"uncertain\",\n  \"severity\": \"critical\" | \"high\" | \"medium\" | \"low\" | \"info\" | null,\n  \"reasoning\": \"Your skeptical analysis\",\n  \"confidence\": 0.0-1.0\n  }}\n\
             \nOnly respond with the JSON object, no other text.",
            finding.title,
            finding.vulnerability_class,
            finding.severity,
            finding.description,
            finding.confidence,
            serde_json::to_string(&finding.evidence).unwrap_or_default(),
            serde_json::to_string(&finding.location).unwrap_or_default(),
            finding.cwe_id.as_deref().unwrap_or("none"),
            finding.cvss_score,
            questions,
        );

        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are a skeptical security validator. Respond with JSON only. You are biased toward finding issues with reported vulnerabilities."}),
            serde_json::json!({"role": "user", "content": prompt}),
        ];

        let response = provider.chat(&messages, &self.model).await?;

        let json_str = self.extract_json_object(&response);
        if let Some(json) = json_str {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                let decision = match v
                    .get("decision")
                    .and_then(|d| d.as_str())
                    .unwrap_or("uncertain")
                {
                    "confirmed" => ValidationDecision::Confirmed,
                    "downgraded" => ValidationDecision::Downgraded,
                    "false_positive" => ValidationDecision::FalsePositive,
                    _ => ValidationDecision::Uncertain,
                };
                let severity = v
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse::<Severity>().ok());
                let reasoning = v
                    .get("reasoning")
                    .and_then(|r| r.as_str())
                    .unwrap_or("")
                    .into();
                let confidence = v.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.5);

                return Ok(ValidationResult {
                    finding_id: finding.id.clone(),
                    original_severity: finding.severity,
                    validated_severity: severity,
                    status: decision,
                    reasoning,
                    confidence,
                });
            }
        }

        tracing::warn!(
            "Failed to parse LLM validator response for finding {}: {:?}",
            finding.id,
            response
        );
        Ok(ValidationResult {
            finding_id: finding.id.clone(),
            original_severity: finding.severity,
            validated_severity: None,
            status: ValidationDecision::Uncertain,
            reasoning: "Failed to parse LLM validation response".into(),
            confidence: finding.confidence * 0.5,
        })
    }

    /// Heuristic validation (no LLM needed). Returns (result, enriched_finding).
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

        let result = ValidationResult {
            finding_id: enriched.id.clone(),
            original_severity: enriched.severity,
            validated_severity: Some(severity),
            status: decision,
            reasoning: reasons.join("; "),
            confidence: confidence.max(0.0),
        };

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
    use chrono::Utc;

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
        let (result, _enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::Uncertain);
    }

    #[test]
    fn test_heuristic_validate_critical_low_confidence_downgraded() {
        let validator = Validator::new();
        let finding = make_finding(Severity::Critical, 0.4, VulnerabilityClass::BufferOverflow);
        let (result, _enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::Downgraded);
        assert_eq!(result.validated_severity, Some(Severity::High));
    }

    #[test]
    fn test_heuristic_validate_high_confidence_confirmed() {
        let validator = Validator::new();
        let finding = make_finding(Severity::High, 0.9, VulnerabilityClass::SQLInjection);
        let (result, _enriched) = validator.heuristic_validate(&finding);
        assert_eq!(result.status, ValidationDecision::Confirmed);
    }

    #[test]
    fn test_heuristic_validate_unknown_class_reduces_confidence() {
        let validator = Validator::new();
        let finding = make_finding(Severity::Medium, 0.5, VulnerabilityClass::Unknown);
        let (result, _enriched) = validator.heuristic_validate(&finding);
        assert!(result.confidence < 0.5);
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
        assert!(finding.cvss_score.is_some());
    }

    #[test]
    fn test_enrich_finding_unknown_stays_unknown() {
        let mut finding = make_finding(Severity::Low, 0.5, VulnerabilityClass::Unknown);
        finding.title = "some generic observation".into();
        enrich_finding_heuristic(&mut finding);
        // No pattern match, should remain Unknown
        assert_eq!(finding.vulnerability_class, VulnerabilityClass::Unknown);
        // CVSS still assigned based on severity
        assert!(finding.cvss_score.is_some());
    }

    #[test]
    fn test_enrich_finding_already_has_class() {
        let mut finding = make_finding(Severity::Medium, 0.7, VulnerabilityClass::BufferOverflow);
        finding.title = "XSS in parameter".into();
        enrich_finding_heuristic(&mut finding);
        // Should keep original class, not guess from title
        assert_eq!(
            finding.vulnerability_class,
            VulnerabilityClass::BufferOverflow
        );
    }
}
