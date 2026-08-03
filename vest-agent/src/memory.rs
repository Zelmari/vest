use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use vest_core::ids::new_id;
use vest_core::types::{Finding, PatternType, ScanMemoryEntry, VulnerabilityClass};

/// Cross-session agent memory that persists vulnerability patterns,
/// false positive markers, and successful tool sequences across scans.
pub struct AgentMemory {
    /// In-memory false positive cache keyed by target hash + pattern hash
    pub false_positives: HashMap<String, FpEntry>,
    /// Confirmed vulnerability patterns
    pub confirmed_patterns: Vec<ConfirmedPattern>,
    /// Successful tool sequences
    pub tool_sequences: Vec<ToolSequence>,
    /// Current session's findings
    pub session_findings: Vec<Finding>,
    /// Session observations
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpEntry {
    pub pattern_hash: String,
    pub target_hash: Option<String>,
    pub reason: String,
    pub context: String,
    pub confidence: f64,
    pub occurrences: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedPattern {
    pub pattern_hash: String,
    pub vulnerability_class: VulnerabilityClass,
    pub description: String,
    pub occurrence_count: u32,
    pub avg_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSequence {
    pub tools: Vec<String>,
    pub description: String,
    pub success_rate: f64,
    pub times_used: u32,
}

impl AgentMemory {
    pub fn new() -> Self {
        Self {
            false_positives: HashMap::new(),
            confirmed_patterns: Vec::new(),
            tool_sequences: Vec::new(),
            session_findings: Vec::new(),
            observations: Vec::new(),
        }
    }

    /// Record a false positive finding so it won't be rediscovered
    pub fn record_false_positive(&mut self, finding: &Finding, reason: &str, context: &str) {
        let pattern_hash = self.hash_finding(finding);
        let target_hash = finding.target_id.clone();

        let entry = FpEntry {
            pattern_hash: pattern_hash.clone(),
            target_hash: Some(target_hash),
            reason: reason.into(),
            context: context.into(),
            confidence: 0.95,
            occurrences: 1,
        };

        self.false_positives.insert(pattern_hash, entry);
        self.observations
            .push(format!("Recorded false positive: {}", finding.title));
    }

    /// Check if a finding matches a known false positive pattern
    pub fn is_known_false_positive(&self, finding: &Finding) -> Option<&FpEntry> {
        let pattern_hash = self.hash_finding(finding);

        // Check exact match
        if let Some(entry) = self.false_positives.get(&pattern_hash) {
            return Some(entry);
        }

        // Fuzzy match: same target + same vuln class + similar content
        self.false_positives.values().find(|entry| {
            entry.target_hash.as_deref() == Some(&finding.target_id)
                && (finding
                    .title
                    .to_lowercase()
                    .contains(&entry.reason.to_lowercase())
                    || entry
                        .reason
                        .to_lowercase()
                        .contains(&finding.title.to_lowercase())
                    || finding
                        .description
                        .to_lowercase()
                        .contains(&entry.reason.to_lowercase())
                    || entry
                        .reason
                        .to_lowercase()
                        .contains(&finding.description.to_lowercase()))
        })
    }

    /// Record a confirmed vulnerability pattern for faster future detection
    pub fn record_confirmed_pattern(&mut self, finding: &Finding) {
        let pattern_hash = self.hash_finding(finding);

        // Check if already known
        if let Some(existing) = self
            .confirmed_patterns
            .iter_mut()
            .find(|p| p.pattern_hash == pattern_hash)
        {
            existing.occurrence_count += 1;
            existing.avg_confidence = (existing.avg_confidence + finding.confidence) / 2.0;
        } else {
            self.confirmed_patterns.push(ConfirmedPattern {
                pattern_hash,
                vulnerability_class: finding.vulnerability_class,
                description: finding.title.clone(),
                occurrence_count: 1,
                avg_confidence: finding.confidence,
            });
        }
    }

    /// Record a successful tool sequence
    pub fn record_tool_sequence(&mut self, tools: Vec<String>, description: impl Into<String>) {
        let desc = description.into();
        if let Some(existing) = self
            .tool_sequences
            .iter_mut()
            .find(|t| t.tools == tools && t.description == desc)
        {
            existing.times_used += 1;
            existing.success_rate = (existing.success_rate + 1.0) / 2.0;
        } else {
            self.tool_sequences.push(ToolSequence {
                tools,
                description: desc,
                success_rate: 1.0,
                times_used: 1,
            });
        }
    }

    /// Convert memory entries to persistent format for SQLite storage
    pub fn to_scan_memory_entries(&self) -> Vec<ScanMemoryEntry> {
        let now = Utc::now();
        let mut entries = Vec::new();

        // False positives
        for fp in self.false_positives.values() {
            entries.push(ScanMemoryEntry {
                id: new_id(),
                pattern_hash: fp.pattern_hash.clone(),
                pattern_type: PatternType::FalsePositive,
                target_hash: fp.target_hash.clone(),
                description: fp.reason.clone(),
                evidence: serde_json::json!({"context": fp.context}),
                confidence: fp.confidence,
                occurrences: fp.occurrences,
                created_at: now,
                updated_at: now,
            });
        }

        // Confirmed patterns
        for cp in &self.confirmed_patterns {
            entries.push(ScanMemoryEntry {
                id: new_id(),
                pattern_hash: cp.pattern_hash.clone(),
                pattern_type: PatternType::ConfirmedVuln,
                target_hash: None,
                description: cp.description.clone(),
                evidence: serde_json::json!({"class": cp.vulnerability_class.to_string()}),
                confidence: cp.avg_confidence,
                occurrences: cp.occurrence_count,
                created_at: now,
                updated_at: now,
            });
        }

        entries
    }

    /// Load memory entries from persistent storage
    pub fn load_from_entries(&mut self, entries: &[ScanMemoryEntry]) {
        for entry in entries {
            match entry.pattern_type {
                PatternType::FalsePositive => {
                    self.false_positives.insert(
                        entry.pattern_hash.clone(),
                        FpEntry {
                            pattern_hash: entry.pattern_hash.clone(),
                            target_hash: entry.target_hash.clone(),
                            reason: entry.description.clone(),
                            context: serde_json::to_string(&entry.evidence).unwrap_or_default(),
                            confidence: entry.confidence,
                            occurrences: entry.occurrences,
                        },
                    );
                }
                PatternType::ConfirmedVuln => {
                    let vuln_class = entry
                        .evidence
                        .get("class")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<VulnerabilityClass>().ok())
                        .unwrap_or(VulnerabilityClass::Unknown);
                    self.confirmed_patterns.push(ConfirmedPattern {
                        pattern_hash: entry.pattern_hash.clone(),
                        vulnerability_class: vuln_class,
                        description: entry.description.clone(),
                        occurrence_count: entry.occurrences,
                        avg_confidence: entry.confidence,
                    });
                }
                _ => {}
            }
        }
    }

    fn hash_finding(&self, finding: &Finding) -> String {
        let combined = format!("{}:{}", finding.title, finding.vulnerability_class);
        let mut hasher = DefaultHasher::new();
        combined.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub fn clear_session(&mut self) {
        self.session_findings.clear();
        self.observations.clear();
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.session_findings.push(finding);
    }

    pub fn add_observation(&mut self, obs: impl Into<String>) {
        self.observations.push(obs.into());
    }
}

impl Default for AgentMemory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vest_core::types::FindingStatus;

    fn make_finding(title: &str, vuln_class: VulnerabilityClass, target_id: &str) -> Finding {
        Finding {
            id: new_id(),
            scan_id: "s1".into(),
            target_id: target_id.into(),
            title: title.into(),
            description: "test".into(),
            vulnerability_class: vuln_class,
            severity: vest_core::types::Severity::High,
            confidence: 0.9,
            status: FindingStatus::Open,
            severity_score_estimate: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_record_and_check_false_positive() {
        let mut memory = AgentMemory::new();
        let finding = make_finding("XSS in search", VulnerabilityClass::XSS, "target-1");
        memory.record_false_positive(&finding, "Auth required", "Behind login");
        assert!(memory.is_known_false_positive(&finding).is_some());
    }

    #[test]
    fn test_different_target_not_false_positive_by_fuzzy() {
        let mut memory = AgentMemory::new();
        let f1 = make_finding("XSS in search", VulnerabilityClass::XSS, "target-1");
        memory.record_false_positive(&f1, "Auth required", "XSS in search");
        let f2 = make_finding("XSS in search", VulnerabilityClass::XSS, "target-2");
        // Same title+class on different target - hash matches at exact level
        let result = memory.is_known_false_positive(&f2);
        assert!(result.is_some());
    }

    #[test]
    fn test_record_confirmed_pattern() {
        let mut memory = AgentMemory::new();
        let finding = make_finding("Buffer Overflow", VulnerabilityClass::BufferOverflow, "t1");
        memory.record_confirmed_pattern(&finding);
        assert_eq!(memory.confirmed_patterns.len(), 1);
        memory.record_confirmed_pattern(&finding);
        assert_eq!(memory.confirmed_patterns[0].occurrence_count, 2);
    }

    #[test]
    fn test_record_tool_sequence() {
        let mut memory = AgentMemory::new();
        memory.record_tool_sequence(
            vec!["read_memory".into(), "disassemble".into()],
            "Found ROP gadget",
        );
        assert_eq!(memory.tool_sequences.len(), 1);
        memory.record_tool_sequence(
            vec!["read_memory".into(), "disassemble".into()],
            "Found ROP gadget",
        );
        assert_eq!(memory.tool_sequences[0].times_used, 2);
    }

    #[test]
    fn test_to_scan_memory_entries() {
        let mut memory = AgentMemory::new();
        let f = make_finding("SQL Injection", VulnerabilityClass::SQLInjection, "t1");
        memory.record_false_positive(&f, "WAF protected", "WAF blocks payload");
        memory.record_confirmed_pattern(&f);
        let entries = memory.to_scan_memory_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_clear_session() {
        let mut memory = AgentMemory::new();
        memory.add_finding(make_finding("test", VulnerabilityClass::Unknown, "t1"));
        memory.add_observation("test obs");
        assert_eq!(memory.session_findings.len(), 1);
        memory.clear_session();
        assert_eq!(memory.session_findings.len(), 0);
        assert_eq!(memory.observations.len(), 0);
    }
}
