use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

/// Severity of a vulnerability finding, ordered from most to least critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TargetType {
    Process,
    Binary,
    Web,
    Network,
    Browser,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "kebab-case")]
pub enum ScanMode {
    Pipeline,
    Swarm,
    #[strum(serialize = "tool-use")]
    ToolUse,
    Hierarchical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum VulnerabilityClass {
    BufferOverflow,
    UseAfterFree,
    DoubleFree,
    IntegerOverflow,
    FormatString,
    RaceCondition,
    XSS,
    SQLInjection,
    CommandInjection,
    SSTI,
    SSRF,
    XXE,
    PathTraversal,
    IDOR,
    AuthBypass,
    CSRF,
    InsecureDeserialization,
    JWTAttack,
    CORS,
    Clickjacking,
    CachePoisoning,
    RequestSmuggling,
    StackCanaryBypass,
    ROPGadget,
    ASLRBypass,
    DEPBypass,
    SEHOverwrite,
    ImportTableHooking,
    DLLInjection,
    CodeCave,
    AntiDebug,
    SpeedHack,
    WallHack,
    Aimbot,
    NoClip,
    InfiniteResources,
    SaveFileRCE,
    ProtocolExploit,
    AssetTheft,
    DRMBypass,
    EngineExploit,
    WebSocketTamper,
    ClientPredictionExploit,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Fixed,
    WontFix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ToolCallType {
    ToolCall,
    LlmResponse,
    ApprovalRequest,
    ApprovalResponse,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PatternType {
    FalsePositive,
    ConfirmedVuln,
    UsefulToolSequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum MergeStrategy {
    Voting,
    Union,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FallbackStrategy {
    NextOnFailure,
    NextOnRateLimit,
    TryAllParallel,
}

/// A vulnerability finding discovered during a scan.
///
/// Contains the full details of a vulnerability including its classification,
/// severity, confidence score, evidence, and optional proof-of-concept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scan_id: String,
    pub target_id: String,
    pub title: String,
    pub description: String,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: Severity,
    pub confidence: f64,
    pub status: FindingStatus,
    pub cvss_score: Option<f64>,
    pub cve_id: Option<String>,
    pub cwe_id: Option<String>,
    pub evidence: serde_json::Value,
    pub poc: Option<String>,
    pub remediation: Option<String>,
    pub location: serde_json::Value,
    pub false_positive_history: Option<serde_json::Value>,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub discovered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A scan target (process, binary, web app, network service, browser, or file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub target_type: TargetType,
    pub path: Option<String>,
    pub url_str: Option<String>,
    pub pid: Option<u32>,
    pub host: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single scan session with its configuration, status, and result counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: String,
    pub target_id: String,
    pub mode: ScanMode,
    pub config: serde_json::Value,
    pub status: ScanStatus,
    pub agent_model: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub total_findings: u64,
    pub critical_count: u64,
    pub high_count: u64,
    pub medium_count: u64,
    pub low_count: u64,
    pub info_count: u64,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub scan_id: String,
    pub finding_id: Option<String>,
    pub artifact_type: String,
    pub mime_type: Option<String>,
    pub filename: String,
    pub size_bytes: Option<u64>,
    pub content_path: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMemoryEntry {
    pub id: String,
    pub pattern_hash: String,
    pub pattern_type: PatternType,
    pub target_hash: Option<String>,
    pub description: String,
    pub evidence: serde_json::Value,
    pub confidence: f64,
    pub occurrences: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub id: String,
    pub scan_id: String,
    pub sequence: u32,
    pub agent_role: String,
    pub action_type: ToolCallType,
    pub action_data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn test_severity_parse() {
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("high".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("medium".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("low".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("info".parse::<Severity>().unwrap(), Severity::Info);
    }

    #[test]
    fn test_severity_parse_invalid() {
        assert!("invalid".parse::<Severity>().is_err());
        assert!("".parse::<Severity>().is_err());
        assert!("CRITICAL".parse::<Severity>().is_err());
    }

    #[test]
    fn test_severity_serde_json() {
        let s = Severity::Critical;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#""critical""#);
        let deser: Severity = serde_json::from_str(r#""critical""#).unwrap();
        assert_eq!(deser, Severity::Critical);

        let result: Result<Severity, _> = serde_json::from_str(r#""invalid-severity""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_target_type_display_and_parse() {
        assert_eq!(TargetType::Process.to_string(), "process");
        assert_eq!(
            "process".parse::<TargetType>().unwrap(),
            TargetType::Process
        );
        assert_eq!(TargetType::Binary.to_string(), "binary");
        assert_eq!(TargetType::Web.to_string(), "web");
        assert_eq!(TargetType::Network.to_string(), "network");
        assert_eq!(TargetType::Browser.to_string(), "browser");
        assert_eq!(TargetType::File.to_string(), "file");
    }

    #[test]
    fn test_target_type_parse_invalid() {
        assert!("invalid".parse::<TargetType>().is_err());
        assert!("Process".parse::<TargetType>().is_err());
    }

    #[test]
    fn test_scan_mode_display() {
        assert_eq!(ScanMode::Pipeline.to_string(), "pipeline");
        assert_eq!(ScanMode::Swarm.to_string(), "swarm");
        assert_eq!(ScanMode::ToolUse.to_string(), "tool-use");
        assert_eq!(ScanMode::Hierarchical.to_string(), "hierarchical");
    }

    #[test]
    fn test_scan_mode_parse() {
        assert_eq!("pipeline".parse::<ScanMode>().unwrap(), ScanMode::Pipeline);
        assert_eq!("swarm".parse::<ScanMode>().unwrap(), ScanMode::Swarm);
        assert_eq!("tool-use".parse::<ScanMode>().unwrap(), ScanMode::ToolUse);
        assert_eq!(
            "hierarchical".parse::<ScanMode>().unwrap(),
            ScanMode::Hierarchical
        );
    }

    #[test]
    fn test_scan_mode_parse_invalid() {
        assert!("ToolUse".parse::<ScanMode>().is_err());
        assert!("invalid".parse::<ScanMode>().is_err());
    }

    #[test]
    fn test_scan_status_display_and_parse() {
        assert_eq!(ScanStatus::Pending.to_string(), "pending");
        assert_eq!(ScanStatus::Running.to_string(), "running");
        assert_eq!(ScanStatus::Paused.to_string(), "paused");
        assert_eq!(ScanStatus::Completed.to_string(), "completed");
        assert_eq!(ScanStatus::Failed.to_string(), "failed");
        assert_eq!(ScanStatus::Cancelled.to_string(), "cancelled");

        assert_eq!(
            "pending".parse::<ScanStatus>().unwrap(),
            ScanStatus::Pending
        );
        assert_eq!(
            "running".parse::<ScanStatus>().unwrap(),
            ScanStatus::Running
        );
        assert_eq!(
            "completed".parse::<ScanStatus>().unwrap(),
            ScanStatus::Completed
        );
        assert_eq!("failed".parse::<ScanStatus>().unwrap(), ScanStatus::Failed);
        assert_eq!(
            "cancelled".parse::<ScanStatus>().unwrap(),
            ScanStatus::Cancelled
        );
    }

    #[test]
    fn test_scan_status_parse_invalid() {
        assert!("unknown".parse::<ScanStatus>().is_err());
    }

    #[test]
    fn test_finding_status_display_and_parse() {
        assert_eq!(FindingStatus::Open.to_string(), "open");
        assert_eq!(FindingStatus::Confirmed.to_string(), "confirmed");
        assert_eq!(FindingStatus::FalsePositive.to_string(), "false_positive");
        assert_eq!(FindingStatus::Fixed.to_string(), "fixed");
        assert_eq!(FindingStatus::WontFix.to_string(), "wont_fix");

        assert_eq!(
            "open".parse::<FindingStatus>().unwrap(),
            FindingStatus::Open
        );
        assert_eq!(
            "confirmed".parse::<FindingStatus>().unwrap(),
            FindingStatus::Confirmed
        );
        assert_eq!(
            "false_positive".parse::<FindingStatus>().unwrap(),
            FindingStatus::FalsePositive
        );
        assert_eq!(
            "fixed".parse::<FindingStatus>().unwrap(),
            FindingStatus::Fixed
        );
        assert_eq!(
            "wont_fix".parse::<FindingStatus>().unwrap(),
            FindingStatus::WontFix
        );
    }

    #[test]
    fn test_finding_status_parse_invalid() {
        assert!("unknown".parse::<FindingStatus>().is_err());
        assert!("Open".parse::<FindingStatus>().is_err());
    }

    #[test]
    fn test_vulnerability_class_display() {
        assert_eq!(
            VulnerabilityClass::BufferOverflow.to_string(),
            "buffer_overflow"
        );
        assert_eq!(
            VulnerabilityClass::UseAfterFree.to_string(),
            "use_after_free"
        );
        assert_eq!(VulnerabilityClass::XSS.to_string(), "xss");
        assert_eq!(
            VulnerabilityClass::SQLInjection.to_string(),
            "sql_injection"
        );
        assert_eq!(VulnerabilityClass::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_vulnerability_class_parse() {
        assert_eq!(
            "buffer_overflow".parse::<VulnerabilityClass>().unwrap(),
            VulnerabilityClass::BufferOverflow
        );
        assert_eq!(
            "use_after_free".parse::<VulnerabilityClass>().unwrap(),
            VulnerabilityClass::UseAfterFree
        );
        assert_eq!(
            "xss".parse::<VulnerabilityClass>().unwrap(),
            VulnerabilityClass::XSS
        );
        assert_eq!(
            "sql_injection".parse::<VulnerabilityClass>().unwrap(),
            VulnerabilityClass::SQLInjection
        );
    }

    #[test]
    fn test_vulnerability_class_parse_invalid() {
        assert!("nonexistent_vuln".parse::<VulnerabilityClass>().is_err());
        assert!("BufferOverflow".parse::<VulnerabilityClass>().is_err());
    }

    #[test]
    fn test_pattern_type_display() {
        assert_eq!(PatternType::FalsePositive.to_string(), "false_positive");
        assert_eq!(PatternType::ConfirmedVuln.to_string(), "confirmed_vuln");
        assert_eq!(
            PatternType::UsefulToolSequence.to_string(),
            "useful_tool_sequence"
        );
    }

    #[test]
    fn test_pattern_type_parse() {
        assert_eq!(
            "false_positive".parse::<PatternType>().unwrap(),
            PatternType::FalsePositive
        );
        assert_eq!(
            "confirmed_vuln".parse::<PatternType>().unwrap(),
            PatternType::ConfirmedVuln
        );
        assert_eq!(
            "useful_tool_sequence".parse::<PatternType>().unwrap(),
            PatternType::UsefulToolSequence
        );
    }

    #[test]
    fn test_pattern_type_parse_invalid() {
        assert!("FalsePositive".parse::<PatternType>().is_err());
        assert!("invalid".parse::<PatternType>().is_err());
    }

    #[test]
    fn test_finding_creation() {
        let now = Utc::now();
        let finding = Finding {
            id: "test-id".into(),
            scan_id: "scan-1".into(),
            target_id: "target-1".into(),
            title: "Buffer Overflow".into(),
            description: "Found a buffer overflow".into(),
            vulnerability_class: VulnerabilityClass::BufferOverflow,
            severity: Severity::Critical,
            confidence: 0.95,
            status: FindingStatus::Open,
            cvss_score: Some(9.8),
            cve_id: Some("CVE-2024-0001".into()),
            cwe_id: Some("CWE-120".into()),
            evidence: serde_json::json!({"crash": true}),
            poc: Some("AAAA ...".into()),
            remediation: Some("Add bounds check".into()),
            location: serde_json::json!({"address": "0xDEADBEEF"}),
            false_positive_history: None,
            tags: vec!["memory".into(), "critical".into()],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        };
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, 0.95);
        assert!(finding.poc.is_some());
    }

    #[test]
    fn test_finding_with_no_cvss() {
        let now = Utc::now();
        let finding = Finding {
            id: "test-id".into(),
            scan_id: "scan-1".into(),
            target_id: "target-1".into(),
            title: "Info Leak".into(),
            description: "Some info leak".into(),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: Severity::Info,
            confidence: 0.3,
            status: FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        };
        assert_eq!(finding.cvss_score, None);
        assert_eq!(finding.cve_id, None);
        assert_eq!(finding.cwe_id, None);
    }

    #[test]
    fn test_finding_json_roundtrip() {
        let now = Utc::now();
        let finding = Finding {
            id: "test-id".into(),
            scan_id: "scan-1".into(),
            target_id: "target-1".into(),
            title: "Test Vuln".into(),
            description: "Test desc".into(),
            vulnerability_class: VulnerabilityClass::XSS,
            severity: Severity::High,
            confidence: 0.8,
            status: FindingStatus::Open,
            cvss_score: Some(7.5),
            cve_id: None,
            cwe_id: Some("CWE-79".into()),
            evidence: serde_json::json!({"url": "http://test.com"}),
            poc: None,
            remediation: None,
            location: serde_json::json!({"url": "http://test.com/search"}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        };
        let json = serde_json::to_string(&finding).unwrap();
        let deser: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, finding.id);
        assert_eq!(deser.severity, finding.severity);
        assert_eq!(deser.vulnerability_class, finding.vulnerability_class);
        assert_eq!(deser.confidence, finding.confidence);
        assert_eq!(deser.title, finding.title);
    }

    #[test]
    fn test_target_creation() {
        let now = Utc::now();
        let target = Target {
            id: "target-1".into(),
            name: "test.exe".into(),
            target_type: TargetType::Process,
            path: Some("/usr/bin/test.exe".into()),
            url_str: None,
            pid: Some(12345),
            host: None,
            metadata: serde_json::json!({"platform": "windows"}),
            created_at: now,
            updated_at: now,
        };
        assert_eq!(target.target_type, TargetType::Process);
        assert_eq!(target.pid, Some(12345));
    }

    #[test]
    fn test_target_web_type() {
        let now = Utc::now();
        let target = Target {
            id: "web-1".into(),
            name: "example.com".into(),
            target_type: TargetType::Web,
            path: None,
            url_str: Some("https://example.com".into()),
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        };
        assert_eq!(target.target_type, TargetType::Web);
        assert_eq!(target.url_str, Some("https://example.com".into()));
    }

    #[test]
    fn test_target_binary_type() {
        let now = Utc::now();
        let target = Target {
            id: "bin-1".into(),
            name: "app.so".into(),
            target_type: TargetType::Binary,
            path: Some("/lib/app.so".into()),
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        };
        assert_eq!(target.target_type, TargetType::Binary);
        assert_eq!(target.path, Some("/lib/app.so".into()));
    }

    #[test]
    fn test_scan_session_defaults() {
        let now = Utc::now();
        let scan = ScanSession {
            id: "scan-1".into(),
            target_id: "target-1".into(),
            mode: ScanMode::Pipeline,
            config: serde_json::json!({"profile": "deep"}),
            status: ScanStatus::Pending,
            agent_model: None,
            started_at: None,
            completed_at: None,
            duration_ms: None,
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            metadata: serde_json::json!({}),
            created_at: now,
        };
        assert_eq!(scan.status, ScanStatus::Pending);
        assert_eq!(scan.total_findings, 0);
    }

    #[test]
    fn test_scan_session_with_counts() {
        let now = Utc::now();
        let scan = ScanSession {
            id: "scan-2".into(),
            target_id: "target-2".into(),
            mode: ScanMode::Swarm,
            config: serde_json::json!({}),
            status: ScanStatus::Completed,
            agent_model: Some("claude-sonnet-4-20250514".into()),
            started_at: Some(now),
            completed_at: Some(now),
            duration_ms: Some(12000),
            total_findings: 42,
            critical_count: 3,
            high_count: 7,
            medium_count: 12,
            low_count: 15,
            info_count: 5,
            metadata: serde_json::json!({}),
            created_at: now,
        };
        assert_eq!(scan.critical_count, 3);
        assert_eq!(scan.high_count, 7);
        assert_eq!(scan.medium_count, 12);
        assert_eq!(scan.low_count, 15);
        assert_eq!(scan.info_count, 5);
        assert_eq!(scan.total_findings, 42);
    }

    #[test]
    fn test_artifact_creation() {
        let now = Utc::now();
        let artifact = Artifact {
            id: "art-1".into(),
            scan_id: "scan-1".into(),
            finding_id: Some("finding-1".into()),
            artifact_type: "screenshot".into(),
            mime_type: Some("image/png".into()),
            filename: "crash.png".into(),
            size_bytes: Some(1024),
            content_path: Some("/tmp/crash.png".into()),
            metadata: serde_json::json!({}),
            created_at: now,
        };
        assert_eq!(artifact.artifact_type, "screenshot");
    }

    #[test]
    fn test_artifact_without_finding() {
        let now = Utc::now();
        let artifact = Artifact {
            id: "art-1".into(),
            scan_id: "scan-1".into(),
            finding_id: None,
            artifact_type: "memory_dump".into(),
            mime_type: None,
            filename: "dump.bin".into(),
            size_bytes: None,
            content_path: None,
            metadata: serde_json::json!({}),
            created_at: now,
        };
        assert!(artifact.finding_id.is_none());
    }

    #[test]
    fn test_scan_memory_entry() {
        let now = Utc::now();
        let entry = ScanMemoryEntry {
            id: "mem-1".into(),
            pattern_hash: "abc123hash".into(),
            pattern_type: PatternType::FalsePositive,
            target_hash: Some("target123hash".into()),
            description: "Common false positive in login forms".into(),
            evidence: serde_json::json!({"form": "/login"}),
            confidence: 0.95,
            occurrences: 5,
            created_at: now,
            updated_at: now,
        };
        assert_eq!(entry.pattern_type, PatternType::FalsePositive);
        assert_eq!(entry.occurrences, 5);
    }

    #[test]
    fn test_scan_memory_entry_no_target() {
        let now = Utc::now();
        let entry = ScanMemoryEntry {
            id: "mem-2".into(),
            pattern_hash: "def456hash".into(),
            pattern_type: PatternType::ConfirmedVuln,
            target_hash: None,
            description: "Identified vulnerability pattern".into(),
            evidence: serde_json::json!({"signature": "0xDEADBEEF"}),
            confidence: 0.99,
            occurrences: 1,
            created_at: now,
            updated_at: now,
        };
        assert!(entry.target_hash.is_none());
        assert_eq!(entry.confidence, 0.99);
    }

    #[test]
    fn test_agent_action() {
        let now = Utc::now();
        let action = AgentAction {
            id: "act-1".into(),
            scan_id: "scan-1".into(),
            sequence: 42,
            agent_role: "recon".into(),
            action_type: ToolCallType::ToolCall,
            action_data: serde_json::json!({"tool": "http_request", "url": "http://test.com"}),
            timestamp: now,
        };
        assert_eq!(action.sequence, 42);
        assert_eq!(action.agent_role, "recon");
    }

    #[test]
    fn test_agent_action_approval() {
        let now = Utc::now();
        let action = AgentAction {
            id: "act-2".into(),
            scan_id: "scan-1".into(),
            sequence: 100,
            agent_role: "exploit".into(),
            action_type: ToolCallType::ApprovalRequest,
            action_data: serde_json::json!({"action": "memory_write", "address": "0xCAFE"}),
            timestamp: now,
        };
        assert_eq!(action.action_type, ToolCallType::ApprovalRequest);
    }

    #[test]
    fn test_merge_strategy_display() {
        assert_eq!(MergeStrategy::Voting.to_string(), "voting");
        assert_eq!(MergeStrategy::Union.to_string(), "union");
        assert_eq!(MergeStrategy::Strict.to_string(), "strict");
    }

    #[test]
    fn test_merge_strategy_parse() {
        assert_eq!(
            "voting".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Voting
        );
        assert_eq!(
            "union".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Union
        );
        assert_eq!(
            "strict".parse::<MergeStrategy>().unwrap(),
            MergeStrategy::Strict
        );
    }

    #[test]
    fn test_merge_strategy_parse_invalid_fails() {
        assert!("Voting".parse::<MergeStrategy>().is_err());
        assert!("consensus".parse::<MergeStrategy>().is_err());
        assert!("".parse::<MergeStrategy>().is_err());
    }

    #[test]
    fn test_fallback_strategy_display() {
        assert_eq!(FallbackStrategy::NextOnFailure.to_string(), "next_on_failure");
        assert_eq!(
            FallbackStrategy::NextOnRateLimit.to_string(),
            "next_on_rate_limit"
        );
        assert_eq!(
            FallbackStrategy::TryAllParallel.to_string(),
            "try_all_parallel"
        );
    }

    #[test]
    fn test_fallback_strategy_parse() {
        assert_eq!(
            "next_on_failure".parse::<FallbackStrategy>().unwrap(),
            FallbackStrategy::NextOnFailure
        );
        assert_eq!(
            "next_on_rate_limit".parse::<FallbackStrategy>().unwrap(),
            FallbackStrategy::NextOnRateLimit
        );
        assert_eq!(
            "try_all_parallel".parse::<FallbackStrategy>().unwrap(),
            FallbackStrategy::TryAllParallel
        );
    }

    #[test]
    fn test_fallback_strategy_parse_invalid_fails() {
        assert!("NextOnFailure".parse::<FallbackStrategy>().is_err());
        assert!("none".parse::<FallbackStrategy>().is_err());
    }

    #[test]
    fn test_tool_call_type_display_and_parse() {
        assert_eq!(ToolCallType::ToolCall.to_string(), "tool_call");
        assert_eq!(ToolCallType::LlmResponse.to_string(), "llm_response");
        assert_eq!(ToolCallType::ApprovalRequest.to_string(), "approval_request");
        assert_eq!(
            ToolCallType::ApprovalResponse.to_string(),
            "approval_response"
        );
        assert_eq!(ToolCallType::Error.to_string(), "error");

        assert_eq!(
            "tool_call".parse::<ToolCallType>().unwrap(),
            ToolCallType::ToolCall
        );
        assert_eq!(
            "llm_response".parse::<ToolCallType>().unwrap(),
            ToolCallType::LlmResponse
        );
        assert_eq!(
            "error".parse::<ToolCallType>().unwrap(),
            ToolCallType::Error
        );
    }

    #[test]
    fn test_tool_call_type_parse_invalid() {
        assert!("ToolCall".parse::<ToolCallType>().is_err());
    }

    // Property-based and edge-case tests

    #[test]
    fn test_finding_json_roundtrip_100_random() {
        use rand::Rng;
        use uuid::Uuid;
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let finding = Finding {
                id: Uuid::new_v4().to_string(),
                scan_id: Uuid::new_v4().to_string(),
                target_id: Uuid::new_v4().to_string(),
                title: (0..rng.gen_range(0..500))
                    .map(|_| rng.gen::<char>())
                    .collect(),
                description: (0..rng.gen_range(0..2000))
                    .map(|_| rng.gen::<char>())
                    .collect(),
                vulnerability_class: VulnerabilityClass::Unknown,
                severity: Severity::Medium,
                confidence: rng.gen::<f64>() * 2.0 - 0.5,
                status: FindingStatus::Open,
                cvss_score: if rng.gen() {
                    Some(rng.gen_range(-5.0..15.0))
                } else {
                    None
                },
                cve_id: if rng.gen() {
                    Some(format!("CVE-{}", rng.gen::<u32>()))
                } else {
                    None
                },
                cwe_id: if rng.gen() {
                    Some(format!("CWE-{}", rng.gen::<u32>()))
                } else {
                    None
                },
                evidence: serde_json::json!({"random": rng.gen::<u64>()}),
                poc: if rng.gen() {
                    Some(fuzz_string(rng.gen_range(0..1000)))
                } else {
                    None
                },
                remediation: if rng.gen() {
                    Some(fuzz_string(rng.gen_range(0..1000)))
                } else {
                    None
                },
                location: serde_json::json!({"file": fuzz_string(20), "line": rng.gen::<u32>()}),
                false_positive_history: None,
                tags: (0..rng.gen_range(0..20))
                    .map(|_| fuzz_string(rng.gen_range(0..50)))
                    .collect(),
                metadata: serde_json::json!({"rng": rng.gen::<u64>()}),
                discovered_at: Utc::now(),
                updated_at: Utc::now(),
            };
            let json = serde_json::to_string(&finding).unwrap();
            let _: serde_json::Value = serde_json::from_str(&json).unwrap();
            let deser: Finding = serde_json::from_str(&json).unwrap();
            assert_eq!(deser.id, finding.id);
            assert_eq!(deser.title, finding.title);
        }
    }

    #[test]
    fn test_severity_parse_case_insensitive_should_fail() {
        assert!("CRITICAL".parse::<Severity>().is_err());
        assert!("Critical".parse::<Severity>().is_err());
        assert!("cRiTiCaL".parse::<Severity>().is_err());
        assert!(" critical ".parse::<Severity>().is_err());
    }

    #[test]
    fn test_severity_parse_empty_and_whitespace() {
        assert!("".parse::<Severity>().is_err());
        assert!(" ".parse::<Severity>().is_err());
        assert!("\n".parse::<Severity>().is_err());
        assert!("\t".parse::<Severity>().is_err());
    }

    #[test]
    fn test_vulnerability_class_all_variants_roundtrip_string() {
        let classes = [
            VulnerabilityClass::BufferOverflow,
            VulnerabilityClass::UseAfterFree,
            VulnerabilityClass::XSS,
            VulnerabilityClass::SQLInjection,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::SSTI,
            VulnerabilityClass::SSRF,
            VulnerabilityClass::Unknown,
            VulnerabilityClass::SpeedHack,
            VulnerabilityClass::WallHack,
            VulnerabilityClass::Aimbot,
            VulnerabilityClass::NoClip,
            VulnerabilityClass::InfiniteResources,
            VulnerabilityClass::SaveFileRCE,
            VulnerabilityClass::ProtocolExploit,
            VulnerabilityClass::AssetTheft,
            VulnerabilityClass::DRMBypass,
            VulnerabilityClass::EngineExploit,
            VulnerabilityClass::WebSocketTamper,
            VulnerabilityClass::ClientPredictionExploit,
        ];
        for cls in &classes {
            let s = cls.to_string();
            let parsed: VulnerabilityClass = s
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse '{}'", s));
            assert_eq!(parsed, *cls, "Roundtrip failed for {:?}", cls);
        }
    }

    #[test]
    fn test_finding_confidence_bounds() {
        fn make_finding(confidence: f64) -> Finding {
            Finding {
                id: uuid::Uuid::new_v4().to_string(),
                scan_id: "factory-scan".into(),
                target_id: "factory-target".into(),
                title: "Factory Finding".into(),
                description: "Generated by test factory".into(),
                vulnerability_class: VulnerabilityClass::Unknown,
                severity: Severity::Medium,
                confidence,
                status: FindingStatus::Open,
                cvss_score: None,
                cve_id: None,
                cwe_id: None,
                evidence: serde_json::json!({"factory": true}),
                poc: None,
                remediation: None,
                location: serde_json::json!({"factory": "test"}),
                false_positive_history: None,
                tags: vec!["factory".into()],
                metadata: serde_json::json!({}),
                discovered_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        let extreme_values = [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MIN,
            f64::MAX,
            -0.0,
            0.0,
            2.0,
            -1.0,
            1e308,
        ];
        for val in &extreme_values {
            let finding = make_finding(*val);
            let json = serde_json::to_string(&finding).unwrap();
            // NaN/Infinity serialize as null in JSON, so deserialization
            // to f64 will fail for those. Verify we don't panic and
            // that valid finite values roundtrip.
            if val.is_finite() {
                let deser: Finding = serde_json::from_str(&json).unwrap();
                assert_eq!(deser.confidence, *val);
            } else {
                // At least verify it serialized without panicking
                let _: serde_json::Value = serde_json::from_str(&json).unwrap();
            }
        }
    }

    #[test]
    fn test_target_unicode_strings() {
        let unicode_names: Vec<String> = vec![
            "日本語のゲーム.exe".to_string(),
            "🎮game🎯.exe".to_string(),
            "игра.exe".to_string(),
            "게임.exe".to_string(),
            "\u{1f600}\u{1f601}\u{1f602}".to_string(),
            "a".repeat(10000),
            "game\x00hidden.exe".to_string(),
        ];
        for name in &unicode_names {
            let target = Target {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.clone(),
                target_type: TargetType::Binary,
                path: Some(name.clone()),
                url_str: None,
                pid: None,
                host: None,
                metadata: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            let json = serde_json::to_string(&target).unwrap();
            let deser: Target = serde_json::from_str(&json).unwrap();
            assert_eq!(deser.name, *name);
        }
    }

    #[test]
    fn test_scan_session_all_statuses_roundtrip() {
        for status in &[
            ScanStatus::Pending,
            ScanStatus::Running,
            ScanStatus::Paused,
            ScanStatus::Completed,
            ScanStatus::Failed,
            ScanStatus::Cancelled,
        ] {
            let s = status.to_string();
            let parsed: ScanStatus = s.parse().unwrap();
            assert_eq!(parsed, *status);
        }
    }

    #[test]
    fn test_severity_ordering_consistency() {
        let sevs = [
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("info", Severity::Info),
        ];
        let mut prev = Severity::Critical;
        for (_name, current) in &sevs[1..] {
            let rank_prev = severity_rank(prev);
            let rank_curr = severity_rank(*current);
            assert!(rank_prev > rank_curr, "Expected {:?} > {:?}", prev, current);
            prev = *current;
        }
    }

    fn severity_rank(s: Severity) -> u8 {
        match s {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    fn fuzz_string(len: usize) -> String {
        use rand::Rng;
        (0..len).map(|_| rand::thread_rng().gen::<char>()).collect()
    }
}
