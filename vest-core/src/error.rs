use thiserror::Error;

/// The unified error type for all VEST operations.
#[derive(Debug, Error)]
pub enum VestError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(feature = "toml")]
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Agent error: {0}")]
    Agent(String),

    #[error("Scan error: {0}")]
    Scan(String),

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Finding not found: {0}")]
    FindingNotFound(String),

    #[error("Approval denied: {0}")]
    ApprovalDenied(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Sandbox error: {0}")]
    Sandbox(String),

    #[error("Validation failed for finding {finding_id}: {}", reasons.join(", "))]
    ValidationFailed {
        finding_id: String,
        reasons: Vec<String>,
    },

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Unsupported: {0}")]
    Unsupported(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// CI / policy gate after a scan completed (severity threshold or new findings).
    #[error("Findings gate: {0}")]
    FindingsGate(String),
}

impl VestError {
    /// Stable CLI exit codes (see `vest-cli` exit_code module).
    ///
    /// Mapping is by typed variant — not by searching error message text.
    pub fn cli_exit_code(&self) -> i32 {
        match self {
            VestError::Config(_) => 3,
            #[cfg(feature = "toml")]
            VestError::Toml(_) => 3,
            VestError::ApprovalDenied(_) => 4,
            VestError::Scan(_) | VestError::Unsupported(_) | VestError::UnsupportedPlatform(_) => 5,
            VestError::Storage(_) => 6,
            VestError::Provider(_) => 7,
            VestError::FindingsGate(_) => 8,
            VestError::InvalidInput(_)
            | VestError::UnsupportedFormat(_)
            | VestError::TargetNotFound(_)
            | VestError::FindingNotFound(_) => 2,
            VestError::RateLimited(_) | VestError::Timeout(_) => 5,
            VestError::ValidationFailed { .. } | VestError::Agent(_) => 7,
            VestError::Sandbox(_)
            | VestError::Internal(_)
            | VestError::Io(_)
            | VestError::Json(_) => 1,
        }
    }

    /// Soft provider/agent failure for degraded scans (CLI exit 7).
    ///
    /// [`VestError::ApprovalDenied`] is preserved so authorisation stays exit 4.
    pub fn into_provider_soft_failure(self) -> Self {
        match self {
            VestError::Provider(_)
            | VestError::Agent(_)
            | VestError::ValidationFailed { .. }
            | VestError::ApprovalDenied(_) => self,
            other => VestError::Provider(format!(
                "provider/agent soft failure; scanner findings preserved: {other}"
            )),
        }
    }
}

#[cfg(test)]
mod exit_code_unit_tests {
    use super::*;

    #[test]
    fn typed_exit_codes() {
        assert_eq!(VestError::Config("x".into()).cli_exit_code(), 3);
        assert_eq!(VestError::ApprovalDenied("x".into()).cli_exit_code(), 4);
        assert_eq!(VestError::Scan("x".into()).cli_exit_code(), 5);
        assert_eq!(VestError::Storage("x".into()).cli_exit_code(), 6);
        assert_eq!(VestError::Provider("x".into()).cli_exit_code(), 7);
        assert_eq!(VestError::InvalidInput("x".into()).cli_exit_code(), 2);
        assert_eq!(VestError::FindingsGate("high".into()).cli_exit_code(), 8);
    }

    #[test]
    fn provider_soft_failure_preserves_approval_denied_exit_4() {
        let soft = VestError::ApprovalDenied("policy denied".into()).into_provider_soft_failure();
        assert!(matches!(soft, VestError::ApprovalDenied(_)));
        assert_eq!(soft.cli_exit_code(), 4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VestError::Internal("test error".into());
        assert_eq!(err.to_string(), "Internal error: test error");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let vest_err: VestError = io_err.into();
        assert!(matches!(vest_err, VestError::Io(_)));
        assert!(vest_err.to_string().contains("file not found"));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("not valid json").unwrap_err();
        let vest_err: VestError = json_err.into();
        assert!(matches!(vest_err, VestError::Json(_)));
    }

    #[test]
    fn test_error_validation_failed() {
        let err = VestError::ValidationFailed {
            finding_id: "finding-1".into(),
            reasons: vec!["No exploit possible".into(), "Behind auth guard".into()],
        };
        let display = err.to_string();
        assert!(display.contains("finding-1"));
        assert!(display.contains("No exploit possible"));
        assert!(display.contains("Behind auth guard"));
    }

    #[test]
    fn test_validation_failed_empty_reasons() {
        let err = VestError::ValidationFailed {
            finding_id: "finding-2".into(),
            reasons: vec![],
        };
        let display = err.to_string();
        assert!(display.contains("finding-2"));
    }

    #[test]
    fn test_storage_error() {
        let err = VestError::Storage("connection refused".into());
        assert_eq!(err.to_string(), "Storage error: connection refused");
    }

    #[test]
    fn test_config_error() {
        let err = VestError::Config("missing required field".into());
        assert_eq!(err.to_string(), "Config error: missing required field");
    }

    #[test]
    fn test_provider_error() {
        let err = VestError::Provider("rate limited".into());
        assert_eq!(err.to_string(), "Provider error: rate limited");
    }

    #[test]
    fn test_agent_error() {
        let err = VestError::Agent("model not available".into());
        assert_eq!(err.to_string(), "Agent error: model not available");
    }

    #[test]
    fn test_scan_error() {
        let err = VestError::Scan("target unreachable".into());
        assert_eq!(err.to_string(), "Scan error: target unreachable");
    }

    #[test]
    fn test_target_not_found() {
        let err = VestError::TargetNotFound("target-123".into());
        assert_eq!(err.to_string(), "Target not found: target-123");
    }

    #[test]
    fn test_finding_not_found() {
        let err = VestError::FindingNotFound("finding-456".into());
        assert_eq!(err.to_string(), "Finding not found: finding-456");
    }

    #[test]
    fn test_approval_denied() {
        let err = VestError::ApprovalDenied("memory write".into());
        assert!(err.to_string().contains("memory write"));
    }

    #[test]
    fn test_rate_limited() {
        let err = VestError::RateLimited("too many requests".into());
        assert!(err.to_string().contains("too many requests"));
    }

    #[test]
    fn test_timeout() {
        let err = VestError::Timeout("operation timed out after 30s".into());
        assert!(err.to_string().contains("operation timed out after 30s"));
    }

    #[test]
    fn test_sandbox_error() {
        let err = VestError::Sandbox("seccomp violation".into());
        assert_eq!(err.to_string(), "Sandbox error: seccomp violation");
    }

    #[test]
    fn test_unsupported_platform() {
        let err = VestError::UnsupportedPlatform("arm-linux".into());
        assert_eq!(err.to_string(), "Unsupported platform: arm-linux");
    }

    #[test]
    fn test_unsupported_format() {
        let err = VestError::UnsupportedFormat("pdf".into());
        assert_eq!(err.to_string(), "Unsupported format: pdf");
    }

    #[test]
    fn test_unsupported() {
        let err = VestError::Unsupported("feature not implemented".into());
        assert_eq!(err.to_string(), "Unsupported: feature not implemented");
    }

    #[test]
    fn test_internal_error() {
        let err = VestError::Internal("unexpected null pointer".into());
        assert_eq!(err.to_string(), "Internal error: unexpected null pointer");
    }

    #[test]
    fn test_error_debug_format() {
        let err = VestError::Internal("foo".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Internal"));
        assert!(debug.contains("foo"));
    }

    #[test]
    fn test_vest_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VestError>();
    }

    #[test]
    fn test_error_size_not_too_large() {
        let size = std::mem::size_of::<VestError>();
        assert!(size <= 128, "VestError is {} bytes, too large", size);
    }

    #[test]
    fn test_from_io_error_roundtrip() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let vest: VestError = io.into();
        let msg = vest.to_string();
        assert!(msg.contains("Permission") || msg.contains("denied") || msg.contains("IO error"));
    }

    #[test]
    fn test_from_json_error_roundtrip() {
        let json = serde_json::from_str::<serde_json::Value>("{invalid").unwrap_err();
        let vest: VestError = json.into();
        assert!(vest.to_string().contains("JSON"));
    }

    #[test]
    fn test_validation_failed_with_many_reasons() {
        let reasons: Vec<String> = (0..100).map(|i| format!("reason {}", i)).collect();
        let err = VestError::ValidationFailed {
            finding_id: "test".into(),
            reasons,
        };
        let msg = err.to_string();
        assert!(msg.contains("test"));
        assert!(msg.contains("reason 0"));
        assert!(msg.contains("reason 99"));
    }

    #[test]
    fn test_error_debug_vs_display() {
        let err = VestError::TargetNotFound("t1".into());
        let display = format!("{}", err);
        let debug = format!("{:?}", err);
        assert!(display.contains("Target not found"));
        assert!(debug.contains("TargetNotFound"));
    }
}
