use thiserror::Error;
use vest_core::error::VestError;

/// Typed failure from [`crate::ToolRegistry`] authorise/execute paths.
///
/// Converts to [`VestError`] for CLI exit mapping. Policy / capability denials
/// become [`VestError::ApprovalDenied`] (exit 4). Handler bodies may still use
/// coarse [`ToolError::Handler`] strings — retiring those is residual work.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Tool '{0}' not found")]
    NotFound(String),

    #[error("{0}")]
    ApprovalDenied(String),

    #[error("tool '{tool}' execution denied: {reason}")]
    CapabilityDenied { tool: String, reason: String },

    /// Opaque handler / helper failure (still stringly in many tool bodies).
    #[error("{0}")]
    Handler(String),

    #[error(transparent)]
    Vest(#[from] VestError),
}

impl ToolError {
    pub fn approval_denied(message: impl Into<String>) -> Self {
        Self::ApprovalDenied(message.into())
    }

    pub fn capability_denied(tool: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CapabilityDenied {
            tool: tool.into(),
            reason: reason.into(),
        }
    }

    pub fn handler(message: impl Into<String>) -> Self {
        Self::Handler(message.into())
    }
}

impl From<String> for ToolError {
    fn from(value: String) -> Self {
        Self::Handler(value)
    }
}

impl From<&str> for ToolError {
    fn from(value: &str) -> Self {
        Self::Handler(value.to_string())
    }
}

impl From<ToolError> for VestError {
    fn from(err: ToolError) -> Self {
        match err {
            ToolError::ApprovalDenied(reason) => VestError::ApprovalDenied(reason),
            ToolError::CapabilityDenied { tool, reason } => {
                VestError::ApprovalDenied(format!("tool '{tool}' execution denied: {reason}"))
            }
            ToolError::NotFound(name) => VestError::Agent(format!("Tool '{name}' not found")),
            ToolError::Handler(message) => VestError::Agent(message),
            ToolError::Vest(vest) => vest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_denied_maps_to_exit_4() {
        let vest: VestError = ToolError::approval_denied("nope").into();
        assert!(matches!(vest, VestError::ApprovalDenied(_)));
        assert_eq!(vest.cli_exit_code(), 4);
    }

    #[test]
    fn capability_denied_maps_to_exit_4() {
        let vest: VestError =
            ToolError::capability_denied("http_get", "one-shot capability already consumed").into();
        assert!(matches!(vest, VestError::ApprovalDenied(_)));
        assert_eq!(vest.cli_exit_code(), 4);
    }

    #[test]
    fn preserves_nested_vest_approval_denied() {
        let vest: VestError =
            ToolError::from(VestError::ApprovalDenied("network scope".into())).into();
        assert_eq!(vest.cli_exit_code(), 4);
    }

    #[test]
    fn handler_string_becomes_agent_exit_7() {
        let vest: VestError = ToolError::handler("web_scan failed: boom").into();
        assert!(matches!(vest, VestError::Agent(_)));
        assert_eq!(vest.cli_exit_code(), 7);
    }
}
