use thiserror::Error;
use vest_core::error::VestError;

/// Typed failure from [`crate::ToolRegistry`] authorise/execute paths.
///
/// Converts to [`VestError`] for CLI exit mapping. Policy / capability denials
/// become [`VestError::ApprovalDenied`] (exit 4). Handler-level failures
/// (missing parameter, IO, transport, egress) map to [`VestError::Agent`]
/// (exit 7, soft agent failure) — same CLI semantics as the old coarse
/// [`ToolError::Handler`] strings, but with typed categories (D2).
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Tool '{0}' not found")]
    NotFound(String),

    #[error("{0}")]
    ApprovalDenied(String),

    #[error("tool '{tool}' execution denied: {reason}")]
    CapabilityDenied { tool: String, reason: String },

    /// Required tool argument missing (model supplied an incomplete call).
    #[error("missing tool parameter: {0}")]
    MissingParameter(String),

    /// Referenced path does not exist on disk.
    #[error("path not found: {0}")]
    PathNotFound(String),

    /// Filesystem / IO failure inside a tool handler.
    #[error("tool IO error: {0}")]
    Io(String),

    /// Transport / client / serialization failure inside a tool handler.
    #[error("tool client error: {0}")]
    Client(String),

    /// Model-egress filter refused the tool result.
    #[error("tool result refused for model egress: {0}")]
    Egress(String),

    /// Opaque handler / helper failure — last resort only.
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

    pub fn missing_parameter(message: impl Into<String>) -> Self {
        Self::MissingParameter(message.into())
    }

    pub fn path_not_found(message: impl Into<String>) -> Self {
        Self::PathNotFound(message.into())
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::Io(message.into())
    }

    pub fn client(message: impl Into<String>) -> Self {
        Self::Client(message.into())
    }

    pub fn egress(message: impl Into<String>) -> Self {
        Self::Egress(message.into())
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
            ToolError::MissingParameter(message) => VestError::Agent(message),
            ToolError::PathNotFound(message) => VestError::Agent(message),
            ToolError::Io(message) => VestError::Agent(message),
            ToolError::Client(message) => VestError::Agent(message),
            ToolError::Egress(message) => VestError::Agent(message),
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

    #[test]
    fn typed_handler_categories_map_to_agent_exit_7() {
        for err in [
            ToolError::missing_parameter("url parameter required"),
            ToolError::path_not_found("Path not found: /tmp/x"),
            ToolError::io("Cannot read file: boom"),
            ToolError::client("web_scan failed: boom"),
            ToolError::egress("credential material must not egress"),
        ] {
            let vest: VestError = err.into();
            assert!(
                matches!(vest, VestError::Agent(_)),
                "typed tool failures stay agent-soft: {vest}"
            );
            assert_eq!(vest.cli_exit_code(), 7);
        }
    }
}
