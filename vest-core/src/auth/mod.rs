//! Central authorisation and egress classification types.
//!
//! Model output is untrusted data. It does not grant authority.
//! These types describe effects and data classes; policy enforcement lives
//! in `vest-agent` and CLI wiring.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Real effect of a tool invocation (not inferred from tool-name substrings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    PureComputation,
    LocalMetadataRead,
    LocalFileContentRead,
    LocalWrite,
    NetworkMetadataRead,
    PassiveNetworkRequest,
    ActiveNetworkProbe,
    StateChangingNetworkRequest,
    ProcessMetadataRead,
    ProcessMemoryRead,
    CommandExecution,
    CredentialAccess,
    Unknown,
}

impl ToolEffect {
    /// Whether this effect may mutate remote or local state.
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            ToolEffect::LocalWrite
                | ToolEffect::StateChangingNetworkRequest
                | ToolEffect::CommandExecution
                | ToolEffect::ActiveNetworkProbe
        )
    }

    /// Whether this effect touches the network.
    pub fn is_network(self) -> bool {
        matches!(
            self,
            ToolEffect::NetworkMetadataRead
                | ToolEffect::PassiveNetworkRequest
                | ToolEffect::ActiveNetworkProbe
                | ToolEffect::StateChangingNetworkRequest
        )
    }

    /// Whether this effect reads local file contents.
    pub fn reads_local_content(self) -> bool {
        matches!(self, ToolEffect::LocalFileContentRead)
    }

    /// Fail-closed: Unknown is never auto-allowed.
    pub fn is_unknown(self) -> bool {
        matches!(self, ToolEffect::Unknown)
    }

    /// Partial order: stronger effects are not implied by weaker ones.
    pub fn strength_rank(self) -> u8 {
        match self {
            ToolEffect::PureComputation => 0,
            ToolEffect::LocalMetadataRead | ToolEffect::NetworkMetadataRead => 1,
            ToolEffect::ProcessMetadataRead => 2,
            ToolEffect::PassiveNetworkRequest => 3,
            ToolEffect::LocalFileContentRead => 4,
            ToolEffect::ProcessMemoryRead => 5,
            ToolEffect::ActiveNetworkProbe => 6,
            ToolEffect::StateChangingNetworkRequest => 7,
            ToolEffect::LocalWrite | ToolEffect::CommandExecution => 8,
            ToolEffect::CredentialAccess => 9,
            ToolEffect::Unknown => 255,
        }
    }

    /// True if `self` is strictly stronger than `other` (approval of other must not imply self).
    pub fn is_stronger_than(self, other: Self) -> bool {
        self.strength_rank() > other.strength_rank()
    }
}

impl fmt::Display for ToolEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ToolEffect::PureComputation => "pure_computation",
            ToolEffect::LocalMetadataRead => "local_metadata_read",
            ToolEffect::LocalFileContentRead => "local_file_content_read",
            ToolEffect::LocalWrite => "local_write",
            ToolEffect::NetworkMetadataRead => "network_metadata_read",
            ToolEffect::PassiveNetworkRequest => "passive_network_request",
            ToolEffect::ActiveNetworkProbe => "active_network_probe",
            ToolEffect::StateChangingNetworkRequest => "state_changing_network_request",
            ToolEffect::ProcessMetadataRead => "process_metadata_read",
            ToolEffect::ProcessMemoryRead => "process_memory_read",
            ToolEffect::CommandExecution => "command_execution",
            ToolEffect::CredentialAccess => "credential_access",
            ToolEffect::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for ToolEffect {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pure_computation" => Ok(ToolEffect::PureComputation),
            "local_metadata_read" => Ok(ToolEffect::LocalMetadataRead),
            "local_file_content_read" => Ok(ToolEffect::LocalFileContentRead),
            "local_write" => Ok(ToolEffect::LocalWrite),
            "network_metadata_read" => Ok(ToolEffect::NetworkMetadataRead),
            "passive_network_request" => Ok(ToolEffect::PassiveNetworkRequest),
            "active_network_probe" => Ok(ToolEffect::ActiveNetworkProbe),
            "state_changing_network_request" => Ok(ToolEffect::StateChangingNetworkRequest),
            "process_metadata_read" => Ok(ToolEffect::ProcessMetadataRead),
            "process_memory_read" => Ok(ToolEffect::ProcessMemoryRead),
            "command_execution" => Ok(ToolEffect::CommandExecution),
            "credential_access" => Ok(ToolEffect::CredentialAccess),
            "unknown" => Ok(ToolEffect::Unknown),
            other => Err(format!(
                "unknown tool effect '{other}' (expected snake_case ToolEffect name)"
            )),
        }
    }
}

/// Classification of data that may leave the process toward a model or remote party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataEgressClass {
    PublicNonSensitive,
    UserAuthored,
    LocalMetadata,
    LocalContent,
    TargetMetadata,
    TargetContent,
    PotentiallySecretBearing,
    CredentialMaterial,
    ProcessMemory,
    Prohibited,
}

impl DataEgressClass {
    pub fn requires_explicit_egress_approval(self) -> bool {
        matches!(
            self,
            DataEgressClass::LocalContent
                | DataEgressClass::TargetContent
                | DataEgressClass::PotentiallySecretBearing
                | DataEgressClass::CredentialMaterial
                | DataEgressClass::ProcessMemory
                | DataEgressClass::Prohibited
        )
    }

    pub fn is_prohibited(self) -> bool {
        matches!(
            self,
            DataEgressClass::Prohibited | DataEgressClass::CredentialMaterial
        )
    }
}

/// Outcome of a policy evaluation (safe to log; contains no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Allow,
    Deny { reason: String },
    RequireInteractive { reason: String },
}

impl ApprovalDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, ApprovalDecision::Allow)
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        ApprovalDecision::Deny {
            reason: reason.into(),
        }
    }

    pub fn require_interactive(reason: impl Into<String>) -> Self {
        ApprovalDecision::RequireInteractive {
            reason: reason.into(),
        }
    }
}

/// Normalised HTTP method for effect classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethodKind {
    Get,
    Head,
    Options,
    Post,
    Put,
    Patch,
    Delete,
    Other,
}

impl HttpMethodKind {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_uppercase().as_str() {
            "GET" => HttpMethodKind::Get,
            "HEAD" => HttpMethodKind::Head,
            "OPTIONS" => HttpMethodKind::Options,
            "POST" => HttpMethodKind::Post,
            "PUT" => HttpMethodKind::Put,
            "PATCH" => HttpMethodKind::Patch,
            "DELETE" => HttpMethodKind::Delete,
            _ => HttpMethodKind::Other,
        }
    }

    pub fn is_state_changing(self) -> bool {
        matches!(
            self,
            HttpMethodKind::Post
                | HttpMethodKind::Put
                | HttpMethodKind::Patch
                | HttpMethodKind::Delete
                | HttpMethodKind::Other
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_effect_is_strongest_unknown() {
        assert!(ToolEffect::Unknown.is_unknown());
        assert!(ToolEffect::Unknown.is_stronger_than(ToolEffect::PureComputation));
    }

    #[test]
    fn post_stronger_than_get_passive() {
        assert!(ToolEffect::StateChangingNetworkRequest
            .is_stronger_than(ToolEffect::PassiveNetworkRequest));
    }

    #[test]
    fn memory_stronger_than_process_metadata() {
        assert!(ToolEffect::ProcessMemoryRead.is_stronger_than(ToolEffect::ProcessMetadataRead));
    }

    #[test]
    fn http_method_post_is_state_changing() {
        assert!(HttpMethodKind::parse("post").is_state_changing());
        assert!(!HttpMethodKind::parse("GET").is_state_changing());
    }

    #[test]
    fn egress_local_content_requires_approval() {
        assert!(DataEgressClass::LocalContent.requires_explicit_egress_approval());
        assert!(DataEgressClass::ProcessMemory.requires_explicit_egress_approval());
        assert!(!DataEgressClass::LocalMetadata.requires_explicit_egress_approval());
    }

    #[test]
    fn tool_effect_from_str_roundtrips_display() {
        for effect in [
            ToolEffect::LocalWrite,
            ToolEffect::LocalFileContentRead,
            ToolEffect::ActiveNetworkProbe,
            ToolEffect::CommandExecution,
        ] {
            let parsed: ToolEffect = effect.to_string().parse().unwrap();
            assert_eq!(parsed, effect);
        }
        assert!("not_an_effect".parse::<ToolEffect>().is_err());
    }
}
