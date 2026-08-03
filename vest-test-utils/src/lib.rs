pub mod chaos;
pub mod factories;
pub mod fuzzer;
pub mod property;

pub use chaos::*;
pub use factories::*;
pub use fuzzer::*;
pub use property::*;

/// Re-exports of test-only permissive auth helpers (POL-2).
///
/// Production builds of `vest-agent` omit these constructors unless the
/// `test-utils` feature is enabled.
pub mod auth {
    pub use vest_agent::{
        ApprovedFilesystemScope, ApprovedNetworkScope, AuthorisationContext, SafetyChecker,
    };

    pub fn permissive_auth(session_id: impl Into<String>) -> AuthorisationContext {
        AuthorisationContext::permissive_for_tests(session_id)
    }

    pub fn permissive_safety() -> SafetyChecker {
        SafetyChecker::permissive()
    }

    pub fn unrestricted_fs() -> ApprovedFilesystemScope {
        ApprovedFilesystemScope::unrestricted()
    }

    pub fn unrestricted_net() -> ApprovedNetworkScope {
        ApprovedNetworkScope::unrestricted()
    }
}
