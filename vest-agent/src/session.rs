//! Per-run execution session — immutable authority for one scan/command.
//!
//! Replaces process-global filesystem/network scope mutation. Tools capture
//! `Arc<ExecutionSession>` so concurrent sessions cannot overwrite each other.

use crate::fs_scope::ApprovedFilesystemScope;
use crate::net_scope::ApprovedNetworkScope;
use crate::policy::AuthorisationContext;
use std::sync::Arc;
use vest_core::ids::new_id;

/// Immutable, per-run authority and options for scanners and agent tools.
#[derive(Debug, Clone)]
pub struct ExecutionSession {
    pub id: String,
    pub filesystem: ApprovedFilesystemScope,
    pub network: ApprovedNetworkScope,
    pub interactive: bool,
    pub allow_memory_simulation: bool,
    pub allow_local_content_egress: bool,
    pub allow_process_memory_egress: bool,
    pub allow_target_content_egress: bool,
    pub allow_potentially_secret_bearing_egress: bool,
    pub allow_evidence_egress: bool,
    /// When true, auto-allow effects that pass scope checks (tests only).
    pub permissive_effects: bool,
}

impl ExecutionSession {
    pub fn new(
        filesystem: ApprovedFilesystemScope,
        network: ApprovedNetworkScope,
        interactive: bool,
    ) -> Self {
        Self {
            id: new_id(),
            filesystem,
            network,
            interactive,
            allow_memory_simulation: false,
            allow_local_content_egress: false,
            allow_process_memory_egress: false,
            allow_target_content_egress: false,
            allow_potentially_secret_bearing_egress: false,
            allow_evidence_egress: false,
            permissive_effects: false,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn with_memory_simulation(mut self, allow: bool) -> Self {
        self.allow_memory_simulation = allow;
        self
    }

    pub fn with_egress(
        mut self,
        local_content: bool,
        process_memory: bool,
        evidence: bool,
    ) -> Self {
        self.allow_local_content_egress = local_content;
        self.allow_process_memory_egress = process_memory;
        self.allow_evidence_egress = evidence;
        self
    }

    pub fn with_target_content_egress(mut self, allow: bool) -> Self {
        self.allow_target_content_egress = allow;
        self
    }

    pub fn with_potentially_secret_bearing_egress(mut self, allow: bool) -> Self {
        self.allow_potentially_secret_bearing_egress = allow;
        self
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Build an [`AuthorisationContext`] bound to this session's id and scopes.
    pub fn authorisation_context(&self) -> AuthorisationContext {
        let mut auth = AuthorisationContext::new(self.id.clone())
            .with_filesystem(self.filesystem.clone())
            .with_network(self.network.clone())
            .with_interactive(self.interactive);
        auth.allow_local_content_egress = self.allow_local_content_egress;
        auth.allow_process_memory_egress = self.allow_process_memory_egress;
        auth.allow_target_content_egress = self.allow_target_content_egress;
        auth.allow_potentially_secret_bearing_egress = self.allow_potentially_secret_bearing_egress;
        auth.allow_evidence_egress = self.allow_evidence_egress;
        auth.permissive_effects = self.permissive_effects;
        auth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn concurrent_sessions_keep_distinct_roots() {
        let a_dir = std::env::temp_dir().join(format!("vest-sess-a-{}", std::process::id()));
        let b_dir = std::env::temp_dir().join(format!("vest-sess-b-{}", std::process::id()));
        std::fs::create_dir_all(&a_dir).unwrap();
        std::fs::create_dir_all(&b_dir).unwrap();

        let a = ExecutionSession::new(
            ApprovedFilesystemScope::new([a_dir.clone()]).unwrap(),
            ApprovedNetworkScope::empty(),
            false,
        )
        .with_id("session-a")
        .into_arc();
        let b = ExecutionSession::new(
            ApprovedFilesystemScope::new([b_dir.clone()]).unwrap(),
            ApprovedNetworkScope::empty(),
            false,
        )
        .with_id("session-b")
        .into_arc();

        let a2 = Arc::clone(&a);
        let b2 = Arc::clone(&b);
        let t1 = std::thread::spawn(move || a2.filesystem.roots().to_vec());
        let t2 = std::thread::spawn(move || b2.filesystem.roots().to_vec());
        let ra = t1.join().unwrap();
        let rb = t2.join().unwrap();
        assert_ne!(ra, rb);
        assert_eq!(a.id, "session-a");
        assert_eq!(b.id, "session-b");
        assert_ne!(
            a.authorisation_context().session_id,
            b.authorisation_context().session_id
        );
    }
}
