//! Opaque approved-tool-call capability (K5).
//!
//! Callers outside this module cannot forge an approval: fields are private and
//! only [`crate::policy::PolicyEngine`] mints capabilities after a successful
//! evaluation or matching grant.

use crate::policy::NormalisedToolCall;
use std::sync::atomic::{AtomicBool, Ordering};
use vest_core::{DataEgressClass, ToolEffect};

/// Opaque, non-forgeable proof that a specific normalised call was authorised.
pub struct ApprovedToolCall {
    session_id: String,
    tool_id: String,
    effect: ToolEffect,
    egress_class: DataEgressClass,
    normalised_target: String,
    arg_digest: [u8; 32],
    one_shot: bool,
    consumed: AtomicBool,
}

impl ApprovedToolCall {
    /// Package-private constructor — only policy code should call this.
    pub(crate) fn mint(
        session_id: impl Into<String>,
        call: &NormalisedToolCall,
        one_shot: bool,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            tool_id: call.tool_id.clone(),
            effect: call.effect,
            egress_class: call.egress_class,
            normalised_target: call.normalised_target.clone(),
            arg_digest: call.arg_digest,
            one_shot,
            consumed: AtomicBool::new(false),
        }
    }

    pub fn tool_id(&self) -> &str {
        &self.tool_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn effect(&self) -> ToolEffect {
        self.effect
    }

    pub fn matches_call(&self, call: &NormalisedToolCall, session_id: &str) -> bool {
        self.session_id == session_id
            && self.tool_id == call.tool_id
            && self.effect == call.effect
            && self.egress_class == call.egress_class
            && self.normalised_target == call.normalised_target
            && self.arg_digest == call.arg_digest
    }

    /// Consume a one-shot capability. Returns false if already used.
    pub fn consume(&self) -> bool {
        if !self.one_shot {
            return true;
        }
        !self.consumed.swap(true, Ordering::SeqCst)
    }
}

impl std::fmt::Debug for ApprovedToolCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedToolCall")
            .field("session_id", &self.session_id)
            .field("tool_id", &self.tool_id)
            .field("effect", &self.effect)
            .field("egress_class", &self.egress_class)
            .field("normalised_target", &self.normalised_target)
            .field("arg_digest", &"[REDACTED]")
            .field("one_shot", &self.one_shot)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vest_core::DataEgressClass;

    #[test]
    fn one_shot_consumed_once() {
        let call = NormalisedToolCall::from_parts(
            "read_file",
            ToolEffect::LocalFileContentRead,
            DataEgressClass::LocalContent,
            &serde_json::json!({"path": "/tmp/a"}),
        );
        let cap = ApprovedToolCall::mint("s1", &call, true);
        assert!(cap.consume());
        assert!(!cap.consume());
    }

    #[test]
    fn debug_redacts_digest() {
        let call = NormalisedToolCall::from_parts(
            "t",
            ToolEffect::PureComputation,
            DataEgressClass::PublicNonSensitive,
            &serde_json::json!({}),
        );
        let cap = ApprovedToolCall::mint("s", &call, false);
        let s = format!("{cap:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains(&format!("{:x}", call.arg_digest[0])));
    }
}
