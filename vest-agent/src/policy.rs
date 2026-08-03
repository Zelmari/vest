//! Central tool authorisation policy.
//!
//! Model output is untrusted. Every tool invocation must pass through
//! [`PolicyEngine::evaluate`] before execution. Registry `requires_approval`
//! is never a bypass.

use crate::fs_scope::{resolve_read_path, ApprovedFilesystemScope};
use crate::net_scope::ApprovedNetworkScope;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use vest_core::auth::{ApprovalDecision, DataEgressClass, HttpMethodKind, ToolEffect};

/// Session-scoped authorisation derived from explicit user intent.
#[derive(Debug, Clone)]
pub struct AuthorisationContext {
    pub session_id: String,
    pub filesystem: ApprovedFilesystemScope,
    pub network: ApprovedNetworkScope,
    pub interactive: bool,
    pub allow_local_content_egress: bool,
    pub allow_process_memory_egress: bool,
    pub allow_evidence_egress: bool,
    /// Test/escape hatch: auto-allow effects that pass scope checks.
    pub permissive_effects: bool,
    pub known_secrets: Vec<String>,
}

impl AuthorisationContext {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            filesystem: ApprovedFilesystemScope::empty(),
            network: ApprovedNetworkScope::empty(),
            interactive: false,
            allow_local_content_egress: false,
            allow_process_memory_egress: false,
            allow_evidence_egress: false,
            permissive_effects: false,
            known_secrets: Vec::new(),
        }
    }

    /// Test-only: unrestricted scopes + permissive effects. Unknown effects still deny.
    pub fn permissive_for_tests(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            filesystem: ApprovedFilesystemScope::unrestricted(),
            network: ApprovedNetworkScope::unrestricted(),
            interactive: true,
            allow_local_content_egress: true,
            allow_process_memory_egress: false,
            allow_evidence_egress: false,
            permissive_effects: true,
            known_secrets: Vec::new(),
        }
    }

    /// Alias for [`Self::permissive_for_tests`] with a fixed session id.
    pub fn permissive() -> Self {
        Self::permissive_for_tests("permissive")
    }

    pub fn with_filesystem(mut self, fs: ApprovedFilesystemScope) -> Self {
        self.filesystem = fs;
        self
    }

    pub fn with_network(mut self, net: ApprovedNetworkScope) -> Self {
        self.network = net;
        self
    }

    pub fn with_interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }
}

/// Normalised tool call after argument inspection.
#[derive(Debug, Clone)]
pub struct NormalisedToolCall {
    pub tool_id: String,
    pub effect: ToolEffect,
    pub egress_class: DataEgressClass,
    pub normalised_target: String,
    /// SHA-256 of canonical JSON for all arguments (not a subset).
    pub arg_digest: [u8; 32],
    pub path: Option<String>,
    pub url: Option<String>,
    pub http_method: Option<HttpMethodKind>,
    pub pid: Option<u32>,
    pub material_args: Value,
}

impl NormalisedToolCall {
    pub fn from_parts(
        tool_id: impl Into<String>,
        effect: ToolEffect,
        egress_class: DataEgressClass,
        args: &Value,
    ) -> Self {
        let tool_id = tool_id.into();
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let http_method = match args.get("method").and_then(|v| v.as_str()) {
            Some(m) => Some(HttpMethodKind::parse(m)),
            None => match effect {
                ToolEffect::StateChangingNetworkRequest => Some(HttpMethodKind::Post),
                ToolEffect::PassiveNetworkRequest => Some(HttpMethodKind::Get),
                _ => None,
            },
        };
        let pid = args.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32);

        let mut effect = effect;
        if let Some(method) = http_method {
            if method.is_state_changing()
                && matches!(
                    effect,
                    ToolEffect::PassiveNetworkRequest | ToolEffect::NetworkMetadataRead
                )
            {
                effect = ToolEffect::StateChangingNetworkRequest;
            }
        }

        let normalised_target = url
            .clone()
            .or_else(|| path.clone())
            .or_else(|| pid.map(|p| format!("pid:{p}")))
            .unwrap_or_else(|| format!("tool:{tool_id}"));

        let material_args = canonical_args(args);
        let arg_digest = digest_sha256(&material_args);

        Self {
            tool_id,
            effect,
            egress_class,
            normalised_target,
            arg_digest,
            path,
            url,
            http_method,
            pid,
            material_args,
        }
    }
}

/// Canonical JSON value for digesting: object keys sorted recursively.
fn canonical_args(args: &Value) -> Value {
    match args {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical_args(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_args).collect()),
        other => other.clone(),
    }
}

fn digest_sha256(value: &Value) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Scoped approval that does not grant stronger effects or other targets.
#[derive(Clone)]
pub struct ApprovalToken {
    pub tool_id: String,
    pub effect: ToolEffect,
    pub normalised_target: String,
    pub arg_digest: [u8; 32],
    pub session_id: String,
    pub expires_at: Instant,
    pub one_shot: bool,
}

impl std::fmt::Debug for ApprovalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalToken")
            .field("tool_id", &self.tool_id)
            .field("effect", &self.effect)
            .field("normalised_target", &self.normalised_target)
            .field("arg_digest", &"[REDACTED]")
            .field("session_id", &self.session_id)
            .field("one_shot", &self.one_shot)
            .finish()
    }
}

impl ApprovalToken {
    pub fn matches(&self, call: &NormalisedToolCall, session_id: &str) -> bool {
        self.session_id == session_id
            && self.tool_id == call.tool_id
            && self.effect == call.effect
            && self.normalised_target == call.normalised_target
            && self.arg_digest == call.arg_digest
            && Instant::now() < self.expires_at
    }

    pub fn cache_key(&self) -> String {
        let digest_hex: String = self.arg_digest.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "{}|{}|{}|{}|{}",
            self.tool_id, self.effect, self.normalised_target, digest_hex, self.session_id
        )
    }
}

pub struct PolicyEngine {
    approvals: RwLock<HashMap<String, ApprovalToken>>,
    default_ttl: Duration,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            approvals: RwLock::new(HashMap::new()),
            default_ttl: Duration::from_secs(300),
        }
    }

    pub fn evaluate(
        &self,
        ctx: &AuthorisationContext,
        call: &NormalisedToolCall,
    ) -> ApprovalDecision {
        if call.tool_id.trim().is_empty() {
            return ApprovalDecision::deny("empty tool id");
        }
        if call.effect.is_unknown() {
            return ApprovalDecision::deny("unknown tool effect (fail closed)");
        }

        if let Some(path) = &call.path {
            if call.effect.reads_local_content()
                || matches!(
                    call.effect,
                    ToolEffect::LocalMetadataRead | ToolEffect::LocalWrite
                )
            {
                if let Err(e) = resolve_read_path(&ctx.filesystem, path) {
                    return ApprovalDecision::deny(format!("filesystem scope: {e}"));
                }
            }
        }

        if let Some(url) = &call.url {
            if call.effect.is_network() {
                if let Err(e) = ctx.network.authorise_url(url) {
                    return ApprovalDecision::deny(format!("network scope: {e}"));
                }
            }
        }

        if let Some(token) = self.find_matching_token(ctx, call) {
            if token.one_shot {
                if let Ok(mut guard) = self.approvals.try_write() {
                    guard.remove(&token.cache_key());
                }
            }
            return ApprovalDecision::Allow;
        }

        if ctx.permissive_effects {
            return ApprovalDecision::Allow;
        }

        let needs_interactive = matches!(
            call.effect,
            ToolEffect::LocalWrite
                | ToolEffect::LocalFileContentRead
                | ToolEffect::StateChangingNetworkRequest
                | ToolEffect::ActiveNetworkProbe
                | ToolEffect::ProcessMemoryRead
                | ToolEffect::CommandExecution
                | ToolEffect::CredentialAccess
        );

        if needs_interactive {
            if ctx.interactive {
                return ApprovalDecision::require_interactive(format!(
                    "effect {} requires interactive approval for target {}",
                    call.effect, call.normalised_target
                ));
            }
            return ApprovalDecision::deny(format!(
                "effect {} requires approval; non-interactive mode fails closed",
                call.effect
            ));
        }

        match call.effect {
            ToolEffect::PureComputation
            | ToolEffect::LocalMetadataRead
            | ToolEffect::NetworkMetadataRead
            | ToolEffect::PassiveNetworkRequest
            | ToolEffect::ProcessMetadataRead => ApprovalDecision::Allow,
            _ => ApprovalDecision::deny(format!("effect {} not auto-allowed", call.effect)),
        }
    }

    fn find_matching_token(
        &self,
        ctx: &AuthorisationContext,
        call: &NormalisedToolCall,
    ) -> Option<ApprovalToken> {
        let guard = self.approvals.try_read().ok()?;
        guard
            .values()
            .find(|t| t.matches(call, &ctx.session_id))
            .cloned()
    }

    pub async fn grant(
        &self,
        ctx: &AuthorisationContext,
        call: &NormalisedToolCall,
        one_shot: bool,
    ) {
        let token = ApprovalToken {
            tool_id: call.tool_id.clone(),
            effect: call.effect,
            normalised_target: call.normalised_target.clone(),
            arg_digest: call.arg_digest,
            session_id: ctx.session_id.clone(),
            expires_at: Instant::now() + self.default_ttl,
            one_shot,
        };
        let key = token.cache_key();
        self.approvals.write().await.insert(key, token);
    }

    pub async fn clear(&self) {
        self.approvals.write().await.clear();
    }

    /// Evaluate policy and, if allowed, mint an opaque [`ApprovedToolCall`].
    pub fn authorise(
        &self,
        ctx: &AuthorisationContext,
        call: &NormalisedToolCall,
    ) -> Result<crate::approved::ApprovedToolCall, ApprovalDecision> {
        match self.evaluate(ctx, call) {
            ApprovalDecision::Allow => Ok(crate::approved::ApprovedToolCall::mint(
                &ctx.session_id,
                call,
                false,
            )),
            other => Err(other),
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn call(name: &str, effect: ToolEffect, args: Value) -> NormalisedToolCall {
        NormalisedToolCall::from_parts(name, effect, DataEgressClass::LocalMetadata, &args)
    }

    #[test]
    fn unknown_effect_denied() {
        let engine = PolicyEngine::new();
        let ctx = AuthorisationContext::new("s1");
        let c = call("mystery", ToolEffect::Unknown, serde_json::json!({}));
        assert!(!engine.evaluate(&ctx, &c).is_allow());
    }

    #[test]
    fn unknown_tool_name_denied_via_unknown_effect() {
        // Registry miss maps to ToolEffect::Unknown before evaluate.
        let engine = PolicyEngine::new();
        let ctx = AuthorisationContext::permissive();
        let c = call(
            "completely_unknown_tool",
            ToolEffect::Unknown,
            serde_json::json!({}),
        );
        assert!(matches!(
            engine.evaluate(&ctx, &c),
            ApprovalDecision::Deny { .. }
        ));
    }

    #[test]
    fn post_method_upgrades_passive_claim() {
        let c = NormalisedToolCall::from_parts(
            "http_get",
            ToolEffect::PassiveNetworkRequest,
            DataEgressClass::TargetContent,
            &serde_json::json!({"url": "http://127.0.0.1/", "method": "POST"}),
        );
        assert_eq!(c.effect, ToolEffect::StateChangingNetworkRequest);
    }

    #[test]
    fn non_interactive_require_interactive_becomes_deny() {
        let engine = PolicyEngine::new();
        let mut ctx = AuthorisationContext::new("s1").with_interactive(false);
        ctx.filesystem = ApprovedFilesystemScope::unrestricted();
        let c = call(
            "read_memory",
            ToolEffect::ProcessMemoryRead,
            serde_json::json!({"pid": 1}),
        );
        assert!(matches!(
            engine.evaluate(&ctx, &c),
            ApprovalDecision::Deny { .. }
        ));
    }

    #[test]
    fn empty_tool_denied() {
        let engine = PolicyEngine::new();
        let ctx = AuthorisationContext::permissive_for_tests("s1");
        let c = call("", ToolEffect::PureComputation, serde_json::json!({}));
        assert!(!engine.evaluate(&ctx, &c).is_allow());
    }

    #[test]
    fn post_fails_closed_non_interactive() {
        let engine = PolicyEngine::new();
        let mut ctx = AuthorisationContext::new("s1");
        ctx.network = ApprovedNetworkScope::unrestricted();
        ctx.interactive = false;
        let c = call(
            "http_post",
            ToolEffect::StateChangingNetworkRequest,
            serde_json::json!({"url": "http://127.0.0.1:9/", "data": {}}),
        );
        assert!(matches!(
            engine.evaluate(&ctx, &c),
            ApprovalDecision::Deny { .. }
        ));
    }

    #[test]
    fn active_probe_distinct_from_passive() {
        assert!(ToolEffect::ActiveNetworkProbe.is_stronger_than(ToolEffect::PassiveNetworkRequest));
        let engine = PolicyEngine::new();
        let mut ctx = AuthorisationContext::new("s1");
        ctx.network = ApprovedNetworkScope::unrestricted();
        let passive = call(
            "http_get",
            ToolEffect::PassiveNetworkRequest,
            serde_json::json!({"url": "http://127.0.0.1:9/"}),
        );
        let probe = call(
            "web_scan",
            ToolEffect::ActiveNetworkProbe,
            serde_json::json!({"url": "http://127.0.0.1:9/"}),
        );
        assert!(engine.evaluate(&ctx, &passive).is_allow());
        assert!(!engine.evaluate(&ctx, &probe).is_allow());
    }

    #[test]
    fn memory_stronger_than_metadata() {
        assert!(ToolEffect::ProcessMemoryRead.is_stronger_than(ToolEffect::ProcessMetadataRead));
    }

    #[test]
    fn mutated_args_invalidate_approval() {
        let engine = PolicyEngine::new();
        let mut strict = AuthorisationContext::new("s1");
        strict.filesystem = ApprovedFilesystemScope::unrestricted();
        strict.interactive = false;
        let c1 = call(
            "read_file",
            ToolEffect::LocalFileContentRead,
            serde_json::json!({"path": "/tmp/a"}),
        );
        let c2 = call(
            "read_file",
            ToolEffect::LocalFileContentRead,
            serde_json::json!({"path": "/tmp/b"}),
        );
        assert_ne!(c1.arg_digest, c2.arg_digest);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            engine.grant(&strict, &c1, false).await;
        });
        assert!(engine.evaluate(&strict, &c1).is_allow());
        assert!(!engine.evaluate(&strict, &c2).is_allow());
    }

    #[test]
    fn path_outside_root_denied() {
        let dir = tempfile_dir();
        let engine = PolicyEngine::new();
        let fs = ApprovedFilesystemScope::new([dir.path().to_path_buf()]).unwrap();
        let mut ctx = AuthorisationContext::new("s1").with_filesystem(fs);
        ctx.interactive = true;
        let outside = dir.path().parent().unwrap().join("vest-outside-scope.txt");
        let c = call(
            "read_file",
            ToolEffect::LocalFileContentRead,
            serde_json::json!({"path": outside.to_string_lossy()}),
        );
        assert!(!engine.evaluate(&ctx, &c).is_allow());
    }

    fn tempfile_dir() -> TempDir {
        let path = std::env::temp_dir().join(format!("vest-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::File::create(path.join("ok.txt"))
            .unwrap()
            .write_all(b"ok")
            .unwrap();
        TempDir { path }
    }

    struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
