//! K2: effect+session pre-grants and fail-closed non-interactive / no-approval behaviour.

use vest_agent::{
    cli_pregrant_effects, ApprovedFilesystemScope, ApprovedNetworkScope, AuthorisationContext,
    NormalisedToolCall, PolicyEngine,
};
use vest_core::auth::{ApprovalDecision, DataEgressClass, ToolEffect};

fn write_call(path: &str) -> NormalisedToolCall {
    NormalisedToolCall::from_parts(
        "write_file",
        ToolEffect::LocalWrite,
        DataEgressClass::PotentiallySecretBearing,
        &serde_json::json!({"path": path, "content": "x"}),
    )
}

fn probe_call(url: &str) -> NormalisedToolCall {
    NormalisedToolCall::from_parts(
        "web_scan",
        ToolEffect::ActiveNetworkProbe,
        DataEgressClass::TargetContent,
        &serde_json::json!({"url": url}),
    )
}

#[test]
fn non_interactive_denies_without_grant() {
    let engine = PolicyEngine::new();
    let mut ctx = AuthorisationContext::new("s1").with_interactive(false);
    ctx.filesystem = ApprovedFilesystemScope::unrestricted();
    let decision = engine.evaluate(&ctx, &write_call("/tmp/a"));
    assert!(
        matches!(decision, ApprovalDecision::Deny { .. }),
        "expected deny, got {decision:?}"
    );
}

#[test]
fn interactive_without_grant_requires_interactive() {
    let engine = PolicyEngine::new();
    let mut ctx = AuthorisationContext::new("s1").with_interactive(true);
    ctx.filesystem = ApprovedFilesystemScope::unrestricted();
    let decision = engine.evaluate(&ctx, &write_call("/tmp/a"));
    assert!(
        matches!(decision, ApprovalDecision::RequireInteractive { .. }),
        "expected RequireInteractive, got {decision:?}"
    );
}

#[test]
fn approve_writes_pregrant_allows_local_write_once_denied() {
    let engine = PolicyEngine::new();
    let mut ctx = AuthorisationContext::new("sess").with_interactive(false);
    ctx.filesystem = ApprovedFilesystemScope::unrestricted();
    let call = write_call("/tmp/a");
    assert!(matches!(
        engine.evaluate(&ctx, &call),
        ApprovalDecision::Deny { .. }
    ));

    for effect in cli_pregrant_effects(true, false, &[]) {
        engine.grant_effect_session_sync("sess", effect);
    }

    assert!(
        engine.evaluate(&ctx, &call).is_allow(),
        "approve-writes grant should allow LocalWrite"
    );
}

#[test]
fn approve_exploits_pregrant_allows_probe_not_write() {
    let engine = PolicyEngine::new();
    let mut ctx = AuthorisationContext::new("sess").with_interactive(false);
    ctx.filesystem = ApprovedFilesystemScope::unrestricted();
    ctx.network = ApprovedNetworkScope::unrestricted();

    for effect in cli_pregrant_effects(false, true, &[]) {
        engine.grant_effect_session_sync("sess", effect);
    }

    assert!(engine
        .evaluate(&ctx, &probe_call("http://127.0.0.1:9/"))
        .is_allow());
    assert!(matches!(
        engine.evaluate(&ctx, &write_call("/tmp/a")),
        ApprovalDecision::Deny { .. }
    ));
}

#[test]
fn approve_effect_file_content_exact() {
    let engine = PolicyEngine::new();
    let mut ctx = AuthorisationContext::new("sess").with_interactive(false);
    ctx.filesystem = ApprovedFilesystemScope::unrestricted();
    let read = NormalisedToolCall::from_parts(
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
        &serde_json::json!({"path": "/tmp/a"}),
    );
    assert!(matches!(
        engine.evaluate(&ctx, &read),
        ApprovalDecision::Deny { .. }
    ));
    for effect in cli_pregrant_effects(false, false, &[ToolEffect::LocalFileContentRead]) {
        engine.grant_effect_session_sync("sess", effect);
    }
    assert!(engine.evaluate(&ctx, &read).is_allow());
    assert!(matches!(
        engine.evaluate(&ctx, &write_call("/tmp/a")),
        ApprovalDecision::Deny { .. }
    ));
}

#[test]
fn effect_grant_does_not_bypass_filesystem_scope() {
    let dir = std::env::temp_dir().join(format!("vest-k2-scope-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let engine = PolicyEngine::new();
    let fs = ApprovedFilesystemScope::new([dir.clone()]).unwrap();
    let ctx = AuthorisationContext::new("sess")
        .with_interactive(false)
        .with_filesystem(fs);
    engine.grant_effect_session_sync("sess", ToolEffect::LocalWrite);
    let outside = dir.parent().unwrap().join("vest-k2-outside.txt");
    let call = write_call(&outside.to_string_lossy());
    assert!(
        !engine.evaluate(&ctx, &call).is_allow(),
        "grant must not bypass FS scope"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
