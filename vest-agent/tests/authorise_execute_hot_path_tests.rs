//! K5b: authorise → execute_authorised → filter_for_model.
//!
//! Proves forgeable `ApprovalDecision::Allow` cannot execute; capability
//! mismatches fail closed; egress filtering is applied on the authorised path.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use vest_agent::{
    ApprovedFilesystemScope, AuthorisationContext, NormalisedToolCall, PolicyEngine,
    ToolDefinition, ToolRegistry,
};
use vest_core::{ApprovalDecision, DataEgressClass, ToolEffect};

fn echo_def() -> ToolDefinition {
    ToolDefinition::new(
        "echo",
        "Echo args",
        serde_json::json!({"type":"object"}),
        ToolEffect::PureComputation,
        DataEgressClass::PublicNonSensitive,
    )
}

fn read_file_def() -> ToolDefinition {
    ToolDefinition::new(
        "read_file",
        "Read a local file",
        serde_json::json!({"type":"object"}),
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
    )
}

fn tempfile_root(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("vest-k5b-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn forgeable_allow_alone_cannot_execute_handler() {
    // Public Allow is forgeable; it is not an ApprovedToolCall and must not run handlers.
    let forged = ApprovalDecision::Allow;
    assert!(forged.is_allow());

    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let mut registry = ToolRegistry::new();
    registry.register(echo_def(), move |_| {
        calls2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"ok": true}))
    });

    // Legacy execute shim is not a bypass.
    let err = registry.execute("echo", serde_json::json!({})).unwrap_err();
    assert!(
        err.to_string().contains("not a policy bypass") || err.to_string().contains("invoke"),
        "{err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // Without PolicyEngine::authorise there is no ApprovedToolCall to execute.
    let ctx = AuthorisationContext::new("forge");
    let policy = PolicyEngine::new();
    let err = registry
        .invoke(&policy, &ctx, "not_registered", serde_json::json!({}))
        .unwrap_err();
    assert!(
        err.to_string().contains("not found") || err.to_string().contains("denied"),
        "{err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn capability_tool_id_mismatch_fails_and_handler_not_run() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_echo = calls.clone();
    let calls_read = calls.clone();
    let mut registry = ToolRegistry::new();
    registry.register(echo_def(), move |_| {
        calls_echo.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"ok": true}))
    });
    registry.register(read_file_def(), move |_| {
        calls_read.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"content": "LEAK"}))
    });

    let root = tempfile_root("mismatch-tool");
    let file = root.join("a.txt");
    std::fs::write(&file, "secret").unwrap();
    let fs = ApprovedFilesystemScope::new([root.clone()]).unwrap();
    let mut ctx = AuthorisationContext::permissive_for_tests("mismatch-tool");
    ctx.filesystem = fs;

    let policy = PolicyEngine::new();
    let call = NormalisedToolCall::from_parts(
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
        &serde_json::json!({"path": file.to_string_lossy()}),
    );
    let approval = policy
        .authorise(&ctx, &call)
        .expect("should authorise read_file");

    let err = registry
        .execute_authorised("echo", serde_json::json!({}), &approval, &ctx)
        .unwrap_err();
    assert!(
        err.to_string().contains("capability is for") || err.to_string().contains("denied"),
        "{err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn capability_arg_mismatch_fails_and_handler_not_run() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), move |_| {
        calls2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "path": "/tmp/x",
            "content": "password = super-secret-value",
            "size": 32
        }))
    });

    let root = tempfile_root("mismatch-args");
    let a = root.join("a.txt");
    let b = root.join("b.txt");
    std::fs::write(&a, "A").unwrap();
    std::fs::write(&b, "B").unwrap();
    let fs = ApprovedFilesystemScope::new([root.clone()]).unwrap();
    let mut ctx = AuthorisationContext::permissive_for_tests("mismatch-args");
    ctx.filesystem = fs;
    ctx.allow_local_content_egress = true;

    let policy = PolicyEngine::new();
    let call = NormalisedToolCall::from_parts(
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
        &serde_json::json!({"path": a.to_string_lossy()}),
    );
    let approval = policy.authorise(&ctx, &call).expect("authorise path A");

    let err = registry
        .execute_authorised(
            "read_file",
            serde_json::json!({"path": b.to_string_lossy()}),
            &approval,
            &ctx,
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("does not match") || err.to_string().contains("denied"),
        "{err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_authorised_applies_egress_filter() {
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), |_| {
        Ok(serde_json::json!({
            "path": "/tmp/x",
            "content": "password = super-secret-value",
            "size": 32
        }))
    });

    let root = tempfile_root("egress");
    let file = root.join("x");
    std::fs::write(&file, "password = super-secret-value").unwrap();
    let fs = ApprovedFilesystemScope::new([root.clone()]).unwrap();
    let mut ctx = AuthorisationContext::permissive_for_tests("egress");
    ctx.filesystem = fs;
    ctx.allow_local_content_egress = false;

    let policy = PolicyEngine::new();
    let args = serde_json::json!({"path": file.to_string_lossy()});
    let call = NormalisedToolCall::from_parts(
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
        &args,
    );
    let approval = policy.authorise(&ctx, &call).expect("authorise");

    let out = registry
        .execute_authorised("read_file", args, &approval, &ctx)
        .expect("execute_authorised must return filtered stub, not raw content");

    assert_eq!(out["egress_denied"], true);
    let s = out.to_string();
    assert!(
        !s.contains("super-secret-value"),
        "local content must not reach model context: {s}"
    );
}

#[test]
fn invoke_is_thin_wrapper_over_authorise_execute_filter() {
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), |_| {
        Ok(serde_json::json!({
            "path": "/tmp/x",
            "content": "password = super-secret-value",
            "size": 32
        }))
    });

    let root = tempfile_root("invoke-wrap");
    let file = root.join("x");
    std::fs::write(&file, "password = super-secret-value").unwrap();
    let fs = ApprovedFilesystemScope::new([root.clone()]).unwrap();
    let mut ctx = AuthorisationContext::permissive_for_tests("invoke-wrap");
    ctx.filesystem = fs;
    ctx.allow_local_content_egress = false;

    let policy = PolicyEngine::new();
    let out = registry
        .invoke(
            &policy,
            &ctx,
            "read_file",
            serde_json::json!({"path": file.to_string_lossy()}),
        )
        .unwrap();

    assert_eq!(out["egress_denied"], true);
    assert!(!out.to_string().contains("super-secret-value"));
}

#[test]
fn session_mismatch_rejects_capability() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let mut registry = ToolRegistry::new();
    registry.register(echo_def(), move |_| {
        calls2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"ok": true}))
    });

    let ctx_a = AuthorisationContext::permissive_for_tests("session-a");
    let ctx_b = AuthorisationContext::permissive_for_tests("session-b");

    let policy = PolicyEngine::new();
    let args = serde_json::json!({});
    let call = NormalisedToolCall::from_parts(
        "echo",
        ToolEffect::PureComputation,
        DataEgressClass::PublicNonSensitive,
        &args,
    );
    let approval = policy
        .authorise(&ctx_a, &call)
        .expect("authorise in session-a");

    let err = registry
        .execute_authorised("echo", args, &approval, &ctx_b)
        .unwrap_err();
    assert!(
        err.to_string().contains("does not match") || err.to_string().contains("denied"),
        "{err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
