//! Adversarial tool-use attempts — model-shaped calls that try to bypass policy.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use vest_agent::{
    ApprovedFilesystemScope, ApprovedNetworkScope, AuthorisationContext, PolicyEngine,
    ToolDefinition, ToolRegistry,
};
use vest_core::{DataEgressClass, ToolEffect};

fn read_file_def() -> ToolDefinition {
    ToolDefinition::new(
        "read_file",
        "Read a local file",
        serde_json::json!({"type":"object"}),
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
    )
}

fn http_get_def() -> ToolDefinition {
    ToolDefinition::new(
        "http_get",
        "HTTP GET",
        serde_json::json!({"type":"object"}),
        ToolEffect::PassiveNetworkRequest,
        DataEgressClass::TargetContent,
    )
}

fn tempfile_root(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("vest-adv-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn path_escape_via_dotdot_is_denied_and_handler_not_run() {
    let root = tempfile_root("policy-fs");
    let outside = root.join("outside.txt");
    let inside = root.join("jail");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::write(&outside, "SECRET").unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), move |_args| {
        calls2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"content": "LEAKED"}))
    });

    let fs = ApprovedFilesystemScope::new([inside.clone()]).unwrap();
    let ctx = AuthorisationContext::new("adv-fs")
        .with_filesystem(fs)
        .with_interactive(true);
    let policy = PolicyEngine::new();

    let err = registry
        .invoke(
            &policy,
            &ctx,
            "read_file",
            serde_json::json!({"path": outside.to_string_lossy()}),
        )
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("filesystem") || err.to_lowercase().contains("denied"),
        "{err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "handler must not run");

    let err2 = registry
        .invoke(
            &policy,
            &ctx,
            "read_file",
            serde_json::json!({"path": inside.join("..").join("outside.txt").to_string_lossy()}),
        )
        .unwrap_err();
    assert!(err2.to_lowercase().contains("filesystem") || err2.to_lowercase().contains("denied"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn absolute_path_outside_root_denied() {
    let root = tempfile_root("policy-abs");
    let jail = root.join("jail");
    std::fs::create_dir_all(&jail).unwrap();
    let fs = ApprovedFilesystemScope::new([jail]).unwrap();
    let ctx = AuthorisationContext::new("abs").with_filesystem(fs);
    let policy = PolicyEngine::new();
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), |_| Ok(serde_json::json!({})));

    let err = registry
        .invoke(
            &policy,
            &ctx,
            "read_file",
            serde_json::json!({"path": "/etc/passwd"}),
        )
        .unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn network_host_prefix_collision_denied() {
    let net = ApprovedNetworkScope::new(["http://example.com"]).unwrap();
    let ctx = AuthorisationContext::new("net")
        .with_network(net)
        .with_interactive(false);
    let policy = PolicyEngine::new();
    let mut registry = ToolRegistry::new();
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    registry.register(http_get_def(), move |_| {
        ran2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"body": "ok"}))
    });

    let err = registry
        .invoke(
            &policy,
            &ctx,
            "http_get",
            serde_json::json!({"url": "http://example.com.evil/"}),
        )
        .unwrap_err();
    assert!(err.to_lowercase().contains("network") || err.to_lowercase().contains("denied"));
    assert_eq!(ran.load(Ordering::SeqCst), 0);

    let _ok = registry
        .invoke(
            &policy,
            &ctx,
            "http_get",
            serde_json::json!({"url": "http://example.com/path"}),
        )
        .unwrap();
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

#[test]
fn claimed_get_with_post_method_fails_closed_non_interactive() {
    let net = ApprovedNetworkScope::new(["http://127.0.0.1:9"]).unwrap();
    let ctx = AuthorisationContext::new("post").with_network(net);
    let policy = PolicyEngine::new();
    let mut registry = ToolRegistry::new();
    registry.register(http_get_def(), |_| Ok(serde_json::json!({"ok": true})));

    let err = registry
        .invoke(
            &policy,
            &ctx,
            "http_get",
            serde_json::json!({"url": "http://127.0.0.1:9/", "method": "POST"}),
        )
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("denied") || err.to_lowercase().contains("approval"),
        "{err}"
    );
}

#[test]
fn unknown_tool_denied_even_with_permissive_context() {
    let ctx = AuthorisationContext::permissive();
    let policy = PolicyEngine::new();
    let registry = ToolRegistry::new();
    let err = registry
        .invoke(&policy, &ctx, "totally_fake_tool", serde_json::json!({}))
        .unwrap_err();
    assert!(err.contains("not found") || err.to_lowercase().contains("denied"));
}

#[test]
fn execute_shim_is_not_a_policy_bypass() {
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), |_| {
        Ok(serde_json::json!({"content": "should-not-run"}))
    });
    let err = registry
        .execute("read_file", serde_json::json!({"path": "/etc/passwd"}))
        .unwrap_err();
    assert!(
        err.contains("not a policy bypass") || err.contains("invoke"),
        "{err}"
    );
}

#[test]
fn missing_path_denied_before_handler_even_when_permissive() {
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), move |_| {
        ran2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"content": "LEAKED"}))
    });
    let ctx = AuthorisationContext::permissive();
    let policy = PolicyEngine::new();

    let err = registry
        .invoke(&policy, &ctx, "read_file", serde_json::json!({}))
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("missing path"),
        "expected missing-path deny, got: {err}"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 0, "handler must not run");
}

#[test]
fn non_string_path_denied_before_handler() {
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let mut registry = ToolRegistry::new();
    registry.register(read_file_def(), move |_| {
        ran2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"content": "LEAKED"}))
    });
    let ctx = AuthorisationContext::permissive();
    let policy = PolicyEngine::new();

    for args in [
        serde_json::json!({"path": ["/etc/passwd"]}),
        serde_json::json!({"path": {"p": "/etc/passwd"}}),
        serde_json::json!({"path": null}),
    ] {
        let err = registry
            .invoke(&policy, &ctx, "read_file", args)
            .unwrap_err();
        assert!(
            err.to_lowercase().contains("must be a string"),
            "expected non-string path deny, got: {err}"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0, "handler must not run");
    }
}

#[test]
fn missing_or_non_string_url_denied_before_handler() {
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let mut registry = ToolRegistry::new();
    registry.register(http_get_def(), move |_| {
        ran2.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"body": "LEAKED"}))
    });
    let ctx = AuthorisationContext::permissive();
    let policy = PolicyEngine::new();

    let err = registry
        .invoke(&policy, &ctx, "http_get", serde_json::json!({}))
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("missing url"),
        "expected missing-url deny, got: {err}"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 0);

    let err2 = registry
        .invoke(
            &policy,
            &ctx,
            "http_get",
            serde_json::json!({"url": ["http://evil.test/"]}),
        )
        .unwrap_err();
    assert!(
        err2.to_lowercase().contains("must be a string"),
        "expected non-string url deny, got: {err2}"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 0, "handler must not run");
}

#[test]
fn local_write_missing_path_denied_before_handler() {
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let mut registry = ToolRegistry::new();
    registry.register(
        ToolDefinition::new(
            "write_file",
            "Write a local file",
            serde_json::json!({"type":"object"}),
            ToolEffect::LocalWrite,
            DataEgressClass::LocalMetadata,
        ),
        move |_| {
            ran2.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({"ok": true}))
        },
    );
    let ctx = AuthorisationContext::permissive();
    let policy = PolicyEngine::new();
    let err = registry
        .invoke(
            &policy,
            &ctx,
            "write_file",
            serde_json::json!({"path": {"nested": "x"}}),
        )
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("must be a string"),
        "expected non-string path deny, got: {err}"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 0, "handler must not run");
}

#[test]
fn approval_token_invalidated_when_args_mutate() {
    let root = tempfile_root("token-mut");
    let jail = root.join("jail");
    std::fs::create_dir_all(&jail).unwrap();
    std::fs::write(jail.join("a.txt"), "a").unwrap();
    std::fs::write(jail.join("b.txt"), "b").unwrap();

    let fs = ApprovedFilesystemScope::new([jail.clone()]).unwrap();
    let mut ctx = AuthorisationContext::new("tok").with_filesystem(fs);
    ctx.interactive = true;
    let policy = PolicyEngine::new();

    let call_a = vest_agent::NormalisedToolCall::from_parts(
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
        &serde_json::json!({"path": jail.join("a.txt").to_string_lossy()}),
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(policy.grant(&ctx, &call_a, false));

    let call_b = vest_agent::NormalisedToolCall::from_parts(
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
        &serde_json::json!({"path": jail.join("b.txt").to_string_lossy()}),
    );
    let decision = policy.evaluate(&ctx, &call_b);
    assert!(
        !decision.is_allow(),
        "mutated path must not reuse prior approval token"
    );
}
