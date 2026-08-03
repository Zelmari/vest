//! `vest policy explain` — operator-facing tool policy explanation / simulation.

use std::path::Path;

use vest_agent::{
    cli_pregrant_effects, ApprovedFilesystemScope, ApprovedNetworkScope, AuthorisationContext,
    NormalisedToolCall, PolicyEngine,
};
use vest_core::auth::{ApprovalDecision, DataEgressClass, ToolEffect};
use vest_core::error::VestError;

use crate::commands::config::resolve_config_path;
use crate::PolicyExplainArgs;

/// Static catalog of agent tools registered by the CLI scan path.
const REGISTERED_TOOLS: &[(&str, ToolEffect, DataEgressClass)] = &[
    (
        "web_scan",
        ToolEffect::ActiveNetworkProbe,
        DataEgressClass::TargetContent,
    ),
    (
        "file_scan",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
    ),
    (
        "memory_scan",
        ToolEffect::ProcessMemoryRead,
        DataEgressClass::ProcessMemory,
    ),
    (
        "http_get",
        ToolEffect::PassiveNetworkRequest,
        DataEgressClass::TargetContent,
    ),
    (
        "http_post",
        ToolEffect::StateChangingNetworkRequest,
        DataEgressClass::TargetContent,
    ),
    (
        "read_file",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
    ),
    (
        "list_files",
        ToolEffect::LocalMetadataRead,
        DataEgressClass::LocalMetadata,
    ),
    (
        "browser_inspect",
        ToolEffect::ActiveNetworkProbe,
        DataEgressClass::TargetContent,
    ),
    (
        "scan_for_secrets",
        ToolEffect::LocalFileContentRead,
        DataEgressClass::LocalContent,
    ),
];

const ALL_EFFECTS: &[ToolEffect] = &[
    ToolEffect::PureComputation,
    ToolEffect::LocalMetadataRead,
    ToolEffect::LocalFileContentRead,
    ToolEffect::LocalWrite,
    ToolEffect::NetworkMetadataRead,
    ToolEffect::PassiveNetworkRequest,
    ToolEffect::ActiveNetworkProbe,
    ToolEffect::StateChangingNetworkRequest,
    ToolEffect::ProcessMetadataRead,
    ToolEffect::ProcessMemoryRead,
    ToolEffect::CommandExecution,
    ToolEffect::CredentialAccess,
    ToolEffect::Unknown,
];

pub async fn run(
    args: PolicyExplainArgs,
    config_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path.as_ref());
    let config = if config_path.exists() {
        vest_config::load_config(&config_path).map_err(|e| {
            VestError::Config(format!(
                "Failed to load config {}: {e}. Refusing silent defaults for a present file.",
                config_path.display()
            ))
        })?
    } else {
        vest_config::default_config()
    };

    println!("VEST policy explain");
    println!();
    println!("Evaluation pipeline");
    println!("  1. Normalise tool call (effect, egress class, path/url, SHA-256 arg digest)");
    println!("  2. Fail closed on empty tool id / unknown effect / missing material path|url");
    println!("  3. Enforce filesystem + network scopes");
    println!("  4. Match exact ApprovalToken (one-shot / reusable)");
    println!("  5. Match effect+session grant (CLI --approve-*)");
    println!("  6. Interactive RequireInteractive vs non-interactive Deny for sensitive effects");
    println!("  7. Auto-allow passive/metadata effects; deny the rest");
    println!("  Note: authorising an action ≠ allowing model egress of the result.");
    println!();

    println!("ToolEffect catalog");
    for effect in ALL_EFFECTS {
        let posture = effect_posture(*effect);
        println!("  {effect:<34} {posture}");
    }
    println!();

    println!("Registered agent tools (scan path)");
    println!("  {:<20} {:<34} egress", "tool", "effect");
    for (name, effect, egress) in REGISTERED_TOOLS {
        println!("  {name:<20} {effect:<34} {egress:?}");
    }
    println!();

    println!("CLI pre-grants");
    println!("  --approve-writes     → LocalWrite");
    println!(
        "  --approve-exploits   → ActiveNetworkProbe, StateChangingNetworkRequest, CommandExecution"
    );
    println!("  --approve-effect X   → exact ToolEffect (snake_case, repeatable)");
    println!("  --no-approval        → never prompt; deny approval-required ops (not allow-all)");
    println!();

    println!("Active probe consent (CLI web / nuclei)");
    println!("  config/flag allow:   scanner.web.allow_active_probes or --allow-active-probes");
    println!("  confirm:             --confirm-active-probes or --approve-exploits");
    println!("  both required:       allow alone never enables probes");
    println!(
        "  current allow flag:  {}",
        config.scanner.web.allow_active_probes
    );
    println!();

    let s = &config.safety;
    println!("Config safety / egress (from {})", config_path.display());
    println!("  write_approval:            {}", s.write_approval);
    println!("  exploit_approval:          {}", s.exploit_approval);
    println!("  network_write_approval:    {}", s.network_write_approval);
    println!(
        "  egress local_content:      {}",
        s.allow_model_egress_local_content
    );
    println!(
        "  egress process_memory:     {}",
        s.allow_model_egress_process_memory
    );
    println!(
        "  egress target_content:     {}",
        s.allow_model_egress_target_content
    );
    println!(
        "  egress potentially_secret: {}",
        s.allow_model_egress_potentially_secret_bearing
    );
    println!(
        "  egress evidence:           {}",
        s.allow_model_egress_evidence
    );
    println!("  deny_private_targets:      {}", s.deny_private_targets);
    println!();

    if args.tool.is_some() || args.effect.is_some() {
        run_simulation(&args)?;
    } else {
        println!("Simulation");
        println!("  Pass --tool <name> and/or --effect <snake_case> with optional --url/--path");
        println!("  and approve flags to evaluate a synthetic call (no execution).");
    }

    Ok(())
}

fn effect_posture(effect: ToolEffect) -> &'static str {
    match effect {
        ToolEffect::Unknown => "always deny",
        ToolEffect::PureComputation
        | ToolEffect::LocalMetadataRead
        | ToolEffect::NetworkMetadataRead
        | ToolEffect::PassiveNetworkRequest
        | ToolEffect::ProcessMetadataRead => "auto-allow after scope checks",
        ToolEffect::LocalFileContentRead
        | ToolEffect::LocalWrite
        | ToolEffect::ActiveNetworkProbe
        | ToolEffect::StateChangingNetworkRequest
        | ToolEffect::ProcessMemoryRead
        | ToolEffect::CommandExecution
        | ToolEffect::CredentialAccess => "requires grant or interactive approval",
    }
}

fn run_simulation(args: &PolicyExplainArgs) -> Result<(), VestError> {
    let (tool_id, effect, egress) = resolve_sim_identity(args)?;
    let mut args_json = serde_json::Map::new();
    if let Some(ref url) = args.url {
        args_json.insert("url".into(), serde_json::json!(url));
    }
    if let Some(ref path) = args.path {
        args_json.insert("path".into(), serde_json::json!(path));
    }
    let material = serde_json::Value::Object(args_json);
    let call = NormalisedToolCall::from_parts(&tool_id, effect, egress, &material);

    let mut ctx = AuthorisationContext::new("policy-explain");
    if let Some(ref path) = args.path {
        let p = std::path::Path::new(path);
        let root = p
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        let fs = ApprovedFilesystemScope::new([root]).map_err(|e| {
            VestError::InvalidInput(format!("Could not build filesystem scope from --path: {e}"))
        })?;
        ctx = ctx.with_filesystem(fs);
    }
    if let Some(ref url) = args.url {
        let net = ApprovedNetworkScope::new([url.as_str()]).map_err(|e| {
            VestError::InvalidInput(format!("Could not build network scope from --url: {e}"))
        })?;
        ctx = ctx.with_network(net);
    }
    ctx = ctx.with_interactive(args.interactive);

    let engine = PolicyEngine::new();
    let approve_effects: Result<Vec<ToolEffect>, VestError> = args
        .approve_effect
        .iter()
        .map(|raw| {
            parse_tool_effect(raw).ok_or_else(|| {
                VestError::InvalidInput(format!(
                    "Unknown --approve-effect '{raw}'. Use snake_case ToolEffect names."
                ))
            })
        })
        .collect();
    let approve_effects = approve_effects?;
    for granted in
        cli_pregrant_effects(args.approve_writes, args.approve_exploits, &approve_effects)
    {
        engine.grant_effect_session_sync(&ctx.session_id, granted);
    }

    let decision = engine.evaluate(&ctx, &call);
    println!("Simulation");
    println!("  tool:       {tool_id}");
    println!("  effect:     {effect}");
    println!("  egress:     {egress:?}");
    println!("  target:     {}", call.normalised_target);
    println!("  interactive:{}", ctx.interactive);
    println!(
        "  grants:     writes={} exploits={} effects={:?}",
        args.approve_writes, args.approve_exploits, args.approve_effect
    );
    match decision {
        ApprovalDecision::Allow => println!("  decision:   Allow"),
        ApprovalDecision::Deny { reason } => println!("  decision:   Deny — {reason}"),
        ApprovalDecision::RequireInteractive { reason } => {
            println!("  decision:   RequireInteractive — {reason}")
        }
    }
    Ok(())
}

fn resolve_sim_identity(
    args: &PolicyExplainArgs,
) -> Result<(String, ToolEffect, DataEgressClass), VestError> {
    if let Some(ref tool) = args.tool {
        let entry = REGISTERED_TOOLS
            .iter()
            .find(|(name, _, _)| *name == tool.as_str())
            .ok_or_else(|| {
                VestError::InvalidInput(format!(
                    "Unknown tool '{tool}'. Known: {}",
                    REGISTERED_TOOLS
                        .iter()
                        .map(|(n, _, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        let mut effect = entry.1;
        if let Some(ref effect_raw) = args.effect {
            effect = parse_tool_effect(effect_raw).ok_or_else(|| {
                VestError::InvalidInput(format!("Unknown --effect '{effect_raw}'"))
            })?;
        }
        return Ok((entry.0.to_string(), effect, entry.2));
    }

    let effect_raw = args.effect.as_deref().ok_or_else(|| {
        VestError::InvalidInput("Simulation requires --tool and/or --effect".into())
    })?;
    let effect = parse_tool_effect(effect_raw)
        .ok_or_else(|| VestError::InvalidInput(format!("Unknown --effect '{effect_raw}'")))?;
    let egress = default_egress_for_effect(effect);
    Ok((format!("sim:{effect}"), effect, egress))
}

fn default_egress_for_effect(effect: ToolEffect) -> DataEgressClass {
    match effect {
        ToolEffect::LocalMetadataRead => DataEgressClass::LocalMetadata,
        ToolEffect::LocalFileContentRead | ToolEffect::LocalWrite => DataEgressClass::LocalContent,
        ToolEffect::ProcessMemoryRead => DataEgressClass::ProcessMemory,
        ToolEffect::ProcessMetadataRead => DataEgressClass::PublicNonSensitive,
        ToolEffect::NetworkMetadataRead
        | ToolEffect::PassiveNetworkRequest
        | ToolEffect::ActiveNetworkProbe
        | ToolEffect::StateChangingNetworkRequest => DataEgressClass::TargetContent,
        ToolEffect::CommandExecution | ToolEffect::CredentialAccess => {
            DataEgressClass::PotentiallySecretBearing
        }
        ToolEffect::PureComputation | ToolEffect::Unknown => DataEgressClass::PublicNonSensitive,
    }
}

fn parse_tool_effect(raw: &str) -> Option<ToolEffect> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pure_computation" => Some(ToolEffect::PureComputation),
        "local_metadata_read" => Some(ToolEffect::LocalMetadataRead),
        "local_file_content_read" => Some(ToolEffect::LocalFileContentRead),
        "local_write" => Some(ToolEffect::LocalWrite),
        "network_metadata_read" => Some(ToolEffect::NetworkMetadataRead),
        "passive_network_request" => Some(ToolEffect::PassiveNetworkRequest),
        "active_network_probe" => Some(ToolEffect::ActiveNetworkProbe),
        "state_changing_network_request" => Some(ToolEffect::StateChangingNetworkRequest),
        "process_metadata_read" => Some(ToolEffect::ProcessMetadataRead),
        "process_memory_read" => Some(ToolEffect::ProcessMemoryRead),
        "command_execution" => Some(ToolEffect::CommandExecution),
        "credential_access" => Some(ToolEffect::CredentialAccess),
        "unknown" => Some(ToolEffect::Unknown),
        _ => None,
    }
}
