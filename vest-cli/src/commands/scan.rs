use crate::ScanArgs;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vest_agent::{
    cli_pregrant_effects, is_private_or_metadata_target, resolve_read_path,
    ApprovedFilesystemScope, ApprovedNetworkScope, ExecutionSession,
};
use vest_core::error::VestError;
use vest_core::traits::{Reporter, Scanner};
use vest_core::types::{Finding, ScanMode, ScanStatus, Severity, Target, TargetType};
use vest_core::{truncate_chars, DataEgressClass, ToolEffect};
use vest_scanner::{HttpClientBudgets, ScopedHttpClient};

/// Hard cap for agent `read_file`: never absorb more than this many bytes.
/// Matches the tool description ("up to 10KB").
const AGENT_READ_FILE_MAX_BYTES: u64 = 10_240;

/// Formats that must keep stdout free of banners/progress (product contract F).
fn is_machine_format(format: &str) -> bool {
    matches!(
        format.trim().to_ascii_lowercase().as_str(),
        "json" | "sarif"
    )
}

/// Human chatter: stderr for machine formats so stdout stays parseable.
macro_rules! ui_line {
    ($machine:expr, $($arg:tt)*) => {{
        if $machine {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    }};
}

fn resolve_tool_path(session: &ExecutionSession, path: &str) -> Result<PathBuf, String> {
    resolve_read_path(&session.filesystem, Path::new(path))
        .map_err(|e| format!("filesystem scope: {e}"))
}

fn authorise_tool_url(session: &ExecutionSession, url: &str) -> Result<(), String> {
    session
        .network
        .authorise_url(url)
        .map(|_| ())
        .map_err(|e| format!("network scope: {e}"))
}

/// Build a [`ScopedHttpClient`] bound to the authorised origin of `url`.
///
/// Initial URL must pass the session network scope; redirects are re-authorised
/// against that same origin by ScopedHttpClient (fail-closed on escape).
fn scoped_client_for_url(
    session: &ExecutionSession,
    url: &str,
    max_body_bytes: usize,
) -> Result<ScopedHttpClient, String> {
    let authorised = session
        .network
        .authorise_url(url)
        .map_err(|e| format!("network scope: {e}"))?;
    let scope = vest_scanner::web::NetworkScope::from_url(&authorised)
        .map_err(|e| format!("network scope: {e}"))?;
    let budgets = HttpClientBudgets {
        max_body_bytes,
        ..HttpClientBudgets::default()
    };
    ScopedHttpClient::try_new(scope, budgets)
        .map(|c| c.with_deny_private_targets(session.network.deny_private_targets()))
        .map_err(|e| e.to_string())
}

fn block_on_scoped<F, T>(fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, VestError>>,
{
    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| handle.block_on(fut)).map_err(|e| e.to_string())
}

/// Agent `http_get` implementation (session-scoped, redirect-safe).
fn agent_http_get(session: &ExecutionSession, url: &str) -> Result<serde_json::Value, String> {
    let client = scoped_client_for_url(session, url, 8_192)?;
    let (status, body) = block_on_scoped(client.get_text(url))?;
    let truncated = truncate_chars(&body, 8000);
    Ok(serde_json::json!({
        "status": status,
        "url": url,
        "body": truncated,
        "body_size": body.len(),
    }))
}

/// Agent `http_post` implementation (session-scoped, redirect-safe).
fn agent_http_post(
    session: &ExecutionSession,
    url: &str,
    data: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = scoped_client_for_url(session, url, 4_096)?;
    let body_str = serde_json::to_string(data).map_err(|e| format!("Failed to serialize: {e}"))?;
    let (status, body) = block_on_scoped(client.post_text(url, &body_str, "application/json"))?;
    let truncated = truncate_chars(&body, 4000);
    Ok(serde_json::json!({
        "status": status,
        "url": url,
        "body": truncated,
        "body_size": body.len(),
    }))
}

/// Sync bounded read used by [`agent_read_file`] (and the blocking pool).
fn read_file_capped(path: &Path) -> Result<serde_json::Value, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("Cannot read file: {e}"))?;
    let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot read file: {e}"))?;
    let mut buf = Vec::with_capacity(AGENT_READ_FILE_MAX_BYTES as usize);
    file.by_ref()
        .take(AGENT_READ_FILE_MAX_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    Ok(serde_json::json!({
        "path": path.display().to_string(),
        "size": meta.len(),
        "content": text,
        "bytes_read": buf.len(),
        "truncated": meta.len() > buf.len() as u64,
    }))
}

/// Agent `read_file` implementation (session-scoped, byte-capped, off async worker).
fn agent_read_file(session: &ExecutionSession, path: &str) -> Result<serde_json::Value, String> {
    let resolved = resolve_tool_path(session, path)?;
    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| {
        handle.block_on(async move {
            tokio::task::spawn_blocking(move || read_file_capped(&resolved))
                .await
                .map_err(|e| format!("read_file task failed: {e}"))?
        })
    })
}

pub async fn run(
    mut args: ScanArgs,
    config_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.list_profiles {
        return print_known_profiles(config_path.as_ref());
    }

    if let Some(ref scan_id) = args.resume {
        // Scans are persisted only at finalize; SQLite has no resumable checkpoint.
        return Err(VestError::Unsupported(format!(
            "--resume is not implemented (no checkpoint for scan id '{scan_id}')"
        ))
        .into());
    }

    let target_display = args
        .target
        .as_deref()
        .ok_or_else(|| VestError::InvalidInput("TARGET is required".into()))?;

    let machine = is_machine_format(&args.format);

    ui_line!(machine, "\u{250c}{}\u{2510}", "\u{2500}".repeat(50));
    ui_line!(machine, "\u{2502} {:^48} \u{2502}", "VEST SCAN");
    ui_line!(machine, "\u{251c}{}\u{2524}", "\u{2500}".repeat(50));
    ui_line!(
        machine,
        "\u{2502} Target:      {:<35} \u{2502}",
        &target_display[..target_display.len().min(35)]
    );
    ui_line!(
        machine,
        "\u{2502} Profile:     {:<35} \u{2502}",
        args.profile.as_deref().unwrap_or("default")
    );
    ui_line!(
        machine,
        "\u{2502} Mode:        {:<35} \u{2502}",
        args.mode.as_deref().unwrap_or("from config")
    );
    ui_line!(
        machine,
        "\u{2502} Provider:    {:<35} \u{2502}",
        args.provider.as_deref().unwrap_or("from config")
    );
    ui_line!(
        machine,
        "\u{2502} Model:       {:<35} \u{2502}",
        args.model.as_deref().unwrap_or("from config")
    );
    ui_line!(machine, "\u{251c}{}\u{2524}", "\u{2500}".repeat(50));

    // Dry-run and live scan share validation: load config, detect target, resolve
    // scopes, then either print the plan (no side effects) or execute.
    let config_path = config_path.as_ref();
    let config = if config_path.exists() {
        vest_config::load_config(config_path).map_err(|e| {
            VestError::Config(format!(
                "Failed to load config {}: {e}. Refusing silent defaults for a present file.",
                config_path.display()
            ))
        })?
    } else {
        eprintln!(
            "No config at {}; using built-in defaults.",
            config_path.display()
        );
        vest_config::default_config()
    };

    // Fail closed: unknown --profile must not silently fall back to defaults.
    let profile = match args.profile.as_ref() {
        None => None,
        Some(name) => Some(config.profiles.get(name).ok_or_else(|| {
            VestError::InvalidInput(format!(
                "Unknown profile '{name}'. Define [profiles.{name}] in config or omit --profile."
            ))
        })?),
    };

    // --offline / --no-ai force provider none; reject conflicting --provider.
    let force_offline = args.offline || args.no_ai;
    if force_offline {
        if let Some(ref p) = args.provider {
            if p != "none" {
                return Err(VestError::InvalidInput(format!(
                    "--offline/--no-ai conflicts with --provider {p} (use --provider none or omit --provider)"
                ))
                .into());
            }
        }
    }

    let provider_name = if force_offline {
        "none".to_string()
    } else {
        args.provider
            .clone()
            .or_else(|| {
                config
                    .providers
                    .as_ref()
                    .map(|p| p.default.provider.clone())
            })
            // Safer default when no provider is configured: scanner-only (no AI).
            // Explicit config `[providers.default]` or `--provider` still selects a provider.
            .unwrap_or_else(|| "none".to_string())
    };

    let model = args
        .model
        .clone()
        .or_else(|| config.providers.as_ref().map(|p| p.default.model.clone()))
        .unwrap_or_else(|| {
            if provider_name == "none" {
                "none".to_string()
            } else {
                "llama3.2".to_string()
            }
        });

    // Fail closed: invalid --mode (or profile/config pattern) must not fall through to Pipeline.
    let mode_raw = args
        .mode
        .clone()
        .or_else(|| profile.and_then(|p| p.pattern.clone()))
        .unwrap_or_else(|| config.agent.default_pattern.clone());
    let scan_mode: ScanMode = mode_raw.parse().map_err(|_| {
        VestError::InvalidInput(format!(
            "Invalid scan mode '{mode_raw}'. Expected one of: pipeline, swarm, tool-use, hierarchical"
        ))
    })?;

    ui_line!(
        machine,
        "\u{2502} Provider:    {:<35} \u{2502}",
        provider_name
    );
    ui_line!(machine, "\u{2502} Model:       {:<35} \u{2502}", model);
    ui_line!(
        machine,
        "\u{2502} Mode:        {:<35} \u{2502}",
        scan_mode.to_string()
    );
    ui_line!(machine, "\u{251c}{}\u{2524}", "\u{2500}".repeat(50));

    let target = detect_target(&args)?;
    if config.safety.deny_private_targets {
        deny_private_scan_target(&target)?;
    }
    ui_line!(
        machine,
        "\u{2502} Type:        {:<35} \u{2502}",
        target.target_type.to_string()
    );

    let scanner_names = selected_scanners(&args, &config, &target);
    ui_line!(
        machine,
        "\u{2502} Scanners:    {:<35} \u{2502}",
        truncate_for_box(&scanner_names.join(", "), 35)
    );

    // Two-key consent: allow (CLI flag or config) AND confirm (--confirm-active-probes
    // or --approve-exploits). Config/allow alone never enables probes.
    let probes_allowed = args.allow_active_probes || config.scanner.web.allow_active_probes;
    let probes_confirmed = args.confirm_active_probes || args.approve_exploits;
    let allow_active_probes = probes_allowed && probes_confirmed;
    let probes_label = if allow_active_probes { "on" } else { "off" };
    ui_line!(
        machine,
        "\u{2502} Active probes: {:<32} \u{2502}",
        probes_label
    );
    if allow_active_probes {
        eprintln!(
            "CONSENT: active web probes ENABLED (allow + --confirm-active-probes/--approve-exploits)"
        );
    } else if probes_allowed && !probes_confirmed {
        eprintln!(
            "Active probes requested but not confirmed; pass --confirm-active-probes or --approve-exploits to enable."
        );
    }

    let (fs_scope, net_scope) = scopes_from_target(&target);
    let net_scope = net_scope.with_deny_private_targets(config.safety.deny_private_targets);
    let fs_scope_display = format_fs_scope(&fs_scope);
    let net_scope_display = format_net_scope(&net_scope);
    ui_line!(
        machine,
        "\u{2502} FS scope:    {:<35} \u{2502}",
        truncate_for_box(&fs_scope_display, 35)
    );
    ui_line!(
        machine,
        "\u{2502} Net scope:   {:<35} \u{2502}",
        truncate_for_box(&net_scope_display, 35)
    );
    ui_line!(machine, "\u{251c}{}\u{2524}", "\u{2500}".repeat(50));

    // Validate CI gate flags early (including dry-run) so bad input fails closed.
    let fail_on_severity = parse_fail_on_severity(args.fail_on_severity.as_deref())?;

    if args.dry_run {
        let profile_name = args.profile.as_deref().unwrap_or("default");
        let profile_note = match profile {
            Some(p) => format_profile_note(p),
            None => "built-in defaults".to_string(),
        };
        ui_line!(
            machine,
            "\u{2502} {:^48} \u{2502}",
            "DRY RUN - plan only, no actions"
        );
        ui_line!(
            machine,
            "\u{2502} {:^48} \u{2502}",
            truncate_for_box(
                &format!("Selected profile: {profile_name} — {profile_note}"),
                48
            )
        );
        ui_line!(
            machine,
            "\u{2502} {:^48} \u{2502}",
            truncate_for_box(
                &format!(
                    "Would scan {} via [{}]",
                    &target_display[..target_display.len().min(20)],
                    scanner_names.join(", ")
                ),
                48
            )
        );
        ui_line!(machine, "\u{2514}{}\u{2518}", "\u{2500}".repeat(50));
        // No DB writes, no network/scanner execution, no agent tools.
        return Ok(());
    }

    let interactive = !args.no_approval && std::io::IsTerminal::is_terminal(&std::io::stdin());
    let session = ExecutionSession::new(fs_scope.clone(), net_scope.clone(), interactive)
        .with_memory_simulation(args.allow_memory_simulation)
        .with_egress(
            config.safety.allow_model_egress_local_content,
            config.safety.allow_model_egress_process_memory,
            config.safety.allow_model_egress_evidence,
        )
        .with_target_content_egress(config.safety.allow_model_egress_target_content)
        .with_potentially_secret_bearing_egress(
            config.safety.allow_model_egress_potentially_secret_bearing,
        )
        .into_arc();
    args.include_evidence = args.include_evidence || config.general.include_report_evidence;
    let registry = build_tool_registry(Arc::clone(&session), allow_active_probes);
    let safety = build_safety(&args, &config, profile, Arc::clone(&session)).await?;

    ui_line!(machine, "\u{2502} {:^48} \u{2502}", "Running scan...");
    ui_line!(machine, "\u{251c}{}\u{2524}", "\u{2500}".repeat(50));

    let start = std::time::Instant::now();
    let (mut findings, scanner_fatals) = run_builtin_scanners(
        &scanner_names,
        &target,
        &config,
        args.allow_memory_simulation,
        allow_active_probes,
        machine,
    )
    .await?;

    // Degraded exit: scanner fatals (5) take precedence over provider soft (7).
    let mut degraded: Option<VestError> = None;
    if !scanner_fatals.is_empty() {
        degraded = Some(scanner_failure_error(&scanner_fatals));
    }

    if provider_name == "none" {
        ui_line!(
            machine,
            "\u{2502} {:^48} \u{2502}",
            "Agent disabled; scanner-only scan"
        );
        // Enrich scanner findings heuristically since no agent available
        for finding in &mut findings {
            vest_agent::enrich_finding_heuristic(finding);
        }
    } else {
        match crate::commands::providers::create_provider(&provider_name, &model, &config) {
            Ok(provider) => {
                ui_line!(
                    machine,
                    "\u{2502} {:^48} \u{2502}",
                    "Provider configured; running agent"
                );
                let max_iterations = profile
                    .and_then(|p| p.max_llm_iterations)
                    .unwrap_or(config.agent.max_llm_iterations);
                let orchestrator = vest_agent::Orchestrator::new(
                    provider,
                    Arc::new(registry),
                    model.clone(),
                    scan_mode,
                    safety,
                )
                .with_max_iterations(max_iterations)
                .with_initial_findings(findings.clone());

                match orchestrator.run(&target).await {
                    Ok(mut agent_findings) => {
                        for finding in &mut agent_findings {
                            mark_finding_source(finding, "agent", None);
                        }
                        // Replace scanner findings with the enriched set from orchestrator
                        // to avoid duplication of unenriched originals
                        findings = agent_findings;
                    }
                    Err(e) => {
                        ui_line!(
                            machine,
                            "\u{2502} Agent skipped: {:<35} \u{2502}",
                            truncate_for_box(&format!("{}", e), 35)
                        );
                        // Enrich scanner findings heuristically since agent failed
                        for finding in &mut findings {
                            vest_agent::enrich_finding_heuristic(finding);
                        }
                        if degraded.is_none() {
                            degraded = Some(provider_soft_error(e));
                        }
                    }
                }
            }
            Err(e) => {
                ui_line!(
                    machine,
                    "\u{2502} Agent skipped: {:<35} \u{2502}",
                    truncate_for_box(&format!("{}", e), 35)
                );
                ui_line!(
                    machine,
                    "\u{2502} {:^48} \u{2502}",
                    "Scanner findings will still be reported"
                );
                if degraded.is_none() {
                    degraded = Some(provider_soft_error(e));
                }
            }
        }
    }

    dedupe_findings(&mut findings);

    let scan_status = if degraded.is_some() {
        ScanStatus::Failed
    } else {
        ScanStatus::Completed
    };

    let finalize_result = match finalize_scan(FinalizeScanInput {
        args: &args,
        target: &target,
        scan_mode,
        scan_status,
        provider_name: &provider_name,
        model: &model,
        scanner_names: &scanner_names,
        findings: findings.clone(),
        start,
    })
    .await
    {
        Ok(result) => {
            ui_line!(
                machine,
                "\u{2502} Stored:      {:<35} \u{2502}",
                result.stored
            );
            result
        }
        Err(e) => {
            ui_line!(machine, "\u{2502} Error: {:<41} \u{2502}", format!("{}", e));
            ui_line!(machine, "\u{2514}{}\u{2518}", "\u{2500}".repeat(50));
            return Err(e.into());
        }
    };

    if let Some(err) = degraded {
        ui_line!(
            machine,
            "\u{2502} {:^48} \u{2502}",
            "Degraded: findings preserved; non-zero exit"
        );
        ui_line!(machine, "\u{2514}{}\u{2518}", "\u{2500}".repeat(50));
        return Err(err.into());
    }

    if let Some(err) = evaluate_ci_gates(
        fail_on_severity,
        args.fail_on_new,
        &target,
        &finalize_result.scan_id,
        &findings,
    )? {
        ui_line!(
            machine,
            "\u{2502} CI gate:    {:<35} \u{2502}",
            "findings policy failed"
        );
        ui_line!(machine, "\u{2514}{}\u{2518}", "\u{2500}".repeat(50));
        return Err(err.into());
    }

    Ok(())
}

/// Map provider/agent failures onto exit 7 while findings are preserved.
fn provider_soft_error(err: VestError) -> VestError {
    match err {
        VestError::Provider(_) | VestError::Agent(_) | VestError::ValidationFailed { .. } => err,
        other => VestError::Provider(format!(
            "provider/agent soft failure; scanner findings preserved: {other}"
        )),
    }
}

fn scanner_failure_error(errors: &[VestError]) -> VestError {
    let msg = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if !errors.is_empty() && errors.iter().all(|e| matches!(e, VestError::Config(_))) {
        VestError::Config(msg)
    } else {
        VestError::Scan(format!("Scanner failure: {msg}"))
    }
}

struct FinalizeScanInput<'a> {
    args: &'a ScanArgs,
    target: &'a Target,
    scan_mode: ScanMode,
    scan_status: ScanStatus,
    provider_name: &'a str,
    model: &'a str,
    scanner_names: &'a [String],
    findings: Vec<Finding>,
    start: std::time::Instant,
}

fn parse_fail_on_severity(raw: Option<&str>) -> Result<Option<Severity>, VestError> {
    let Some(level) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let normalised = level.to_ascii_lowercase();
    normalised.parse::<Severity>().map(Some).map_err(|_| {
        VestError::InvalidInput(format!(
            "Invalid --fail-on-severity '{level}'. Expected one of: critical, high, medium, low, info"
        ))
    })
}

fn severity_rank_ci(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn severity_meets_threshold(severity: Severity, threshold: Severity) -> bool {
    severity_rank_ci(severity) >= severity_rank_ci(threshold)
}

fn finding_baseline_key(finding: &Finding) -> String {
    finding.title.trim().to_string()
}

fn new_finding_titles(current: &[Finding], previous: &[Finding]) -> Vec<String> {
    let previous_keys: BTreeSet<String> = previous.iter().map(finding_baseline_key).collect();
    let mut new_titles = BTreeSet::new();
    for finding in current {
        let key = finding_baseline_key(finding);
        if !key.is_empty() && !previous_keys.contains(&key) {
            new_titles.insert(key);
        }
    }
    new_titles.into_iter().collect()
}

fn same_logical_target(a: &Target, b: &Target) -> bool {
    if a.target_type != b.target_type {
        return false;
    }
    match a.target_type {
        TargetType::File | TargetType::Binary => {
            a.path.as_deref().unwrap_or(a.name.as_str())
                == b.path.as_deref().unwrap_or(b.name.as_str())
        }
        TargetType::Web | TargetType::Browser => {
            a.url_str.as_deref().unwrap_or(a.name.as_str())
                == b.url_str.as_deref().unwrap_or(b.name.as_str())
        }
        TargetType::Network => {
            a.host.as_deref().unwrap_or(a.name.as_str())
                == b.host.as_deref().unwrap_or(b.name.as_str())
        }
        TargetType::Process => a.pid == b.pid && a.pid.is_some(),
    }
}

fn load_previous_findings_for_target(
    target: &Target,
    current_scan_id: &str,
) -> Result<Option<Vec<Finding>>, VestError> {
    let db_path = get_db_path();
    let pool = vest_storage::ConnectionPool::new(&db_path)
        .map_err(|e| VestError::Storage(e.to_string()))?;
    vest_storage::schema::run_migrations(pool.conn())
        .map_err(|e| VestError::Storage(e.to_string()))?;
    let conn = pool.conn();
    let targets =
        vest_storage::targets::list_targets(conn).map_err(|e| VestError::Storage(e.to_string()))?;
    let mut previous_scans = Vec::new();
    for prior_target in targets.iter().filter(|t| same_logical_target(t, target)) {
        let scans = vest_storage::scans::list_scans_by_target(conn, &prior_target.id)
            .map_err(|e| VestError::Storage(e.to_string()))?;
        for scan in scans {
            if scan.id != current_scan_id {
                previous_scans.push(scan);
            }
        }
    }
    previous_scans.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let Some(prev) = previous_scans.into_iter().next() else {
        return Ok(None);
    };
    let findings = vest_storage::findings::list_findings_by_scan(conn, &prev.id)
        .map_err(|e| VestError::Storage(e.to_string()))?;
    Ok(Some(findings))
}

fn evaluate_ci_gates(
    fail_on_severity: Option<Severity>,
    fail_on_new: bool,
    target: &Target,
    current_scan_id: &str,
    findings: &[Finding],
) -> Result<Option<VestError>, VestError> {
    if let Some(threshold) = fail_on_severity {
        let hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| severity_meets_threshold(f.severity, threshold))
            .collect();
        if !hits.is_empty() {
            let titles: Vec<&str> = hits.iter().take(5).map(|f| f.title.as_str()).collect();
            return Ok(Some(VestError::FindingsGate(format!(
                "{} finding(s) at or above severity '{threshold}' (e.g. {})",
                hits.len(),
                titles.join("; ")
            ))));
        }
    }
    if fail_on_new {
        if let Some(previous) = load_previous_findings_for_target(target, current_scan_id)? {
            let new_titles = new_finding_titles(findings, &previous);
            if !new_titles.is_empty() {
                let sample = new_titles.iter().take(5).cloned().collect::<Vec<_>>();
                return Ok(Some(VestError::FindingsGate(format!(
                    "{} new finding title(s) vs previous scan (e.g. {})",
                    new_titles.len(),
                    sample.join("; ")
                ))));
            }
        }
    }
    Ok(None)
}

struct FinalizeScanResult {
    stored: usize,
    scan_id: String,
}

async fn finalize_scan(input: FinalizeScanInput<'_>) -> Result<FinalizeScanResult, VestError> {
    let FinalizeScanInput {
        args,
        target,
        scan_mode,
        scan_status,
        provider_name,
        model,
        scanner_names,
        findings,
        start,
    } = input;
    let machine = is_machine_format(&args.format);
    let elapsed = start.elapsed();
    ui_line!(
        machine,
        "\u{2502} Duration:    {:<35} \u{2502}",
        format!("{:.1}s", elapsed.as_secs_f64())
    );
    ui_line!(
        machine,
        "\u{2502} Findings:    {:<35} \u{2502}",
        findings.len()
    );

    let (critical, high, medium, low, info) = severity_counts(&findings);
    let scan_session = vest_core::types::ScanSession {
        id: vest_core::ids::new_id(),
        target_id: target.id.clone(),
        mode: scan_mode,
        config: serde_json::json!({
            "provider": provider_name,
            "model": model,
            "scanners": scanner_names,
        }),
        status: scan_status,
        agent_model: (provider_name != "none").then(|| format!("{}/{}", provider_name, model)),
        started_at: Some(
            chrono::Utc::now() - chrono::Duration::from_std(elapsed).unwrap_or_default(),
        ),
        completed_at: Some(chrono::Utc::now()),
        duration_ms: Some(elapsed.as_millis() as i64),
        total_findings: findings.len() as u64,
        critical_count: critical as u64,
        high_count: high as u64,
        medium_count: medium as u64,
        low_count: low as u64,
        info_count: info as u64,
        metadata: serde_json::json!({
            "target": {
                "id": target.id,
                "name": target.name,
                "type": target.target_type.to_string(),
                "path": target.path,
                "url": target.url_str,
                "pid": target.pid,
                "host": target.host,
                "metadata": target.metadata,
            }
        }),
        created_at: chrono::Utc::now(),
    };

    let report = render_report(
        &args.format,
        &scan_session,
        &findings,
        args.include_evidence,
    )
    .await?;
    // Report payload stays on stdout (JSON-only when `-f json`).
    println!("{report}");

    if let Some(ref output_path) = args.output {
        std::fs::write(
            output_path,
            render_report(
                &args.format,
                &scan_session,
                &findings,
                args.include_evidence,
            )
            .await?,
        )
        .map_err(VestError::Io)?;
        ui_line!(machine, "\nReport saved to: {}", output_path);
    }

    let db_path = get_db_path();
    let pool = vest_storage::ConnectionPool::new(&db_path)
        .map_err(|e| VestError::Storage(e.to_string()))?;
    vest_storage::schema::run_migrations(pool.conn())
        .map_err(|e| VestError::Storage(e.to_string()))?;

    // Atomic persist: target + scan + findings commit together or not at all (STOR-3).
    let tx = pool
        .conn()
        .unchecked_transaction()
        .map_err(|e| VestError::Storage(e.to_string()))?;
    vest_storage::targets::insert_target(&tx, target)
        .map_err(|e| VestError::Storage(e.to_string()))?;
    vest_storage::scans::insert_scan(&tx, &scan_session)
        .map_err(|e| VestError::Storage(e.to_string()))?;
    for finding in &findings {
        let mut f = finding.clone();
        f.scan_id = scan_session.id.clone();
        f.target_id = target.id.clone();
        vest_storage::findings::insert_finding(&tx, &f)
            .map_err(|e| VestError::Storage(e.to_string()))?;
    }
    tx.commit().map_err(|e| VestError::Storage(e.to_string()))?;

    Ok(FinalizeScanResult {
        stored: findings.len(),
        scan_id: scan_session.id,
    })
}

/// Run selected scanners. Returns findings from scanners that succeeded, plus any
/// fatal per-scanner errors. Total failure (`ran_ok == 0`) is a hard error.
/// Partial failure preserves findings for finalize, then the caller exits non-zero.
async fn run_builtin_scanners(
    scanner_names: &[String],
    target: &Target,
    config: &vest_config::VestConfig,
    allow_memory_simulation: bool,
    allow_active_probes: bool,
    machine: bool,
) -> Result<(Vec<Finding>, Vec<VestError>), VestError> {
    let mut all_findings = Vec::new();
    let mut fatal_errors: Vec<VestError> = Vec::new();
    let mut ran_ok = 0usize;

    for scanner_name in scanner_names {
        let result = match scanner_name.as_str() {
            "web" if config.scanner.web.enabled => {
                let w = &config.scanner.web;
                // Consent already resolved by caller (allow + confirm/approve-exploits).
                let scanner = vest_scanner::web::WebScanner::new()
                    .with_crawl_depth(w.crawl_depth)
                    .with_max_urls(w.crawl_max_urls as usize)
                    .with_user_agent(w.user_agent.clone())
                    .with_respect_robots_txt(w.respect_robots_txt)
                    .with_max_response_bytes(w.max_response_bytes as usize)
                    .with_max_redirects(w.max_redirects)
                    .with_allow_active_probes(allow_active_probes)
                    .with_deny_private_targets(config.safety.deny_private_targets)
                    .with_connect_timeout_ms(w.connect_timeout_ms)
                    .with_timeout_seconds(w.request_timeout_seconds)
                    .with_max_concurrent_requests(w.max_concurrent_requests as usize);
                run_scanner("web", scanner, target).await
            }
            "binary" if config.scanner.binary.enabled => {
                let scanner = vest_scanner::binary::BinaryScanner::new()
                    .with_sink_catalogs(config.scanner.binary.sink_catalogs.clone())
                    .with_mitigations(config.scanner.binary.check_mitigations)
                    .with_rop(config.scanner.binary.find_rop_gadgets)
                    .with_max_file_size_mb(config.scanner.binary.max_file_size_mb);
                run_scanner("binary", scanner, target).await
            }
            "memory" if config.scanner.memory.enabled => {
                let scanner = vest_scanner::memory::MemoryScanner::new()
                    .with_max_memory(config.scanner.memory.max_memory_per_scan_mb)
                    .with_hook_detection(config.scanner.memory.hook_detection)
                    .with_simulation_allowed(allow_memory_simulation);
                run_scanner("memory", scanner, target).await
            }
            "network" if config.scanner.network.enabled => {
                let scanner = vest_scanner::network::NetworkScanner::new();
                run_scanner("network", scanner, target).await
            }
            #[cfg(feature = "browser")]
            "browser" if config.scanner.browser.enabled => {
                let scanner = vest_scanner::browser::BrowserScanner::new()
                    .with_storage(config.scanner.browser.local_storage_inspect)
                    .with_websockets(config.scanner.browser.websocket_intercept)
                    .with_wasm(config.scanner.browser.wasm_inspect);
                run_scanner("browser", scanner, target).await
            }
            "files" if config.scanner.files.enabled => {
                let f = &config.scanner.files;
                let limits = vest_scanner::files::FileTraversalLimits::from_config(
                    f.max_file_size_mb,
                    f.max_depth,
                    f.max_files,
                    f.max_total_bytes,
                    f.follow_symlinks,
                    f.ignore_globs.clone(),
                );
                let scanner = vest_scanner::files::FileScanner::new().with_limits(limits);
                run_scanner("files", scanner, target).await
            }
            disabled if known_scanner(disabled) => {
                ui_line!(
                    machine,
                    "\u{2502} Scanner off: {:<35} \u{2502}",
                    truncate_for_box(disabled, 35)
                );
                Ok(Vec::new())
            }
            unknown => Err(VestError::Config(format!("Unknown scanner: {}", unknown))),
        };

        match result {
            Ok(mut findings) => {
                ran_ok += 1;
                for finding in &mut findings {
                    mark_finding_source(finding, "scanner", Some(scanner_name));
                }
                ui_line!(
                    machine,
                    "\u{2502} {:<12} {:<28} \u{2502}",
                    scanner_name,
                    format!("{} finding(s)", findings.len())
                );
                all_findings.append(&mut findings);
            }
            Err(e) => {
                let msg = e.to_string();
                ui_line!(
                    machine,
                    "\u{2502} {:<12} {:<28} \u{2502}",
                    scanner_name,
                    truncate_for_box(&format!("failed: {}", msg), 28)
                );
                // Unsupported / config / IO failures are fatal for that scanner.
                fatal_errors.push(match e {
                    VestError::Config(m) => VestError::Config(format!("{scanner_name}: {m}")),
                    other => VestError::Scan(format!("{scanner_name}: {other}")),
                });
            }
        }
    }

    if ran_ok == 0 && !fatal_errors.is_empty() {
        return Err(scanner_failure_error(&fatal_errors));
    }

    Ok((all_findings, fatal_errors))
}

fn mark_finding_source(finding: &mut Finding, source: &str, scanner: Option<&str>) {
    if !finding.tags.iter().any(|tag| tag == source) {
        finding.tags.push(source.to_string());
    }
    if let Some(scanner) = scanner {
        let scanner_tag = format!("scanner:{}", scanner);
        if !finding.tags.iter().any(|tag| tag == &scanner_tag) {
            finding.tags.push(scanner_tag);
        }
    }

    let mut metadata = finding
        .metadata
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    metadata.insert("source".into(), serde_json::json!(source));
    if let Some(scanner) = scanner {
        metadata.insert("scanner".into(), serde_json::json!(scanner));
    }
    finding.metadata = serde_json::Value::Object(metadata);
}

async fn run_scanner<S: Scanner>(
    _name: &str,
    scanner: S,
    target: &Target,
) -> Result<Vec<Finding>, VestError> {
    scanner.scan(target).await
}

fn selected_scanners(
    args: &ScanArgs,
    config: &vest_config::VestConfig,
    target: &Target,
) -> Vec<String> {
    let from_args = normalize_scanner_names(args.scanner.iter().map(String::as_str));
    if !from_args.is_empty() {
        return from_args;
    }

    if let Some(profile) = args
        .profile
        .as_ref()
        .and_then(|name| config.profiles.get(name))
        .and_then(|p| p.scanners.as_ref())
    {
        let from_profile = normalize_scanner_names(profile.iter().map(String::as_str));
        if !from_profile.is_empty() {
            return from_profile;
        }
    }

    match target.target_type {
        TargetType::Web => vec!["web".into()],
        TargetType::Binary => vec!["binary".into()],
        TargetType::Process => vec!["memory".into()],
        TargetType::Network => vec!["network".into()],
        #[cfg(feature = "browser")]
        TargetType::Browser => vec!["browser".into()],
        #[cfg(not(feature = "browser"))]
        TargetType::Browser => vec![],
        TargetType::File => vec!["files".into()],
    }
}

fn normalize_scanner_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for name in names {
        let normalized = match name.trim().to_ascii_lowercase().as_str() {
            "" => continue,
            "file" => "files".to_string(),
            "fs" => "files".to_string(),
            other => other.to_string(),
        };
        seen.insert(normalized);
    }
    seen.into_iter().collect()
}

fn known_scanner(name: &str) -> bool {
    #[cfg(feature = "browser")]
    if name == "browser" {
        return true;
    }
    matches!(name, "web" | "binary" | "memory" | "network" | "files")
}

fn dedupe_findings(findings: &mut Vec<Finding>) {
    let mut seen = BTreeSet::new();
    findings.retain(|f| {
        let key = format!(
            "{}:{}:{}:{}",
            f.title, f.vulnerability_class, f.location, f.evidence
        );
        seen.insert(key)
    });
}

fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for finding in findings {
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    (critical, high, medium, low, info)
}

async fn render_report(
    format: &str,
    scan: &vest_core::types::ScanSession,
    findings: &[Finding],
    include_evidence: bool,
) -> Result<String, VestError> {
    match format {
        "json" => {
            vest_report::JsonReporter::new()
                .include_evidence(include_evidence)
                .generate_report(scan, findings)
                .await
        }
        "sarif" => {
            vest_report::SarifReporter::new()
                .generate_report(scan, findings)
                .await
        }
        "markdown" | "md" => {
            vest_report::MarkdownReporter::new()
                .include_evidence(include_evidence)
                .generate_report(scan, findings)
                .await
        }
        "terminal" | "text" => {
            vest_report::TerminalReporter
                .generate_report(scan, findings)
                .await
        }
        other => Err(VestError::Config(format!(
            "Unknown report format '{}'. Use json, sarif, markdown, or terminal.",
            other
        ))),
    }
}

fn truncate_for_box(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn build_tool_registry(
    session: Arc<ExecutionSession>,
    allow_active_probes: bool,
) -> vest_agent::ToolRegistry {
    let mut registry = vest_agent::ToolRegistry::new();
    let ro = vest_agent::context::RiskLevel::ReadOnly;

    let session_file = Arc::clone(&session);
    let session_mem = Arc::clone(&session);
    let session_http_get = Arc::clone(&session);
    let session_http_post = Arc::clone(&session);
    let session_read = Arc::clone(&session);
    let session_list = Arc::clone(&session);
    let session_browser = Arc::clone(&session);
    let _session_analyze = Arc::clone(&session);

    let session_web = Arc::clone(&session);
    registry.register(
        vest_agent::ToolDefinition {
            name: "web_scan".into(),
            description: "Perform a web vulnerability scan against a URL via WebScanner. Fetches the page (redirect-safe), parses links and forms, and runs misconfiguration detection. Active exposure probes (.env/.git) run only when two-key consent is present (allow via config/--allow-active-probes AND --confirm-active-probes or --approve-exploits).".into(),
            parameters: serde_json::json!({"url": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::ActiveNetworkProbe,
            egress_class: DataEgressClass::TargetContent,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("url parameter required")?;
            authorise_tool_url(&session_web, url)?;

            // Same gating as CLI web scan: default off unless config/flag opts in.
            let scanner = vest_scanner::web::WebScanner::new()
                .with_crawl_depth(5)
                .with_max_urls(100)
                .with_allow_active_probes(allow_active_probes)
                .with_deny_private_targets(session_web.network.deny_private_targets())
                .with_respect_robots_txt(true);

            let handle = tokio::runtime::Handle::current();
            let (page, config_findings) = tokio::task::block_in_place(|| {
                handle.block_on(async { scanner.inspect_url(url).await })
            })
            .map_err(|e| format!("web_scan failed: {e}"))?;

            let links = page.links.clone();
            let forms = page.forms.clone();
            let exposed: Vec<String> = config_findings
                .iter()
                .filter(|f| {
                    let t = f.title.to_lowercase();
                    t.contains("exposed .env")
                        || t.contains("exposed .git")
                        || t.contains(".env file")
                        || t.contains(".git directory")
                })
                .filter_map(|f| {
                    f.evidence
                        .get("url")
                        .and_then(|v| v.as_str())
                        .map(|u| u.to_string())
                })
                .collect();

            let finding_summaries: Vec<String> = config_findings
                .iter()
                .map(|f| format!("[{}] {}", f.severity.to_string().to_uppercase(), f.title))
                .collect();

            Ok(serde_json::json!({
                "url": url,
                "status": page.status,
                "links_found": links.len(),
                "forms_found": forms.len(),
                "forms": forms.iter().map(|f| serde_json::json!({
                    "action": f.action,
                    "inputs": f.inputs.iter().map(|(n, t)| format!("{n}:{t}")).collect::<Vec<_>>()
                })).collect::<Vec<_>>(),
                "exposed_resources": exposed,
                "security_issues": finding_summaries,
                "findings_count": config_findings.len(),
                "active_probes": allow_active_probes,
                "links": links.iter().take(30).collect::<Vec<_>>(),
            }))
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "file_scan".into(),
            description: "Scan a file path or directory for security issues. Checks for hardcoded secrets (API keys, passwords, tokens, private keys), backup/debug files, sensitive file exposure (.env, SSH keys, Docker configs, git internals), and suspicious file formats (executables, scripts). Returns detailed findings.".into(),
            parameters: serde_json::json!({"path": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::LocalFileContentRead,
            egress_class: DataEgressClass::LocalContent,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let path_str = args.get("path")
                .and_then(|v| v.as_str())
                .ok_or("path parameter required")?;
            let path = resolve_tool_path(&session_file, path_str)?;
            if !path.exists() {
                return Err(format!("Path not found: {}", path.display()));
            }

            let scanner = vest_scanner::files::FileScanner::new();
            let outcome = vest_scanner::files::collect_files_bounded(
                &path,
                &scanner.limits,
            )
            .map_err(|e| format!("Failed to collect files: {}", e))?;
            if outcome.truncated {
                tracing::warn!(
                    "file_scan traversal truncated: {:?}",
                    outcome.truncation_reason
                );
            }

            let mut all_findings = Vec::new();
            let mut scanned = 0usize;
            for file_path in &outcome.files {
                match scanner.scan_file(file_path) {
                    Ok(findings) => {
                        scanned += 1;
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to scan {}: {}", file_path.display(), e);
                    }
                }
            }

            let secrets_count = all_findings.iter().filter(|f| f.tags.iter().any(|t| t == "secret")).count();
            let backup_count = all_findings.iter().filter(|f| f.tags.iter().any(|t| t == "backup")).count();
            let sensitive_count = all_findings.iter().filter(|f| f.tags.iter().any(|t| t == "sensitive-file")).count();
            let format_count = all_findings.iter().filter(|f| f.tags.iter().any(|t| t == "file-type")).count();

            let summaries: Vec<serde_json::Value> = all_findings.iter().take(50).map(|f| {
                serde_json::json!({
                    "title": f.title,
                    "severity": f.severity.to_string(),
                    "confidence": f.confidence,
                })
            }).collect();

            Ok(serde_json::json!({
                "path": path.display().to_string(),
                "files_scanned": scanned,
                "total_files": outcome.files.len(),
                "total_findings": all_findings.len(),
                "secrets_found": secrets_count,
                "backup_files_found": backup_count,
                "sensitive_files_found": sensitive_count,
                "format_issues_found": format_count,
                "findings": summaries,
            }))
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "memory_scan".into(),
            description: "Scan process memory for RWX regions, hooks, and shellcode. Real OS acquisition is not implemented; without --allow-memory-simulation this returns unsupported. With the flag, results are explicitly tagged mode=simulation (fabricated, not from the PID).".into(),
            parameters: serde_json::json!({"pid": "integer"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::ProcessMemoryRead,
            egress_class: DataEgressClass::ProcessMemory,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let pid: u32 = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            if !session_mem.allow_memory_simulation {
                return Ok(serde_json::json!({
                    "mode": "unsupported",
                    "error": "Real process-memory acquisition is not implemented. Pass --allow-memory-simulation to run the explicit simulation harness (fabricated regions/bytes; not live PID memory).",
                    "pid": pid,
                }));
            }

            let platform = vest_scanner::memory::MemoryScanner::detect_platform();
            let regions = vest_scanner::memory::MemoryScanner::get_simulated_regions(platform);
            let suspicious_findings =
                vest_scanner::memory::MemoryScanner::check_suspicious_regions(&regions);

            let mut region_data: Vec<(&vest_scanner::memory::MemoryRegion, Vec<u8>)> = Vec::new();
            for region in &regions {
                if region.is_executable() {
                    let data = vest_scanner::memory::MemoryScanner::fabricate_simulated_memory(
                        region.base_address,
                        region.size.min(4096) as usize,
                    );
                    region_data.push((region, data));
                }
            }
            let hook_findings = vest_scanner::memory::MemoryScanner::detect_hooks(&region_data);

            Ok(serde_json::json!({
                "mode": "simulation",
                "warning": "SIMULATED data — not read from the requested PID",
                "platform": platform,
                "pid": pid,
                "total_regions": regions.len(),
                "total_findings": suspicious_findings.len() + hook_findings.len(),
                "regions": regions.iter().map(|r| serde_json::json!({
                    "name": r.name,
                    "base_address": format!("0x{:x}", r.base_address),
                    "size": r.size,
                    "permissions": r.permissions,
                    "module": r.module_name,
                    "is_executable": r.is_executable(),
                    "is_writable": r.is_writable(),
                    "is_rwx": r.is_rwx(),
                })).collect::<Vec<_>>(),
                "suspicious_region_findings": suspicious_findings.iter().map(|f| {
                    serde_json::json!({"title": f.title, "severity": f.severity.to_string()})
                }).collect::<Vec<_>>(),
                "hook_and_shellcode_findings": hook_findings.iter().map(|f| {
                    serde_json::json!({"title": f.title, "severity": f.severity.to_string()})
                }).collect::<Vec<_>>(),
            }))
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "http_get".into(),
            description: "Make an HTTP GET request to a URL. Returns status code and response body (truncated at 8KB). Use as fallback for raw HTTP requests when web_scan doesn't cover your needs.".into(),
            parameters: serde_json::json!({"url": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::PassiveNetworkRequest,
            egress_class: DataEgressClass::TargetContent,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("url parameter required")?;
            agent_http_get(&session_http_get, url)
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "http_post".into(),
            description: "Make an HTTP POST request with JSON data. Returns status code and response body (truncated at 4KB).".into(),
            parameters: serde_json::json!({"url": "string", "data": "object"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::StateChangingNetworkRequest,
            egress_class: DataEgressClass::TargetContent,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("url parameter required")?;
            let data = args.get("data").cloned().unwrap_or(serde_json::json!({}));
            agent_http_post(&session_http_post, url, &data)
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "read_file".into(),
            description: "Read a file from disk. Returns contents up to 10KB.".into(),
            parameters: serde_json::json!({"path": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::LocalFileContentRead,
            egress_class: DataEgressClass::LocalContent,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("path parameter required")?;
            agent_read_file(&session_read, path)
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "list_files".into(),
            description: "List files in a directory".into(),
            parameters: serde_json::json!({"path": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::LocalMetadataRead,
            egress_class: DataEgressClass::LocalMetadata,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let resolved = resolve_tool_path(&session_list, path)?;
            let entries: Vec<String> = std::fs::read_dir(&resolved)
                .map_err(|e| format!("Cannot read directory: {}", e))?
                .filter_map(|e| e.ok())
                .map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    if is_dir {
                        format!("{}/", name)
                    } else {
                        name
                    }
                })
                .collect();
            Ok(serde_json::json!({
                "path": resolved.display().to_string(),
                "entries": entries,
                "count": entries.len(),
            }))
        },
    );

    #[cfg(feature = "browser")]
    registry.register(
        vest_agent::ToolDefinition {
            name: "browser_inspect".into(),
            description: "Inspect a web page using Chrome DevTools Protocol (navigates the page; treated as an active network probe requiring approval). Extracts localStorage, sessionStorage, WebSocket URLs, WASM modules, security headers, and inline scripts. Requires Chrome on loopback with --remote-debugging-port=9222; non-loopback CDP websocket URLs are refused.".into(),
            parameters: serde_json::json!({"url": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::ActiveNetworkProbe,
            egress_class: DataEgressClass::TargetContent,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let url = args.get("url")
                .and_then(|v| v.as_str())
                .ok_or("url parameter required")?;
            authorise_tool_url(&session_browser, url)?;
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| {
                handle.block_on(vest_scanner::browser::BrowserScanner::inspect_page(url))
            })
        },
    );

    registry.register(
        vest_agent::ToolDefinition {
            name: "scan_for_secrets".into(),
            description: "Scan a file or text content for hardcoded secrets (API keys, passwords, tokens, private keys).".into(),
            parameters: serde_json::json!({"content": "string", "source": "string"}),
            requires_approval: false,
            risk_level: ro,
            effect: ToolEffect::LocalFileContentRead,
            egress_class: DataEgressClass::PotentiallySecretBearing,
        },
        move |args: serde_json::Value| -> Result<serde_json::Value, String> {
            let content = args.get("content")
                .and_then(|v| v.as_str())
                .ok_or("content parameter required")?;
            let source = args.get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("inline");
            let path = std::path::Path::new(source);
            let scanner = vest_scanner::files::FileScanner::new();
            let findings = scanner.scan_for_secrets(path, content);
            let result: Vec<serde_json::Value> = findings.iter().map(|f| {
                serde_json::json!({
                    "title": f.title,
                    "severity": f.severity.to_string(),
                    "confidence": f.confidence,
                    "location": serde_json::to_string(&f.location).unwrap_or_default(),
                })
            }).collect();
            Ok(serde_json::json!({
                "source": source,
                "findings_count": result.len(),
                "findings": result,
            }))
        },
    );

    registry
}

fn format_fs_scope(scope: &ApprovedFilesystemScope) -> String {
    let roots = scope.roots();
    if roots.is_empty() {
        "(none)".to_string()
    } else {
        roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn format_net_scope(scope: &ApprovedNetworkScope) -> String {
    let origins = scope.origins();
    if origins.is_empty() {
        "(none)".to_string()
    } else {
        origins
            .iter()
            .map(|o| format!("{}://{}:{}", o.scheme, o.host, o.port))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn scopes_from_target(target: &Target) -> (ApprovedFilesystemScope, ApprovedNetworkScope) {
    let fs = match (&target.path, target.target_type) {
        (Some(path), _) => {
            let p = PathBuf::from(path);
            let root = if p.is_file() {
                p.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."))
            } else {
                p
            };
            ApprovedFilesystemScope::new([root])
                .unwrap_or_else(|_| ApprovedFilesystemScope::empty())
        }
        (None, TargetType::File | TargetType::Binary) => {
            let p = PathBuf::from(&target.name);
            let root = if p.is_file() {
                p.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."))
            } else {
                p
            };
            ApprovedFilesystemScope::new([root])
                .unwrap_or_else(|_| ApprovedFilesystemScope::empty())
        }
        _ => ApprovedFilesystemScope::empty(),
    };

    let net = if let Some(ref url) = target.url_str {
        ApprovedNetworkScope::new([url.as_str()]).unwrap_or_else(|_| ApprovedNetworkScope::empty())
    } else {
        ApprovedNetworkScope::empty()
    };

    (fs, net)
}

/// Merge optional profile `safety` overrides onto base `[safety]` approval flags.
/// Only `Some` fields override; unset profile fields keep the base value.
fn merge_profile_safety_approvals(
    base_write: bool,
    base_exploit: bool,
    profile: Option<&vest_config::ProfileConfig>,
) -> (bool, bool) {
    let over = profile.and_then(|p| p.safety.as_ref());
    (
        over.and_then(|s| s.write_approval).unwrap_or(base_write),
        over.and_then(|s| s.exploit_approval)
            .unwrap_or(base_exploit),
    )
}

async fn build_safety(
    args: &ScanArgs,
    config: &vest_config::VestConfig,
    profile: Option<&vest_config::ProfileConfig>,
    session: Arc<ExecutionSession>,
) -> Result<Arc<vest_agent::SafetyChecker>, Box<dyn std::error::Error>> {
    use vest_agent::safety::SafetyConfig;

    let (write_approval, exploit_approval) = merge_profile_safety_approvals(
        config.safety.write_approval,
        config.safety.exploit_approval,
        profile,
    );

    // `--no-approval` means: never prompt; deny approval-required ops.
    // It must NOT install an unrestricted / test-only permissive context (K1).
    let safety_config = SafetyConfig {
        write_approval,
        exploit_approval,
        network_write_approval: config.safety.network_write_approval,
        rate_limit_enabled: !args.no_rate_limit && config.safety.rate_limit_enabled,
        rate_limit_requests_per_second: args
            .rate
            .unwrap_or(config.safety.rate_limit_requests_per_second),
        rate_limit_burst: config.safety.rate_limit_burst,
        sandbox_enabled: config.safety.sandbox_enabled,
        sandbox_image: config.safety.sandbox_image.clone(),
        max_scan_duration_seconds: args
            .timeout
            .unwrap_or(config.safety.max_scan_duration_seconds),
        max_concurrent_exploits: config.safety.max_concurrent_exploits,
        allowed_targets: config.safety.allowed_targets.clone(),
        blocked_targets: config.safety.blocked_targets.clone(),
        allowed_networks: config.safety.allowed_networks.clone(),
        deny_private_targets: config.safety.deny_private_targets,
    };

    let mut explicit_effects = Vec::with_capacity(args.approve_effect.len());
    for raw in &args.approve_effect {
        let effect: ToolEffect = raw.parse().map_err(VestError::Config)?;
        if effect.is_unknown() {
            return Err(VestError::Config(
                "unknown tool effect 'unknown' cannot be pre-granted".into(),
            )
            .into());
        }
        explicit_effects.push(effect);
    }

    let checker = Arc::new(vest_agent::SafetyChecker::new(safety_config));
    checker
        .set_authorisation_context(session.authorisation_context())
        .await;
    for effect in cli_pregrant_effects(
        args.approve_writes,
        args.approve_exploits,
        &explicit_effects,
    ) {
        checker.grant_effect_session(effect).await;
    }
    Ok(checker)
}

fn deny_private_scan_target(target: &Target) -> Result<(), VestError> {
    let candidates = [
        target.url_str.as_deref(),
        target.host.as_deref(),
        Some(target.name.as_str()),
    ];
    for c in candidates.into_iter().flatten() {
        if is_private_or_metadata_target(c) {
            return Err(VestError::InvalidInput(format!(
                "Target '{c}' is loopback/private/link-local/metadata; refused because safety.deny_private_targets=true"
            )));
        }
    }
    Ok(())
}

/// Print `[profiles.*]` from config with short notes (C4 discoverability).
fn print_known_profiles(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = if config_path.exists() {
        vest_config::load_config(config_path).map_err(|e| {
            VestError::Config(format!(
                "Failed to load config {}: {e}. Refusing silent defaults for a present file.",
                config_path.display()
            ))
        })?
    } else {
        eprintln!(
            "No config at {}; using built-in defaults (no profiles).",
            config_path.display()
        );
        vest_config::default_config()
    };

    if config.profiles.is_empty() {
        println!("No scan profiles defined in {}.", config_path.display());
        println!(
            "Add [profiles.<name>] sections (optional description = \"...\") to list them here."
        );
        println!("Use: vest scan <TARGET> --profile <name>");
        return Ok(());
    }

    println!("Known scan profiles (from {}):", config_path.display());
    println!();
    let mut names: Vec<_> = config.profiles.keys().cloned().collect();
    names.sort();
    let width = names.iter().map(|n| n.len()).max().unwrap_or(8).max(8);
    for name in &names {
        let note = format_profile_note(&config.profiles[name]);
        println!("  {name:<width$}  {note}");
    }
    println!();
    println!("Use: vest scan <TARGET> --profile <name>");
    Ok(())
}

fn format_profile_note(profile: &vest_config::ProfileConfig) -> String {
    if let Some(ref description) = profile.description {
        let trimmed = description.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let mut parts = Vec::new();
    if let Some(ref pattern) = profile.pattern {
        parts.push(format!("pattern={pattern}"));
    }
    if let Some(ref scanners) = profile.scanners {
        if !scanners.is_empty() {
            parts.push(format!("scanners={}", scanners.join(",")));
        }
    }
    if parts.is_empty() {
        "(no description)".to_string()
    } else {
        parts.join("; ")
    }
}

fn detect_target(args: &ScanArgs) -> Result<Target, VestError> {
    let name = args
        .target
        .as_deref()
        .ok_or_else(|| VestError::InvalidInput("TARGET is required".into()))?;
    let now = chrono::Utc::now();

    let target_type = if let Some(ref tt) = args.target_type {
        tt.parse::<TargetType>().map_err(|_| {
            VestError::InvalidInput(format!(
                "Invalid target type '{tt}'. Expected one of: process, binary, web, network, browser, file"
            ))
        })?
    } else {
        guess_type(name)
    };

    let (path, url_str, pid, host) = match target_type {
        TargetType::Process => {
            let pid_val = args.pid.or_else(|| name.parse().ok());
            (None, None, pid_val, None)
        }
        TargetType::Binary => (Some(name.to_string()), None, None, None),
        TargetType::Web => resolve_http_target(name)?,
        TargetType::Network => (None, None, None, Some(name.to_string())),
        TargetType::Browser => resolve_http_target(name)?,
        TargetType::File => (Some(name.to_string()), None, None, None),
    };

    Ok(Target {
        id: vest_core::ids::new_id(),
        name: name.to_string(),
        target_type,
        path,
        url_str,
        pid,
        host,
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    })
}

type TargetFields = (Option<String>, Option<String>, Option<u32>, Option<String>);

/// Web/browser targets accept only `http`/`https`. Bare hosts become `https://host`.
/// Schemes like `file:`, `javascript:`, or `data:` fail closed (never rewritten).
fn resolve_http_target(name: &str) -> Result<TargetFields, VestError> {
    if let Some((scheme, _rest)) = name.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(VestError::InvalidInput(format!(
                "Invalid web target URL scheme '{scheme}' (only http/https). Refusing to rewrite '{name}'."
            )));
        }
        return Ok((None, Some(name.to_string()), None, None));
    }
    Ok((
        None,
        Some(format!("https://{name}")),
        None,
        Some(name.to_string()),
    ))
}

fn guess_type(name: &str) -> TargetType {
    let path = std::path::Path::new(name);
    if path.exists() {
        if name.ends_with(".exe")
            || name.ends_with(".dll")
            || name.ends_with(".so")
            || name.ends_with(".elf")
            || name.ends_with(".mach")
        {
            TargetType::Binary
        } else {
            TargetType::File
        }
    } else if name.contains("://")
        || (name.contains('.')
            && !name.contains('/')
            && !name.contains('\\')
            && !name.contains(' '))
    {
        TargetType::Web
    } else if name.ends_with(".exe")
        || name.ends_with(".dll")
        || name.ends_with(".so")
        || name.ends_with(".elf")
        || name.ends_with(".mach")
    {
        TargetType::Binary
    } else if name.parse::<u32>().is_ok() {
        TargetType::Process
    } else if name.contains(':') {
        TargetType::Network
    } else {
        TargetType::File
    }
}

fn get_db_path() -> String {
    if let Ok(path) = std::env::var("VEST_DB_PATH") {
        return path;
    }
    if let Ok(dir) = std::env::var("VEST_HOME") {
        std::fs::create_dir_all(&dir).ok();
        return format!("{}/vest.db", dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = format!("{}/.vest", home);
    std::fs::create_dir_all(&dir).ok();
    format!("{}/vest.db", dir)
}

#[cfg(test)]
#[path = "agent_http_scoped_client.rs"]
mod agent_http_scoped_client;

#[cfg(test)]
#[path = "agent_read_file_bounded.rs"]
mod agent_read_file_bounded;

#[cfg(test)]
mod profile_safety_tests {
    use super::merge_profile_safety_approvals;
    use vest_config::{ProfileConfig, ProfileSafetyOverride};

    fn profile_with_safety(write: Option<bool>, exploit: Option<bool>) -> ProfileConfig {
        ProfileConfig {
            description: None,
            pattern: None,
            phases: None,
            agents: None,
            scanners: None,
            max_llm_iterations: None,
            token_budget_per_scan: None,
            safety: Some(ProfileSafetyOverride {
                write_approval: write,
                exploit_approval: exploit,
            }),
        }
    }

    #[test]
    fn no_profile_keeps_base_approvals() {
        assert_eq!(
            merge_profile_safety_approvals(true, true, None),
            (true, true)
        );
        assert_eq!(
            merge_profile_safety_approvals(false, true, None),
            (false, true)
        );
    }

    #[test]
    fn profile_without_safety_keeps_base() {
        let profile = ProfileConfig {
            description: None,
            pattern: None,
            phases: None,
            agents: None,
            scanners: None,
            max_llm_iterations: None,
            token_budget_per_scan: None,
            safety: None,
        };
        assert_eq!(
            merge_profile_safety_approvals(true, true, Some(&profile)),
            (true, true)
        );
    }

    #[test]
    fn profile_overrides_both_approval_flags() {
        // Matches vest.toml [profiles.bug_bounty] intent: disable approvals.
        let profile = profile_with_safety(Some(false), Some(false));
        assert_eq!(
            merge_profile_safety_approvals(true, true, Some(&profile)),
            (false, false)
        );
    }

    #[test]
    fn partial_override_leaves_unset_field() {
        let write_only = profile_with_safety(Some(false), None);
        assert_eq!(
            merge_profile_safety_approvals(true, true, Some(&write_only)),
            (false, true)
        );
        let exploit_only = profile_with_safety(None, Some(false));
        assert_eq!(
            merge_profile_safety_approvals(true, true, Some(&exploit_only)),
            (true, false)
        );
    }
}

#[cfg(test)]
mod ci_gate_tests {
    use super::*;
    use chrono::Utc;
    use vest_core::types::{FindingStatus, VulnerabilityClass};

    fn finding(title: &str, severity: Severity) -> Finding {
        let now = Utc::now();
        Finding {
            id: vest_core::ids::new_id(),
            scan_id: "s".into(),
            target_id: "t".into(),
            title: title.into(),
            description: String::new(),
            vulnerability_class: VulnerabilityClass::HardcodedCredentials,
            severity,
            confidence: 0.9,
            status: FindingStatus::Open,
            severity_score_estimate: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn parse_fail_on_severity_accepts_levels() {
        assert_eq!(
            parse_fail_on_severity(Some("high")).unwrap(),
            Some(Severity::High)
        );
        assert_eq!(
            parse_fail_on_severity(Some("CRITICAL")).unwrap(),
            Some(Severity::Critical)
        );
        assert!(parse_fail_on_severity(Some("extreme")).is_err());
    }

    #[test]
    fn severity_threshold_includes_equal_and_above() {
        assert!(severity_meets_threshold(Severity::High, Severity::High));
        assert!(severity_meets_threshold(Severity::Critical, Severity::High));
        assert!(!severity_meets_threshold(Severity::Medium, Severity::High));
    }

    #[test]
    fn new_finding_titles_detects_additions_only() {
        let previous = vec![finding("Hardcoded password", Severity::Critical)];
        let current = vec![
            finding("Hardcoded password", Severity::Critical),
            finding("AWS access key", Severity::Critical),
        ];
        assert_eq!(
            new_finding_titles(&current, &previous),
            vec!["AWS access key".to_string()]
        );
    }
}
