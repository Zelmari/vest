//! Agent tool registry and handlers used by `vest scan`.
//!
//! Extracted from `scan.rs` (D1) so scan orchestration stays separate from
//! tool definitions and session-scoped HTTP/FS helpers.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vest_agent::{resolve_read_path, ExecutionSession, ToolError};
use vest_core::error::VestError;
use vest_core::{truncate_chars, DataEgressClass, ToolEffect};
use vest_scanner::{HttpClientBudgets, ScopedHttpClient};

/// Hard cap for agent `read_file`: never absorb more than this many bytes.
/// Matches the tool description ("up to 10KB").
const AGENT_READ_FILE_MAX_BYTES: u64 = 10_240;

fn resolve_tool_path(session: &ExecutionSession, path: &str) -> Result<PathBuf, ToolError> {
    resolve_read_path(&session.filesystem, Path::new(path))
        .map_err(|e| VestError::ApprovalDenied(format!("filesystem scope: {e}")).into())
}

fn authorise_tool_url(session: &ExecutionSession, url: &str) -> Result<(), ToolError> {
    session
        .network
        .authorise_url(url)
        .map(|_| ())
        .map_err(|e| VestError::ApprovalDenied(format!("network scope: {e}")).into())
}

/// Build a [`ScopedHttpClient`] bound to the authorised origin of `url`.
///
/// Initial URL must pass the session network scope; redirects are re-authorised
/// against that same origin by ScopedHttpClient (fail-closed on escape).
fn scoped_client_for_url(
    session: &ExecutionSession,
    url: &str,
    max_body_bytes: usize,
) -> Result<ScopedHttpClient, ToolError> {
    let authorised = session
        .network
        .authorise_url(url)
        .map_err(|e| VestError::ApprovalDenied(format!("network scope: {e}")))?;
    let scope = vest_scanner::web::NetworkScope::from_url(&authorised)
        .map_err(|e| ToolError::client(format!("network scope: {e}")))?;
    let budgets = HttpClientBudgets {
        max_body_bytes,
        ..HttpClientBudgets::default()
    };
    ScopedHttpClient::try_new(scope, budgets)
        .map(|c| c.with_deny_private_targets(session.network.deny_private_targets()))
        .map_err(ToolError::from)
}

fn block_on_scoped<F, T>(fut: F) -> Result<T, ToolError>
where
    F: std::future::Future<Output = Result<T, VestError>>,
{
    let handle = tokio::runtime::Handle::current();
    // Preserve VestError variants (do not stringify) for CLI exit mapping.
    tokio::task::block_in_place(|| handle.block_on(fut)).map_err(ToolError::from)
}

/// Agent `http_get` implementation (session-scoped, redirect-safe).
fn agent_http_get(session: &ExecutionSession, url: &str) -> Result<serde_json::Value, ToolError> {
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
) -> Result<serde_json::Value, ToolError> {
    let client = scoped_client_for_url(session, url, 4_096)?;
    let body_str = serde_json::to_string(data)
        .map_err(|e| ToolError::client(format!("Failed to serialize: {e}")))?;
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
fn read_file_capped(path: &Path) -> Result<serde_json::Value, ToolError> {
    let meta =
        std::fs::metadata(path).map_err(|e| ToolError::io(format!("Cannot read file: {e}")))?;
    let mut file =
        std::fs::File::open(path).map_err(|e| ToolError::io(format!("Cannot read file: {e}")))?;
    let mut buf = Vec::with_capacity(AGENT_READ_FILE_MAX_BYTES as usize);
    file.by_ref()
        .take(AGENT_READ_FILE_MAX_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| ToolError::io(format!("Cannot read file: {e}")))?;
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
fn agent_read_file(session: &ExecutionSession, path: &str) -> Result<serde_json::Value, ToolError> {
    let resolved = resolve_tool_path(session, path)?;
    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| {
        handle.block_on(async move {
            tokio::task::spawn_blocking(move || read_file_capped(&resolved))
                .await
                .map_err(|e| ToolError::io(format!("read_file task failed: {e}")))?
        })
    })
}

pub(crate) fn build_tool_registry(
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("url parameter required"))?;
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
            .map_err(|e| ToolError::client(format!("web_scan failed: {e}")))?;

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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let path_str = args.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("path parameter required"))?;
            let path = resolve_tool_path(&session_file, path_str)?;
            if !path.exists() {
                return Err(ToolError::path_not_found(format!(
                    "Path not found: {}",
                    path.display()
                )));
            }

            let scanner = vest_scanner::files::FileScanner::new();
            let outcome = vest_scanner::files::collect_files_bounded(
                &path,
                &scanner.limits,
            )
            .map_err(|e| ToolError::io(format!("Failed to collect files: {}", e)))?;
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("url parameter required"))?;
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("url parameter required"))?;
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("path parameter required"))?;
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let resolved = resolve_tool_path(&session_list, path)?;
            let entries: Vec<String> = std::fs::read_dir(&resolved)
                .map_err(|e| ToolError::io(format!("Cannot read directory: {}", e)))?
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let url = args.get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("url parameter required"))?;
            authorise_tool_url(&session_browser, url)?;
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| {
                handle.block_on(vest_scanner::browser::BrowserScanner::inspect_page(url))
            })
            .map_err(ToolError::from)
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
        move |args: serde_json::Value| -> Result<serde_json::Value, ToolError> {
            let content = args.get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::missing_parameter("content parameter required"))?;
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

#[cfg(test)]
#[path = "agent_http_scoped_client.rs"]
mod agent_http_scoped_client;

#[cfg(test)]
#[path = "agent_read_file_bounded.rs"]
mod agent_read_file_bounded;
