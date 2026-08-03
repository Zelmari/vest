//! Nuclei subprocess wrapper (NUC-1 / B4).
//!
//! Binary resolution order (cwd-relative paths are never used):
//! 1. Absolute `~/.vest/tools/nuclei` when that file exists
//! 2. Absolute path from `which nuclei` on `PATH`
//!
//! Every scan always passes `-t` constrained to the allowlisted templates root
//! (`~/.vest/tools/nuclei-templates` by default). An empty template list uses
//! that root itself; if the root cannot be resolved, the scan fails closed.
//! Invocations also pass `-disable-update-check` so nuclei does not auto-update.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Default wall-clock timeout for nuclei subprocesses (matches `scanner.nuclei_timeout`).
pub const DEFAULT_NUCLEI_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Deserialize, Clone)]
pub struct NucleiFinding {
    #[serde(rename = "templateID", alias = "template-id")]
    pub template_id: String,
    pub name: String,
    pub severity: String,
    #[serde(rename = "matchedAt", alias = "matched-at")]
    pub matched_at: String,
    pub description: Option<String>,
}

impl std::fmt::Display for NucleiFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} — {} (matched at: {})",
            self.severity.to_uppercase(),
            self.template_id,
            self.name,
            self.matched_at
        )?;
        if let Some(ref desc) = self.description {
            if !desc.is_empty() {
                write!(f, " — {}", desc)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NucleiTool {
    binary_path: PathBuf,
    timeout: Duration,
    templates_root: PathBuf,
    /// When non-empty, passed as nuclei `-severity` (comma-separated).
    severity_filter: Vec<String>,
}

impl NucleiTool {
    pub fn new() -> Option<Self> {
        Self::find_binary().map(|binary_path| Self {
            binary_path,
            timeout: Duration::from_secs(DEFAULT_NUCLEI_TIMEOUT_SECS),
            templates_root: default_templates_root(),
            severity_filter: Vec::new(),
        })
    }

    /// Construct with an explicit absolute binary path (tests / advanced use).
    pub fn with_binary(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            timeout: Duration::from_secs(DEFAULT_NUCLEI_TIMEOUT_SECS),
            templates_root: default_templates_root(),
            severity_filter: Vec::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_templates_root(mut self, root: PathBuf) -> Self {
        self.templates_root = root;
        self
    }

    pub fn with_severity_filter(mut self, severities: impl IntoIterator<Item = String>) -> Self {
        self.severity_filter = severities
            .into_iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        self
    }

    pub fn check_installed() -> bool {
        Self::find_binary().is_some()
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub fn templates_root(&self) -> &Path {
        &self.templates_root
    }

    /// Resolve nuclei binary: `~/.vest/tools/nuclei`, then absolute PATH entry.
    /// Never returns a cwd-relative path such as `./nuclei-templates/nuclei`.
    fn find_binary() -> Option<PathBuf> {
        if let Some(path) = vest_tools_nuclei_path() {
            if path.is_file() {
                return Some(path);
            }
        }

        which_absolute("nuclei")
    }

    pub fn scan_url(
        &self,
        url: &str,
        templates: &[&str],
    ) -> Result<Vec<NucleiFinding>, NucleiError> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-u")
            .arg(url)
            .arg("-json")
            .arg("-silent")
            .arg("-disable-update-check");

        if !self.severity_filter.is_empty() {
            cmd.arg("-severity").arg(self.severity_filter.join(","));
        }

        // B4: never omit `-t` (unconstrained nuclei defaults). Empty list ⇒ root.
        let template_arg = self.constrained_template_arg(templates)?;
        cmd.arg("-t").arg(template_arg);

        let output = run_with_timeout(cmd, self.timeout)?;
        ensure_success(&output)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(finding) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Build the `-t` value: allowlisted paths, or the allowlisted root when empty.
    fn constrained_template_arg(&self, templates: &[&str]) -> Result<String, NucleiError> {
        if templates.is_empty() {
            let root = self.canonical_templates_root()?;
            return Ok(root.to_string_lossy().into_owned());
        }
        let allowed = self.resolve_allowed_templates(templates)?;
        Ok(allowed
            .iter()
            .map(|p| p.to_string_lossy())
            .collect::<Vec<_>>()
            .join(","))
    }

    fn canonical_templates_root(&self) -> Result<PathBuf, NucleiError> {
        self.templates_root.canonicalize().map_err(|e| {
            NucleiError::TemplatesRootInvalid(format!("{}: {e}", self.templates_root.display()))
        })
    }

    pub fn scan_url_with_all_templates(
        &self,
        url: &str,
    ) -> Result<Vec<NucleiFinding>, NucleiError> {
        self.scan_url(url, &[])
    }

    pub fn version(&self) -> Result<String, NucleiError> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-version");
        let output = run_with_timeout(cmd, self.timeout)?;
        ensure_success(&output)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", stdout.trim(), stderr.trim());

        Ok(combined.lines().next().unwrap_or("").to_string())
    }

    fn resolve_allowed_templates(&self, templates: &[&str]) -> Result<Vec<PathBuf>, NucleiError> {
        let root = self.canonical_templates_root()?;

        let mut out = Vec::with_capacity(templates.len());
        for template in templates {
            out.push(resolve_template_under_root(Path::new(template), &root)?);
        }
        Ok(out)
    }
}

fn default_templates_root() -> PathBuf {
    match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(".vest/tools/nuclei-templates"),
        Err(_) => PathBuf::from("/nonexistent/.vest/tools/nuclei-templates"),
    }
}

fn vest_tools_nuclei_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".vest/tools/nuclei"))
}

/// Return an absolute path to `name` via `which`, or `None`.
fn which_absolute(name: &str) -> Option<PathBuf> {
    let output = Command::new("which")
        .arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }
    let path = PathBuf::from(path);
    if path.is_absolute() && path.is_file() {
        Some(path)
    } else {
        None
    }
}

fn resolve_template_under_root(template: &Path, root: &Path) -> Result<PathBuf, NucleiError> {
    let candidate = if template.is_absolute() {
        template.to_path_buf()
    } else {
        root.join(template)
    };

    let canonical = candidate.canonicalize().map_err(|_| {
        NucleiError::TemplateNotAllowed(format!(
            "{} (must exist under {})",
            template.display(),
            root.display()
        ))
    })?;

    if !canonical.starts_with(root) {
        return Err(NucleiError::TemplateNotAllowed(format!(
            "{} resolves outside allowlisted root {}",
            template.display(),
            root.display()
        )));
    }

    Ok(canonical)
}

fn ensure_success(output: &Output) -> Result<(), NucleiError> {
    if output.status.success() {
        return Ok(());
    }
    let code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(NucleiError::ProcessFailed { code, stderr })
}

/// Spawn `cmd`, kill it if it exceeds `timeout`, and return its output.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<Output, NucleiError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd
        .spawn()
        .map_err(|e| NucleiError::ExecutionError(e.to_string()))?;

    let pid = child.id();
    let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
    let timed_out = std::sync::Arc::new(AtomicBool::new(false));
    let timed_out_flag = std::sync::Arc::clone(&timed_out);

    let killer = thread::spawn(move || match cancel_rx.recv_timeout(timeout) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            force_kill(pid);
            timed_out_flag.store(true, Ordering::SeqCst);
        }
    });

    let output = child
        .wait_with_output()
        .map_err(|e| NucleiError::ExecutionError(e.to_string()));
    let _ = cancel_tx.send(());
    let _ = killer.join();

    let output = output?;
    if timed_out.load(Ordering::SeqCst) {
        return Err(NucleiError::Timeout(timeout));
    }
    Ok(output)
}

fn force_kill(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NucleiError {
    #[error("execution error: {0}")]
    ExecutionError(String),
    #[error("nuclei exited with status {code:?}: {stderr}")]
    ProcessFailed { code: Option<i32>, stderr: String },
    #[error("nuclei timed out after {0:?}")]
    Timeout(Duration),
    #[error("template path not allowlisted: {0}")]
    TemplateNotAllowed(String),
    #[error("templates root invalid: {0}")]
    TemplatesRootInvalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vest-nuclei-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body).unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn test_nuclei_finding_deserialize_v2_kebab_case() {
        let json = r#"{"template-id":"http-missing-security-headers","name":"Missing Security Headers","severity":"info","matched-at":"http://example.com","description":"Some missing headers"}"#;
        let finding: NucleiFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.template_id, "http-missing-security-headers");
        assert_eq!(finding.name, "Missing Security Headers");
        assert_eq!(finding.severity, "info");
        assert_eq!(finding.matched_at, "http://example.com");
        assert_eq!(finding.description, Some("Some missing headers".into()));
    }

    #[test]
    fn test_nuclei_finding_deserialize_v3_camel_case() {
        let json = r#"{"templateID":"xss-reflected","name":"Reflected XSS","severity":"medium","matchedAt":"http://example.com/search?q=test","description":null}"#;
        let finding: NucleiFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.template_id, "xss-reflected");
        assert_eq!(finding.name, "Reflected XSS");
        assert_eq!(finding.severity, "medium");
        assert_eq!(finding.matched_at, "http://example.com/search?q=test");
        assert!(finding.description.is_none());
    }

    #[test]
    fn test_nuclei_finding_deserialize_minimal() {
        let json = r#"{"templateID":"cve-2021-44228","name":"Log4j RCE","severity":"critical","matchedAt":"http://target.com"}"#;
        let finding: NucleiFinding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.template_id, "cve-2021-44228");
        assert_eq!(finding.severity, "critical");
        assert!(finding.description.is_none());
    }

    #[test]
    fn test_nuclei_finding_deserialize_invalid_json() {
        let json = r#"not json"#;
        let result = serde_json::from_str::<NucleiFinding>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_nuclei_finding_deserialize_missing_required_fields() {
        let json = r#"{"name":"test"}"#;
        let result = serde_json::from_str::<NucleiFinding>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_nuclei_finding_display() {
        let finding = NucleiFinding {
            template_id: "test-template".into(),
            name: "Test Finding".into(),
            severity: "high".into(),
            matched_at: "http://example.com".into(),
            description: Some("A test vulnerability".into()),
        };
        let display = format!("{}", finding);
        assert!(display.contains("[HIGH]"));
        assert!(display.contains("test-template"));
        assert!(display.contains("Test Finding"));
        assert!(display.contains("http://example.com"));
        assert!(display.contains("A test vulnerability"));
    }

    #[test]
    fn test_nuclei_finding_display_no_description() {
        let finding = NucleiFinding {
            template_id: "test-template".into(),
            name: "Test Finding".into(),
            severity: "low".into(),
            matched_at: "http://example.com".into(),
            description: None,
        };
        let display = format!("{}", finding);
        assert!(display.contains("[LOW]"));
        assert!(!display.contains(" —  — "));
    }

    #[test]
    fn test_nuclei_finding_display_empty_description() {
        let finding = NucleiFinding {
            template_id: "test-template".into(),
            name: "Test Finding".into(),
            severity: "medium".into(),
            matched_at: "http://example.com".into(),
            description: Some("".into()),
        };
        let display = format!("{}", finding);
        assert!(display.contains("[MEDIUM]"));
    }

    #[test]
    fn test_nuclei_tool_find_binary_path_not_installed() {
        let path = std::env::var("HOME").ok().map(|h| {
            std::path::PathBuf::from(&h).join(".vest/tools/nuclei-non-existent-binary-xyz")
        });
        assert!(path.is_none() || !path.as_ref().unwrap().exists());
    }

    #[test]
    fn test_find_binary_returns_only_absolute_paths() {
        // NUC-1: never resolve cwd-relative hijacks like ./nuclei-templates/nuclei.
        if let Some(path) = NucleiTool::find_binary() {
            assert!(
                path.is_absolute(),
                "resolved binary must be absolute, got {}",
                path.display()
            );
            let s = path.to_string_lossy();
            assert!(
                !s.starts_with("./") && !s.contains("/./nuclei-templates/"),
                "cwd-relative hijack path must not be returned: {s}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_fake_binary_scan_parses_findings_and_checks_exit_zero() {
        let dir = temp_dir("ok");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            r#"#!/bin/sh
echo '{"templateID":"vuln-1","name":"First","severity":"high","matchedAt":"http://example.com"}'
exit 0
"#,
        );

        let tool = NucleiTool::with_binary(bin)
            .with_timeout(Duration::from_secs(5))
            .with_templates_root(dir.clone());
        let findings = tool.scan_url("http://example.com", &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "vuln-1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_fake_binary_nonzero_exit_is_error() {
        let dir = temp_dir("fail");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            r#"#!/bin/sh
echo boom >&2
exit 7
"#,
        );

        let tool = NucleiTool::with_binary(bin)
            .with_timeout(Duration::from_secs(5))
            .with_templates_root(dir.clone());
        let err = tool.scan_url("http://example.com", &[]).unwrap_err();
        match err {
            NucleiError::ProcessFailed { code, stderr } => {
                assert_eq!(code, Some(7));
                assert!(stderr.contains("boom"));
            }
            other => panic!("expected ProcessFailed, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_fake_binary_timeout_kills_hanging_process() {
        let dir = temp_dir("hang");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            r#"#!/bin/sh
sleep 30
exit 0
"#,
        );

        let tool = NucleiTool::with_binary(bin)
            .with_timeout(Duration::from_millis(200))
            .with_templates_root(dir.clone());
        let err = tool.scan_url("http://example.com", &[]).unwrap_err();
        assert!(
            matches!(err, NucleiError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_empty_templates_passes_allowlisted_root_and_disables_update_check() {
        let dir = temp_dir("empty-t");
        let root = dir.join("templates");
        fs::create_dir_all(&root).unwrap();
        let args_file = dir.join("args.txt");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            &format!(
                r#"#!/bin/sh
printf '%s\n' "$@" > '{}'
exit 0
"#,
                args_file.display()
            ),
        );

        let tool = NucleiTool::with_binary(bin)
            .with_timeout(Duration::from_secs(5))
            .with_templates_root(root.clone());
        tool.scan_url("http://example.com", &[]).unwrap();

        let args: Vec<String> = fs::read_to_string(&args_file)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert!(
            args.iter().any(|a| a == "-disable-update-check"),
            "expected -disable-update-check in args: {args:?}"
        );
        let t_pos = args
            .iter()
            .position(|a| a == "-t")
            .expect("expected -t in args");
        let root_canon = root.canonicalize().unwrap();
        assert_eq!(
            args.get(t_pos + 1).map(String::as_str),
            Some(root_canon.to_str().unwrap()),
            "empty templates must pass allowlisted root as -t"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_empty_templates_fails_when_root_missing() {
        let dir = temp_dir("missing-root");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            r#"#!/bin/sh
exit 0
"#,
        );
        let missing = dir.join("no-such-templates");
        let tool = NucleiTool::with_binary(bin)
            .with_timeout(Duration::from_secs(5))
            .with_templates_root(missing);
        let err = tool.scan_url("http://example.com", &[]).unwrap_err();
        assert!(
            matches!(err, NucleiError::TemplatesRootInvalid(_)),
            "expected TemplatesRootInvalid, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_templates_must_be_under_allowlisted_root() {
        let dir = temp_dir("tpl");
        let root = dir.join("allowed");
        fs::create_dir_all(&root).unwrap();
        let good = root.join("ok.yaml");
        fs::write(&good, "id: ok\n").unwrap();

        let outside = dir.join("evil.yaml");
        fs::write(&outside, "id: evil\n").unwrap();

        let args_file = dir.join("args.txt");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            &format!(
                r#"#!/bin/sh
# Capture args so we can assert -t / -disable-update-check
printf '%s\n' "$@" > '{}'
echo '{{"templateID":"ok","name":"Ok","severity":"info","matchedAt":"http://example.com"}}'
exit 0
"#,
                args_file.display()
            ),
        );

        let tool = NucleiTool::with_binary(bin)
            .with_timeout(Duration::from_secs(5))
            .with_templates_root(root.clone());

        // Relative path under root is allowed.
        let findings = tool.scan_url("http://example.com", &["ok.yaml"]).unwrap();
        assert_eq!(findings.len(), 1);

        let args = fs::read_to_string(&args_file).unwrap();
        assert!(
            args.lines().any(|l| l == "-disable-update-check"),
            "expected -disable-update-check when templates are provided"
        );
        assert!(
            args.lines().any(|l| l == "-t"),
            "expected -t when templates are provided"
        );

        // Absolute path outside root is refused.
        let err = tool
            .scan_url("http://example.com", &[outside.to_str().unwrap()])
            .unwrap_err();
        assert!(
            matches!(err, NucleiError::TemplateNotAllowed(_)),
            "expected TemplateNotAllowed, got {err:?}"
        );

        // Path escape via .. is refused.
        let err = tool
            .scan_url("http://example.com", &["../evil.yaml"])
            .unwrap_err();
        assert!(
            matches!(err, NucleiError::TemplateNotAllowed(_)),
            "expected TemplateNotAllowed for .. escape, got {err:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_version_checks_exit_status() {
        let dir = temp_dir("ver");
        let bin = dir.join("fake-nuclei");
        write_executable(
            &bin,
            r#"#!/bin/sh
echo "nuclei fake v0.0.1"
exit 0
"#,
        );
        let tool = NucleiTool::with_binary(bin).with_timeout(Duration::from_secs(5));
        let v = tool.version().unwrap();
        assert!(v.contains("nuclei fake"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_nuclei_scan_url_parses_multiple_lines() {
        let json_lines = r#"{"templateID":"vuln-1","name":"First Vuln","severity":"high","matchedAt":"http://example.com/page1","description":"desc1"}
{"templateID":"vuln-2","name":"Second Vuln","severity":"medium","matchedAt":"http://example.com/page2","description":"desc2"}
{"templateID":"vuln-3","name":"Third Vuln","severity":"low","matchedAt":"http://example.com/page3"}"#;

        let mut findings = Vec::new();
        for line in json_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(f) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(f);
            }
        }
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[1].severity, "medium");
        assert_eq!(findings[2].severity, "low");
    }

    #[test]
    fn test_nuclei_scan_url_skips_empty_lines() {
        let json_lines = "\n\n{\"templateID\":\"vuln-1\",\"name\":\"Test\",\"severity\":\"info\",\"matchedAt\":\"http://example.com\"}\n\n";

        let mut findings = Vec::new();
        for line in json_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(f) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(f);
            }
        }
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_nuclei_scan_url_skips_invalid_json_lines() {
        let json_lines = "not json\n{\"templateID\":\"vuln-1\",\"name\":\"Test\",\"severity\":\"info\",\"matchedAt\":\"http://example.com\"}\nalso not json";

        let mut findings = Vec::new();
        for line in json_lines.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(f) = serde_json::from_str::<NucleiFinding>(line) {
                findings.push(f);
            }
        }
        assert_eq!(findings.len(), 1);
    }
}
