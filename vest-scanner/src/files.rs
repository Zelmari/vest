//! File system scanner with bounded directory traversal.
//!
//! # Limits: security vs performance
//!
//! **Security limits** (path escape / content exfiltration):
//! - [`FileTraversalLimits::follow_symlinks`] (default `false`) — when false, skips symlinks;
//!   when true, follows only if the resolved path stays under the canonical scan root (escape
//!   targets are skipped; loops still detected via inode identity)
//! - [`FileTraversalLimits::max_file_size_bytes`] — do not silently read arbitrarily large files
//! - [`FileTraversalLimits::ignore_globs`] — skip names/suffixes that must not be opened
//!
//! **Performance / resource limits** (DoS / hang prevention):
//! - [`FileTraversalLimits::max_depth`] — bound recursion depth
//! - [`FileTraversalLimits::max_files`] — bound number of files collected
//! - [`FileTraversalLimits::max_total_bytes`] — bound aggregate bytes considered for content reads
//!
//! Hitting a limit returns a structured [`TraversalOutcome`] (truncated) rather than panicking.

use async_trait::async_trait;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

/// Configurable bounds for recursive file collection.
#[derive(Debug, Clone)]
pub struct FileTraversalLimits {
    pub max_depth: usize,
    pub max_files: usize,
    pub max_file_size_bytes: u64,
    pub max_total_bytes: u64,
    pub follow_symlinks: bool,
    /// Simple name (`node_modules`) or suffix (`*.pyc`) ignore patterns.
    pub ignore_globs: Vec<String>,
}

impl Default for FileTraversalLimits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_files: 10_000,
            max_file_size_bytes: 500 * 1024 * 1024,
            max_total_bytes: 1_073_741_824,
            follow_symlinks: false,
            ignore_globs: Vec::new(),
        }
    }
}

impl FileTraversalLimits {
    pub fn from_config(
        max_file_size_mb: u32,
        max_depth: u32,
        max_files: u32,
        max_total_bytes: u64,
        follow_symlinks: bool,
        ignore_globs: Vec<String>,
    ) -> Self {
        Self {
            max_depth: max_depth as usize,
            max_files: max_files as usize,
            max_file_size_bytes: (max_file_size_mb as u64) * 1024 * 1024,
            max_total_bytes,
            follow_symlinks,
            ignore_globs,
        }
    }
}

/// Why a path was skipped during traversal or content scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    Symlink,
    SymlinkLoop,
    /// Resolved path (after symlink follow) escaped the canonical scan root.
    OutsideRoot,
    TooLarge,
    Unreadable,
    Ignored,
    InvalidUtf8,
    Binary,
    DepthExceeded,
}

/// Which hard limit stopped further traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitHit {
    MaxDepth,
    MaxFiles,
    MaxTotalBytes,
}

/// Result of a bounded directory walk.
#[derive(Debug, Clone)]
pub struct TraversalOutcome {
    pub files: Vec<PathBuf>,
    pub skipped: Vec<(PathBuf, SkipReason)>,
    pub truncated: bool,
    pub truncation_reason: Option<LimitHit>,
    pub total_bytes: u64,
}

fn path_matches_ignore(path: &Path, ignores: &[String]) -> bool {
    if ignores.is_empty() {
        return false;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    for pat in ignores {
        if let Some(suffix) = pat.strip_prefix('*') {
            if name.ends_with(suffix) {
                return true;
            }
        } else if name.as_ref() == pat.as_str()
            || path
                .components()
                .any(|c| c.as_os_str().to_string_lossy() == *pat)
        {
            return true;
        }
    }
    false
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn identity_key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// True if `path` equals `root` or is a proper descendant (component-wise).
/// Rejects prefix collisions such as `/tmp/root` vs `/tmp/root-evil`.
fn path_within_root(path: &Path, root: &Path) -> bool {
    let path_comps: Vec<_> = path.components().collect();
    let root_comps: Vec<_> = root.components().collect();
    if path_comps.len() < root_comps.len() {
        return false;
    }
    path_comps
        .iter()
        .zip(root_comps.iter())
        .all(|(a, b)| a == b)
}

/// Collect files under `root` honouring [`FileTraversalLimits`].
///
/// Paths in the outcome are sorted for deterministic ordering. Symlinks are skipped when
/// `follow_symlinks` is false. When following is enabled, resolved paths must remain under
/// the canonical scan root or they are skipped as [`SkipReason::OutsideRoot`]. Unreadable
/// entries are recorded and skipped (no panic).
pub fn collect_files_bounded(
    root: &Path,
    limits: &FileTraversalLimits,
) -> Result<TraversalOutcome, VestError> {
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut total_bytes = 0u64;
    let mut truncated = false;
    let mut truncation_reason = None;
    let mut visited: HashSet<PathBuf> = HashSet::new();

    if !root.exists() {
        return Ok(TraversalOutcome {
            files,
            skipped,
            truncated,
            truncation_reason,
            total_bytes,
        });
    }

    if path_matches_ignore(root, &limits.ignore_globs) {
        skipped.push((root.to_path_buf(), SkipReason::Ignored));
        return Ok(TraversalOutcome {
            files,
            skipped,
            truncated,
            truncation_reason,
            total_bytes,
        });
    }

    if is_symlink(root) && !limits.follow_symlinks {
        skipped.push((root.to_path_buf(), SkipReason::Symlink));
        return Ok(TraversalOutcome {
            files,
            skipped,
            truncated,
            truncation_reason,
            total_bytes,
        });
    }

    let root_meta = match std::fs::metadata(root) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Unreadable root {}: {}", root.display(), e);
            skipped.push((root.to_path_buf(), SkipReason::Unreadable));
            return Ok(TraversalOutcome {
                files,
                skipped,
                truncated,
                truncation_reason,
                total_bytes,
            });
        }
    };

    let canonical_root = identity_key(root);

    if root_meta.is_file() {
        let key = canonical_root.clone();
        if !visited.insert(key) {
            skipped.push((root.to_path_buf(), SkipReason::SymlinkLoop));
            return Ok(TraversalOutcome {
                files,
                skipped,
                truncated,
                truncation_reason,
                total_bytes,
            });
        }
        let size = root_meta.len();
        if size > limits.max_file_size_bytes {
            skipped.push((root.to_path_buf(), SkipReason::TooLarge));
        } else if total_bytes.saturating_add(size) > limits.max_total_bytes {
            truncated = true;
            truncation_reason = Some(LimitHit::MaxTotalBytes);
            skipped.push((root.to_path_buf(), SkipReason::TooLarge));
        } else {
            total_bytes += size;
            files.push(root.to_path_buf());
        }
        files.sort();
        return Ok(TraversalOutcome {
            files,
            skipped,
            truncated,
            truncation_reason,
            total_bytes,
        });
    }

    // BFS-style stack: (path, depth). Depth 0 is the root directory itself.
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    visited.insert(canonical_root.clone());

    while let Some((dir, depth)) = stack.pop() {
        if truncated {
            break;
        }
        // Root is depth 0; max_depth=1 allows the root directory and one level of children.
        if depth > limits.max_depth {
            truncated = true;
            truncation_reason = Some(LimitHit::MaxDepth);
            skipped.push((dir, SkipReason::DepthExceeded));
            continue;
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Unreadable directory {}: {}", dir.display(), e);
                skipped.push((dir, SkipReason::Unreadable));
                continue;
            }
        };

        let mut children: Vec<PathBuf> = Vec::new();
        for entry in entries {
            match entry {
                Ok(ent) => children.push(ent.path()),
                Err(e) => {
                    tracing::warn!("Unreadable dir entry under {}: {}", dir.display(), e);
                    skipped.push((dir.clone(), SkipReason::Unreadable));
                }
            }
        }
        children.sort();

        for child in children {
            if truncated {
                break;
            }
            if path_matches_ignore(&child, &limits.ignore_globs) {
                skipped.push((child, SkipReason::Ignored));
                continue;
            }

            let child_is_link = is_symlink(&child);
            if child_is_link && !limits.follow_symlinks {
                skipped.push((child, SkipReason::Symlink));
                continue;
            }

            let meta = match std::fs::metadata(&child) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Unreadable path {}: {}", child.display(), e);
                    skipped.push((child, SkipReason::Unreadable));
                    continue;
                }
            };

            let key = identity_key(&child);
            // Containment: never traverse or collect resolved paths outside the scan root.
            if !path_within_root(&key, &canonical_root) {
                skipped.push((child, SkipReason::OutsideRoot));
                continue;
            }
            if !visited.insert(key) {
                skipped.push((child, SkipReason::SymlinkLoop));
                continue;
            }

            if meta.is_dir() {
                stack.push((child, depth + 1));
                continue;
            }

            if !meta.is_file() {
                continue;
            }

            if files.len() >= limits.max_files {
                truncated = true;
                truncation_reason = Some(LimitHit::MaxFiles);
                break;
            }

            let size = meta.len();
            if size > limits.max_file_size_bytes {
                skipped.push((child, SkipReason::TooLarge));
                continue;
            }
            if total_bytes.saturating_add(size) > limits.max_total_bytes {
                truncated = true;
                truncation_reason = Some(LimitHit::MaxTotalBytes);
                skipped.push((child, SkipReason::TooLarge));
                continue;
            }

            total_bytes += size;
            files.push(child);
        }
    }

    files.sort();
    Ok(TraversalOutcome {
        files,
        skipped,
        truncated,
        truncation_reason,
        total_bytes,
    })
}

#[derive(Clone)]
pub struct FileScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub check_format: bool,
    pub scan_secrets: bool,
    pub detect_backups: bool,
    pub detect_sensitive: bool,
    pub limits: FileTraversalLimits,
}

impl FileScanner {
    pub fn new() -> Self {
        Self {
            name: "file-scanner".into(),
            description:
                "Scans files for secrets, backups, debug files, and format vulnerabilities".into(),
            enabled: true,
            check_format: true,
            scan_secrets: true,
            detect_backups: true,
            detect_sensitive: true,
            limits: FileTraversalLimits::default(),
        }
    }

    pub fn with_format(mut self, check: bool) -> Self {
        self.check_format = check;
        self
    }

    pub fn with_secrets(mut self, scan: bool) -> Self {
        self.scan_secrets = scan;
        self
    }

    pub fn with_backups(mut self, detect: bool) -> Self {
        self.detect_backups = detect;
        self
    }

    pub fn with_sensitive(mut self, detect: bool) -> Self {
        self.detect_sensitive = detect;
        self
    }

    pub fn with_limits(mut self, limits: FileTraversalLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_max_file_size_mb(mut self, mb: u32) -> Self {
        self.limits.max_file_size_bytes = (mb as u64) * 1024 * 1024;
        self
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.limits.max_depth = depth;
        self
    }

    pub fn with_max_files(mut self, max: usize) -> Self {
        self.limits.max_files = max;
        self
    }

    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.limits.follow_symlinks = follow;
        self
    }

    pub fn with_ignore_globs(mut self, globs: Vec<String>) -> Self {
        self.limits.ignore_globs = globs;
        self
    }

    fn detect_file_format(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let dangerous_extensions: Vec<(&str, &str)> = vec![
            (".exe", "Windows executable"),
            (".dll", "Windows dynamic link library"),
            (".bat", "Windows batch script"),
            (".ps1", "PowerShell script"),
            (".vbs", "VBScript file"),
            (".scr", "Windows screensaver (executable)"),
            (".pif", "Program Information File (executable)"),
            (".com", "DOS executable"),
            (".msi", "Windows installer"),
            (".jar", "Java archive"),
            (".apk", "Android package"),
            (".ipa", "iOS application"),
            (".sh", "Shell script"),
            (".bin", "Binary file"),
            (".so", "Shared object library"),
            (".dylib", "macOS dynamic library"),
            (".sys", "System driver"),
        ];

        for (ext, desc) in &dangerous_extensions {
            if filename.ends_with(ext) {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("Potentially dangerous file type: .{}", ext.trim_start_matches('.')),
                    description: format!("File '{}' is a {} that could contain malicious code if from an untrusted source.", filename, desc),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: Severity::Medium,
                    confidence: 0.7,
                    status: FindingStatus::Open,
                    severity_score_estimate: Some(5.0),
                    cve_id: None,
                    cwe_id: Some("CWE-506".into()),
                    evidence: serde_json::json!({
                        "file": path.to_string_lossy(),
                        "extension": ext,
                        "file_type": desc,
                    }),
                    poc: None,
                    remediation: Some(format!("Verify the source and integrity of '{}'. Scan with antivirus if from an external source.", filename)),
                    location: serde_json::json!({
                        "file": path.to_string_lossy(),
                    }),
                    false_positive_history: None,
                    tags: vec!["file-type".into(), "suspicious".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        findings
    }

    pub fn scan_for_secrets(&self, path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();
        let filename = path.file_name().unwrap_or_default().to_string_lossy();

        let patterns: Vec<(&str, &str, Severity)> = vec![
            (
                r#"(?i)aws[_\-\.]?(?:access)?[_\-\.]?key[_\-\.]?id[\s:=]+['\x22\x27]?([A-Z0-9]{16,32})['\x22\x27]?"#,
                "AWS Access Key ID",
                Severity::Critical,
            ),
            (
                r#"(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key[\s:=]+['\x22\x27]?([A-Za-z0-9/+=]{40})['\x22\x27]?"#,
                "AWS Secret Access Key",
                Severity::Critical,
            ),
            (
                r#"(?i)github[_\-\.]?(?:pat|token|personal[_\-\.]?access[_\-\.]?token)[\s:=]+['\x22\x27]?(ghp_[A-Za-z0-9]{36})['\x22\x27]?"#,
                "GitHub Personal Access Token",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:api[_\-\.]?key|api[_\-\.]?token|api[_\-\.]?secret)[\s:=]+['\x22\x27]?([A-Za-z0-9\-_]{20,60})['\x22\x27]?"#,
                "API Key",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:password|passwd|pwd)[\s:=]+['\x22\x27]?([^\x22\x27\s]{4,})['\x22\x27]?"#,
                "Hardcoded password",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:private[_\-\.]?key|privkey)[\s:=]+['\x22\x27]?(\-{3,}BEGIN[\s\w]+\-{3,}.*?\-{3,}END[\s\w]+\-{3,})['\x22\x27]?"#,
                "Private key",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:secret|secret[_\-\.]?key)[\s:=]+['\x22\x27]?([A-Za-z0-9\-_]{16,})['\x22\x27]?"#,
                "Secret key",
                Severity::High,
            ),
            (
                r#"(?i)(?:jwt|jwt[_\-\.]?secret|jwt[_\-\.]?token)[\s:=]+['\x22\x27]?([A-Za-z0-9\-_\.]{20,})['\x22\x27]?"#,
                "JWT secret",
                Severity::High,
            ),
            (
                r#"(?i)(?:stripe[_\-\.]?(?:secret|key|api))[\s:=]+['\x22\x27]?(sk_(?:live|test)_[A-Za-z0-9]{24})['\x22\x27]?"#,
                "Stripe secret key",
                Severity::Critical,
            ),
            (
                r#"(?i)(?:slack[_\-\.]?(?:token|webhook))[\s:=]+['\x22\x27]?(xox[bpras]\-[A-Za-z0-9\-]{10,})['\x22\x27]?"#,
                "Slack token",
                Severity::High,
            ),
        ];

        for (pattern, name, severity) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                    let truncated = if matched.len() > 80 {
                        format!("{}...", &matched[..80])
                    } else {
                        matched.to_string()
                    };

                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: format!("{} found in file", name),
                        description: format!(
                            "Found potential {} in '{}'. Secrets in source code or configuration files can lead to unauthorized access.",
                            name.to_lowercase(), filename
                        ),
                        vulnerability_class: VulnerabilityClass::Unknown,
                        severity: *severity,
                        confidence: 0.75,
                        status: FindingStatus::Open,
                        severity_score_estimate: match severity {
                            Severity::Critical => Some(9.0),
                            Severity::High => Some(7.5),
                            Severity::Medium => Some(5.0),
                            _ => Some(3.0),
                        },
                        cve_id: None,
                        cwe_id: Some("CWE-798".into()),
                        evidence: serde_json::json!({
                            "file": filename,
                            "pattern": name,
                            "match_preview": truncated,
                            "match_length": matched.len(),
                        }),
                        poc: None,
                        remediation: Some(
                            "Remove hardcoded secrets from source code. Use environment variables, a secrets manager, or a vault service."
                                .into(),
                        ),
                        location: serde_json::json!({
                            "file": path.to_string_lossy(),
                        }),
                        false_positive_history: None,
                        tags: vec!["secret".into(), "hardcoded".into(), "credential".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }
        }

        findings
    }

    fn detect_backup_files(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let backup_patterns = [
            ".bak", ".backup", ".old", ".orig", ".save", ".tmp", ".temp", ".swp", ".swo", ".swn",
            ".swm",
        ];

        let ends_with_tilde = filename.ends_with('~');

        let matches_backup = backup_patterns.iter().any(|pat| filename.ends_with(pat));

        if matches_backup || ends_with_tilde {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: format!("Backup file detected: {}", path.to_string_lossy()),
                description: format!(
                    "File '{}' appears to be a backup or temporary file. Backup files may contain sensitive data or old configurations and are often accessible via web servers.",
                    filename
                ),
                vulnerability_class: VulnerabilityClass::Unknown,
                severity: Severity::Medium,
                confidence: 0.8,
                status: FindingStatus::Open,
                severity_score_estimate: Some(5.3),
                cve_id: None,
                cwe_id: Some("CWE-538".into()),
                evidence: serde_json::json!({
                    "file": path.to_string_lossy(),
                    "is_backup": true,
                }),
                poc: None,
                remediation: Some(
                    "Remove backup files from web-accessible directories. Use version control instead of file backups for source code."
                        .into(),
                ),
                location: serde_json::json!({
                    "file": path.to_string_lossy(),
                }),
                false_positive_history: None,
                tags: vec!["backup".into(), "file".into(), "exposure".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        findings
    }

    fn detect_sensitive_files(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let filename_lower = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        struct SensitivePattern {
            name: &'static str,
            filename: &'static str,
            reason: &'static str,
            severity: Severity,
            cwe: &'static str,
        }

        let sensitive_patterns = vec![
            SensitivePattern {
                name: ".env file",
                filename: ".env",
                reason: "Contains environment variables which may include database credentials, API keys, and other secrets",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Git config",
                filename: ".gitconfig",
                reason: "May contain user credentials and repository configuration",
                severity: Severity::Medium,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key",
                filename: "id_rsa",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key (DSA)",
                filename: "id_dsa",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key (ECDSA)",
                filename: "id_ecdsa",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "SSH key (Ed25519)",
                filename: "id_ed25519",
                reason: "Private SSH key could grant unauthorized server access",
                severity: Severity::Critical,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Docker config",
                filename: "config.json",
                reason: "Docker config may contain registry credentials",
                severity: Severity::High,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "npm config",
                filename: ".npmrc",
                reason: "May contain npm registry tokens",
                severity: Severity::High,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "AWS credentials",
                filename: "credentials",
                reason: "Contains AWS access keys and secrets",
                severity: Severity::Critical,
                cwe: "CWE-798",
            },
            SensitivePattern {
                name: "Database file",
                filename: ".db",
                reason: "SQLite or similar database file may contain application data",
                severity: Severity::Medium,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Debug symbol file",
                filename: ".pdb",
                reason: "Program database file may expose internal symbols and paths",
                severity: Severity::Low,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Core dump",
                filename: "core.",
                reason: "Core dump may contain process memory including secrets",
                severity: Severity::High,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Dockerfile",
                filename: "dockerfile",
                reason: "Dockerfile may expose build secrets and configuration",
                severity: Severity::Low,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Docker Compose",
                filename: "docker-compose.yml",
                reason: "Docker Compose file may contain service credentials",
                severity: Severity::Medium,
                cwe: "CWE-538",
            },
            SensitivePattern {
                name: "Kubernetes secret",
                filename: "secret.yaml",
                reason: "Kubernetes secret manifest may contain base64-encoded secrets",
                severity: Severity::High,
                cwe: "CWE-798",
            },
        ];

        for sp in &sensitive_patterns {
            let matches = if sp.filename.starts_with("core.") {
                filename_lower.starts_with(sp.filename)
            } else if sp.filename.starts_with('.') {
                filename_lower == sp.filename || filename_lower.ends_with(sp.filename)
            } else {
                filename_lower == sp.filename
                    || filename_lower.ends_with(&format!(".{}", sp.filename))
            };

            if matches {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("Sensitive file detected: {}", sp.name),
                    description: format!(
                        "File '{}' matches pattern for '{}'. {}. This file should not be accessible.",
                        path.to_string_lossy(),
                        sp.name,
                        sp.reason
                    ),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: sp.severity,
                    confidence: 0.85,
                    status: FindingStatus::Open,
                    severity_score_estimate: match sp.severity {
                        Severity::Critical => Some(9.0),
                        Severity::High => Some(7.5),
                        Severity::Medium => Some(5.0),
                        _ => Some(3.0),
                    },
                    cve_id: None,
                    cwe_id: Some(sp.cwe.into()),
                    evidence: serde_json::json!({
                        "file": path.to_string_lossy(),
                        "matched_pattern": sp.name,
                    }),
                    poc: None,
                    remediation: Some(format!(
                        "Remove '{}' from the repository. Add it to .gitignore and use secure alternatives like a secrets manager.",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )),
                    location: serde_json::json!({
                        "file": path.to_string_lossy(),
                    }),
                    false_positive_history: None,
                    tags: vec!["sensitive-file".into(), "exposure".into(), sp.name.to_lowercase().replace(' ', "-")],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        let parent_dir = path
            .parent()
            .and_then(|p| p.file_name())
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        if parent_dir == ".git" && filename_lower != "head" && filename_lower != "config" {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: format!("Git repository data exposed: {}", path.to_string_lossy()),
                description: "Git repository internal file is accessible. Git directories exposed via web server can leak source code and commit history.".into(),
                vulnerability_class: VulnerabilityClass::Unknown,
                severity: Severity::High,
                confidence: 0.9,
                status: FindingStatus::Open,
                severity_score_estimate: Some(7.5),
                cve_id: None,
                cwe_id: Some("CWE-538".into()),
                evidence: serde_json::json!({
                    "file": path.to_string_lossy(),
                    "in_git_dir": true,
                }),
                poc: None,
                remediation: Some("Ensure .git directories are not exposed via web server. Add rules to block access to .git paths.".into()),
                location: serde_json::json!({
                    "file": path.to_string_lossy(),
                }),
                false_positive_history: None,
                tags: vec!["git".into(), "sensitive-file".into(), "exposure".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        findings
    }

    /// Scan a single file. Content is read at most once for binary/UTF-8/secret checks.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<Finding>, VestError> {
        let mut findings = Vec::new();

        if self.check_format {
            findings.extend(self.detect_file_format(path));
        }

        if self.detect_backups {
            findings.extend(self.detect_backup_files(path));
        }

        if self.detect_sensitive {
            findings.extend(self.detect_sensitive_files(path));
        }

        if self.scan_secrets {
            match self.read_text_for_scan(path) {
                Ok(Some(content)) => {
                    findings.extend(self.scan_for_secrets(path, &content));
                }
                Ok(None) => {
                    // skipped (too large / binary / unreadable) — already logged
                }
                Err(e) => {
                    tracing::warn!("Failed to read {}: {}", path.display(), e);
                }
            }
        }

        Ok(findings)
    }

    /// Single bounded read used for secret scanning. Returns `Ok(None)` when skipped.
    fn read_text_for_scan(&self, path: &Path) -> Result<Option<String>, VestError> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Unreadable file {}: {}", path.display(), e);
                return Ok(None);
            }
        };
        if meta.len() > self.limits.max_file_size_bytes {
            tracing::warn!(
                "Skipping oversized file {} ({} bytes > limit {})",
                path.display(),
                meta.len(),
                self.limits.max_file_size_bytes
            );
            return Ok(None);
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Unreadable file {}: {}", path.display(), e);
                return Ok(None);
            }
        };

        let is_binary = data.iter().take(512).any(|&b| b == 0);
        if is_binary {
            return Ok(None);
        }

        match String::from_utf8(data) {
            Ok(s) => Ok(Some(s)),
            Err(_) => {
                tracing::debug!("Skipping non-UTF8 file {}", path.display());
                Ok(None)
            }
        }
    }

    fn scan_path_sync(&self, path: &Path, target_id: &str) -> Result<Vec<Finding>, VestError> {
        let outcome = collect_files_bounded(path, &self.limits)?;
        if outcome.truncated {
            tracing::warn!(
                "File traversal truncated under {}: {:?}",
                path.display(),
                outcome.truncation_reason
            );
        }
        for (skipped_path, reason) in &outcome.skipped {
            tracing::debug!("Skipped {}: {:?}", skipped_path.display(), reason);
        }

        tracing::info!("Found {} files to analyze", outcome.files.len());

        let mut all_findings = Vec::new();
        for file_path in &outcome.files {
            match self.scan_file(file_path) {
                Ok(mut file_findings) => {
                    for f in &mut file_findings {
                        f.target_id = target_id.to_string();
                        if f.scan_id.is_empty() {
                            f.scan_id = "file-scan".into();
                        }
                    }
                    all_findings.extend(file_findings);
                }
                Err(e) => {
                    tracing::warn!("Failed to scan file {}: {}", file_path.display(), e);
                }
            }
        }

        tracing::info!(
            "File scan complete: {} total findings from {} files",
            all_findings.len(),
            outcome.files.len()
        );
        Ok(all_findings)
    }

    /// Backward-compatible helper: bounded collect with default limits, files only.
    pub fn collect_files(path: &Path) -> Result<Vec<PathBuf>, VestError> {
        let outcome = collect_files_bounded(path, &FileTraversalLimits::default())?;
        Ok(outcome.files)
    }
}

impl Default for FileScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for FileScanner {
    async fn name(&self) -> &str {
        &self.name
    }

    async fn description(&self) -> &str {
        &self.description
    }

    async fn enabled(&self) -> bool {
        self.enabled
    }

    async fn scan(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let path = match &target.path {
            Some(p) => PathBuf::from(p),
            None => return Err(VestError::Config("File target requires a path".into())),
        };

        if !path.exists() {
            return Err(VestError::Config(format!(
                "File target path not found: {}",
                path.display()
            )));
        }

        tracing::info!("Starting file scan of: {}", path.display());

        let scanner = self.clone();
        let target_id = target.id.clone();
        tokio::task::spawn_blocking(move || scanner.scan_path_sync(&path, &target_id))
            .await
            .map_err(|e| VestError::Internal(format!("file scan task failed: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_file(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_default_values() {
        let scanner = FileScanner::new();
        assert!(scanner.enabled);
        assert_eq!(scanner.name, "file-scanner");
        assert!(scanner.check_format);
        assert!(scanner.scan_secrets);
        assert!(scanner.detect_backups);
        assert!(scanner.detect_sensitive);
    }

    #[test]
    fn test_format_detection_exe() {
        let scanner = FileScanner::new();
        let path = write_temp_file("test.exe", "fake executable");
        let findings = scanner.detect_file_format(&path);
        assert!(!findings.is_empty());
        let has_exe = findings.iter().any(|f| f.title.contains("exe"));
        assert!(has_exe);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_format_detection_sh() {
        let scanner = FileScanner::new();
        let path = write_temp_file("test.sh", "#!/bin/bash\necho hello");
        let findings = scanner.detect_file_format(&path);
        assert!(!findings.is_empty());
        let has_sh = findings.iter().any(|f| f.title.contains("sh"));
        assert!(has_sh);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_format_safe_file_no_findings() {
        let scanner = FileScanner::new();
        let path = write_temp_file("readme.txt", "Hello world");
        let findings = scanner.detect_file_format(&path);
        assert!(findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_aws_key() {
        let scanner = FileScanner::new();
        let path = write_temp_file(
            "config.js",
            r#"AWS_ACCESS_KEY_ID = "AWSTESTFAKEEXAMPLEKEY12""#,
        );
        let findings =
            scanner.scan_for_secrets(&path, r#"AWS_ACCESS_KEY_ID = "AWSTESTFAKEEXAMPLEKEY12""#);
        assert!(!findings.is_empty());
        let has_aws = findings.iter().any(|f| f.title.contains("AWS"));
        assert!(has_aws);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_password() {
        let scanner = FileScanner::new();
        let path = write_temp_file("app.py", r#"password = "supersecret123""#);
        let findings = scanner.scan_for_secrets(&path, r#"password = "supersecret123""#);
        assert!(!findings.is_empty());
        let has_pwd = findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("password"));
        assert!(has_pwd);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_api_key() {
        let scanner = FileScanner::new();
        let path = write_temp_file(
            "service.go",
            r#"apiKey = "sk_test_FAKESTRIPEKEY0987654321XY""#,
        );
        let findings =
            scanner.scan_for_secrets(&path, r#"apiKey = "sk_test_FAKESTRIPEKEY0987654321XY""#);
        assert!(!findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_secret_scanning_no_secrets() {
        let scanner = FileScanner::new();
        let path = write_temp_file("clean.js", r#"const hello = "world";"#);
        let findings = scanner.scan_for_secrets(&path, r#"const hello = "world";"#);
        assert!(findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backup_file_detection() {
        let scanner = FileScanner::new();
        let path = write_temp_file("config.bak", "old config");
        let findings = scanner.detect_backup_files(&path);
        assert!(!findings.is_empty());
        let has_backup = findings.iter().any(|f| f.title.contains("Backup"));
        assert!(has_backup);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backup_swp_file() {
        let scanner = FileScanner::new();
        let path = write_temp_file("index.swp", "vim swap");
        let findings = scanner.detect_backup_files(&path);
        assert!(!findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_backup_file_not_detected() {
        let scanner = FileScanner::new();
        let path = write_temp_file("config.json", r#"{"key": "value"}"#);
        let findings = scanner.detect_backup_files(&path);
        assert!(findings.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_env_file() {
        let scanner = FileScanner::new();
        let path = write_temp_file(".env", "DATABASE_URL=postgres://localhost");
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_env = findings.iter().any(|f| f.title.contains(".env"));
        assert!(has_env);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_ssh_key() {
        let scanner = FileScanner::new();
        let path = write_temp_file("id_rsa", "-----BEGIN RSA PRIVATE KEY-----");
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_ssh = findings.iter().any(|f| f.title.contains("SSH"));
        assert!(has_ssh);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_credentials_file() {
        let scanner = FileScanner::new();
        let path = write_temp_file("credentials", "[default]\naws_access_key_id=AKIA...");
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_creds = findings.iter().any(|f| f.title.contains("credential"));
        assert!(has_creds);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_sensitive_git_exposure() {
        let tmp_dir = std::env::temp_dir().join("test_git_exposure");
        let git_dir = tmp_dir.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let path = git_dir.join("objects");
        std::fs::write(&path, "fake git object").unwrap();
        let scanner = FileScanner::new();
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&git_dir).ok();
        std::fs::remove_dir(&tmp_dir).ok();
    }

    #[test]
    fn test_sensitive_docker_config() {
        let scanner = FileScanner::new();
        let path = write_temp_file(
            "config.json",
            r#"{"auths": {"registry": {"auth": "base64"}}}"#,
        );
        let findings = scanner.detect_sensitive_files(&path);
        assert!(!findings.is_empty());
        let has_docker = findings.iter().any(|f| f.title.contains("Docker config"));
        assert!(has_docker);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_with_methods() {
        let scanner = FileScanner::new()
            .with_format(false)
            .with_secrets(false)
            .with_backups(false)
            .with_sensitive(false);
        assert!(!scanner.check_format);
        assert!(!scanner.scan_secrets);
        assert!(!scanner.detect_backups);
        assert!(!scanner.detect_sensitive);
    }

    #[test]
    fn test_scan_rejects_nonexistent_path() {
        let scanner = FileScanner::new();
        let target = Target {
            id: "test".into(),
            name: "missing".into(),
            target_type: vest_core::types::TargetType::File,
            path: Some("/definitely/nonexistent/file.txt".into()),
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.scan(&target));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_rejects_no_path() {
        let scanner = FileScanner::new();
        let target = Target {
            id: "test".into(),
            name: "nopath".into(),
            target_type: vest_core::types::TargetType::File,
            path: None,
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scanner.scan(&target));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path"));
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vest_files_{}_{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_collect_respects_file_size_limit() {
        let dir = unique_temp_dir("size");
        let small = dir.join("small.txt");
        let large = dir.join("large.txt");
        std::fs::write(&small, b"ok").unwrap();
        std::fs::write(&large, vec![b'x'; 64]).unwrap();

        let limits = FileTraversalLimits {
            max_file_size_bytes: 16,
            ..FileTraversalLimits::default()
        };
        let outcome = collect_files_bounded(&dir, &limits).unwrap();
        assert!(outcome.files.iter().any(|p| p.ends_with("small.txt")));
        assert!(!outcome.files.iter().any(|p| p.ends_with("large.txt")));
        assert!(outcome
            .skipped
            .iter()
            .any(|(_, r)| *r == SkipReason::TooLarge));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_respects_max_depth() {
        let dir = unique_temp_dir("depth");
        let nested = dir.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.join("root.txt"), b"r").unwrap();
        std::fs::write(dir.join("a").join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("a").join("b").join("b.txt"), b"b").unwrap();
        std::fs::write(nested.join("c.txt"), b"c").unwrap();

        let limits = FileTraversalLimits {
            max_depth: 1,
            ..FileTraversalLimits::default()
        };
        let outcome = collect_files_bounded(&dir, &limits).unwrap();
        assert!(outcome.truncated);
        assert_eq!(outcome.truncation_reason, Some(LimitHit::MaxDepth));
        assert!(outcome.files.iter().any(|p| p.ends_with("root.txt")));
        assert!(outcome.files.iter().any(|p| p.ends_with("a.txt")));
        assert!(!outcome.files.iter().any(|p| p.ends_with("b.txt")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_respects_max_files() {
        let dir = unique_temp_dir("count");
        for i in 0..10 {
            std::fs::write(dir.join(format!("f{i}.txt")), b"x").unwrap();
        }
        let limits = FileTraversalLimits {
            max_files: 3,
            ..FileTraversalLimits::default()
        };
        let outcome = collect_files_bounded(&dir, &limits).unwrap();
        assert_eq!(outcome.files.len(), 3);
        assert!(outcome.truncated);
        assert_eq!(outcome.truncation_reason, Some(LimitHit::MaxFiles));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_skips_unreadable() {
        let dir = unique_temp_dir("unreadable");
        let file = dir.join("ok.txt");
        std::fs::write(&file, b"hello").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = dir.join("locked.txt");
            std::fs::write(&locked, b"secret").unwrap();
            let mut perms = std::fs::metadata(&locked).unwrap().permissions();
            perms.set_mode(0o000);
            std::fs::set_permissions(&locked, perms).unwrap();

            // Directory listing still sees the file; metadata/read may fail depending on owner.
            // Make a subdirectory unreadable instead.
            let sub = dir.join("nosub");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("hidden.txt"), b"h").unwrap();
            let mut dperms = std::fs::metadata(&sub).unwrap().permissions();
            dperms.set_mode(0o000);
            std::fs::set_permissions(&sub, dperms).unwrap();

            let outcome = collect_files_bounded(&dir, &FileTraversalLimits::default()).unwrap();
            assert!(outcome.files.iter().any(|p| p.ends_with("ok.txt")));
            assert!(outcome
                .skipped
                .iter()
                .any(|(_, r)| *r == SkipReason::Unreadable));

            let mut dperms = std::fs::metadata(&sub).unwrap().permissions();
            dperms.set_mode(0o755);
            std::fs::set_permissions(&sub, dperms).unwrap();
            let mut perms = std::fs::metadata(&locked).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&locked, perms).unwrap();
        }
        #[cfg(not(unix))]
        {
            let outcome = collect_files_bounded(&dir, &FileTraversalLimits::default()).unwrap();
            assert!(outcome.files.iter().any(|p| p.ends_with("ok.txt")));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_skips_invalid_utf8_and_binary() {
        let dir = unique_temp_dir("binary");
        let bin = dir.join("blob.bin");
        let bad = dir.join("bad.txt");
        std::fs::write(&bin, [0u8, 1, 2, 3, 0, 9]).unwrap();
        std::fs::write(&bad, [0xff, 0xfe, 0xfd]).unwrap();

        let scanner = FileScanner::new()
            .with_format(false)
            .with_backups(false)
            .with_sensitive(false);
        let findings_bin = scanner.scan_file(&bin).unwrap();
        let findings_bad = scanner.scan_file(&bad).unwrap();
        assert!(findings_bin.is_empty());
        assert!(findings_bad.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_respects_ignore_globs() {
        let dir = unique_temp_dir("ignore");
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        std::fs::write(dir.join("keep.rs"), b"fn main() {}").unwrap();
        std::fs::write(dir.join("skip.pyc"), b"pyc").unwrap();
        std::fs::write(dir.join("node_modules").join("pkg.js"), b"js").unwrap();

        let limits = FileTraversalLimits {
            ignore_globs: vec!["node_modules".into(), "*.pyc".into()],
            ..FileTraversalLimits::default()
        };
        let outcome = collect_files_bounded(&dir, &limits).unwrap();
        assert_eq!(outcome.files.len(), 1);
        assert!(outcome.files[0].ends_with("keep.rs"));
        assert!(outcome
            .skipped
            .iter()
            .any(|(_, r)| *r == SkipReason::Ignored));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_skips_symlinks_by_default() {
        let dir = unique_temp_dir("symlink");
        let real = dir.join("real.txt");
        std::fs::write(&real, b"data").unwrap();
        let link = dir.join("link.txt");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let outcome = collect_files_bounded(&dir, &FileTraversalLimits::default()).unwrap();
            assert_eq!(outcome.files.len(), 1);
            assert!(outcome.files[0].ends_with("real.txt"));
            assert!(outcome
                .skipped
                .iter()
                .any(|(p, r)| p.ends_with("link.txt") && *r == SkipReason::Symlink));
        }
        #[cfg(not(unix))]
        {
            let _ = link;
            let outcome = collect_files_bounded(&dir, &FileTraversalLimits::default()).unwrap();
            assert!(outcome.files.iter().any(|p| p.ends_with("real.txt")));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_collect_follow_symlinks_skips_escape_outside_root() {
        let dir = unique_temp_dir("symlink_escape");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let outside = std::env::temp_dir().join(format!(
            "vest-files-outside-root-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"outside-leak").unwrap();
        std::fs::write(dir.join("ok.txt"), b"ok").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("escape")).unwrap();

        let limits = FileTraversalLimits {
            follow_symlinks: true,
            ..FileTraversalLimits::default()
        };
        let outcome = collect_files_bounded(&dir, &limits).unwrap();
        assert_eq!(outcome.files.len(), 1);
        assert!(outcome.files[0].ends_with("ok.txt"));
        assert!(
            !outcome.files.iter().any(|p| p.ends_with("secret.txt")),
            "escaped /tmp path must not be collected: {:?}",
            outcome.files
        );
        assert!(outcome
            .skipped
            .iter()
            .any(|(p, r)| p.ends_with("escape") && *r == SkipReason::OutsideRoot));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn test_collect_stable_order_and_no_symlink_duplicates() {
        let dir = unique_temp_dir("order");
        std::fs::write(dir.join("b.txt"), b"b").unwrap();
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("c.txt"), b"c").unwrap();

        #[cfg(unix)]
        {
            let link_dir = dir.join("alias");
            std::os::unix::fs::symlink(&dir, &link_dir).unwrap();
            let limits = FileTraversalLimits {
                follow_symlinks: true,
                ..FileTraversalLimits::default()
            };
            let outcome = collect_files_bounded(&dir, &limits).unwrap();
            let names: Vec<_> = outcome
                .files
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .collect();
            assert_eq!(names, vec!["a.txt", "b.txt", "c.txt"]);
            // Directory symlink back to root must not duplicate files.
            assert_eq!(outcome.files.len(), 3);
        }
        #[cfg(not(unix))]
        {
            let outcome = collect_files_bounded(&dir, &FileTraversalLimits::default()).unwrap();
            let names: Vec<_> = outcome
                .files
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .collect();
            assert_eq!(names, vec!["a.txt", "b.txt", "c.txt"]);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_file_single_read_finds_secret() {
        let dir = unique_temp_dir("secret_once");
        let path = dir.join("cfg.py");
        std::fs::write(&path, r#"password = "supersecret123""#).unwrap();
        let scanner = FileScanner::new()
            .with_format(false)
            .with_backups(false)
            .with_sensitive(false);
        let findings = scanner.scan_file(&path).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.title.to_lowercase().contains("password")));
        std::fs::remove_dir_all(&dir).ok();
    }
}
