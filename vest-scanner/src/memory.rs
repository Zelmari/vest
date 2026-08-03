use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

/// Operating mode for process-memory scanning.
///
/// Real process-memory acquisition (ptrace / ReadProcessMemory / etc.) is **not**
/// implemented. The default is [`MemoryScanMode::Unsupported`]. An explicit
/// simulation harness is available only when opted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryScanMode {
    /// Refuse real acquisition; `scan` returns [`VestError::Unsupported`].
    #[default]
    Unsupported,
    /// Run the explicit local simulation harness (fabricated regions/bytes).
    Simulation,
}

pub struct MemoryScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub max_memory_per_scan_mb: u64,
    pub pattern_scan_acceleration: bool,
    pub suspicious_regions: Vec<String>,
    pub hook_detection: bool,
    /// Scan mode — defaults to [`MemoryScanMode::Unsupported`].
    pub mode: MemoryScanMode,
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            name: "memory-scanner".into(),
            description:
                "Process memory scanner (real acquisition unsupported; simulation opt-in only)"
                    .into(),
            enabled: true,
            max_memory_per_scan_mb: 4096,
            pattern_scan_acceleration: true,
            suspicious_regions: vec!["RWX".into(), "PAGE_EXECUTE_READWRITE".into()],
            hook_detection: true,
            mode: MemoryScanMode::Unsupported,
        }
    }

    pub fn with_hook_detection(mut self, detect: bool) -> Self {
        self.hook_detection = detect;
        self
    }

    pub fn with_max_memory(mut self, mb: u64) -> Self {
        self.max_memory_per_scan_mb = mb;
        self
    }

    /// Explicitly enable the simulation harness.
    ///
    /// When `allowed` is true, [`Scanner::scan`] runs against fabricated regions/bytes
    /// and tags every finding as simulated. When false (default), scan returns
    /// [`VestError::Unsupported`].
    pub fn with_simulation_allowed(mut self, allowed: bool) -> Self {
        self.mode = if allowed {
            MemoryScanMode::Simulation
        } else {
            MemoryScanMode::Unsupported
        };
        self
    }

    pub fn mode(&self) -> MemoryScanMode {
        self.mode
    }

    fn mark_finding_simulated(finding: &mut Finding) {
        if !finding.title.starts_with("[SIMULATED]") {
            finding.title = format!("[SIMULATED] {}", finding.title);
        }
        if !finding.description.starts_with("SIMULATED:") {
            finding.description = format!("SIMULATED: {}", finding.description);
        }
        if !finding.tags.iter().any(|t| t == "simulation") {
            finding.tags.push("simulation".into());
        }
        if !finding.metadata.is_object() {
            finding.metadata = serde_json::json!({});
        }
        if let Some(obj) = finding.metadata.as_object_mut() {
            obj.insert("simulation".into(), serde_json::json!(true));
        }
    }

    pub fn scan_pattern(data: &[u8], pattern: &str) -> Vec<usize> {
        let bytes: Vec<Option<u8>> = pattern
            .split_whitespace()
            .map(|b| {
                if b == "??" || b == "?" {
                    None
                } else {
                    u8::from_str_radix(b, 16).ok()
                }
            })
            .collect();

        if bytes.is_empty() {
            return vec![];
        }

        let mut matches = Vec::new();
        for i in 0..data.len() {
            if i + bytes.len() > data.len() {
                break;
            }
            let mut matched = true;
            for (j, byte) in bytes.iter().enumerate() {
                match byte {
                    Some(b) if data[i + j] != *b => {
                        matched = false;
                        break;
                    }
                    None => {}
                    _ => {}
                }
            }
            if matched {
                matches.push(i);
            }
        }

        matches
    }

    pub fn scan_pattern_fast(data: &[u8], pattern: &str) -> Vec<usize> {
        let bytes: Vec<Option<u8>> = pattern
            .split_whitespace()
            .map(|b| {
                if b == "??" || b == "?" {
                    None
                } else {
                    u8::from_str_radix(b, 16).ok()
                }
            })
            .collect();

        if bytes.is_empty() {
            return vec![];
        }

        let first_byte_idx = match bytes.iter().position(|b| b.is_some()) {
            Some(idx) => idx,
            None => return Self::scan_pattern(data, pattern),
        };
        let first = bytes[first_byte_idx].unwrap();
        let pat_len = bytes.len();

        let mut matches = Vec::new();
        let mut i = 0;
        while i + pat_len <= data.len() {
            if let Some(pos) = data[i..].iter().position(|&b| b == first) {
                i += pos;
                let match_start = i.saturating_sub(first_byte_idx);
                if match_start + pat_len > data.len() {
                    break;
                }
                let mut matched = true;
                for (j, byte) in bytes.iter().enumerate() {
                    match byte {
                        Some(b) if data[match_start + j] != *b => {
                            matched = false;
                            break;
                        }
                        None => {}
                        _ => {}
                    }
                }
                if matched {
                    matches.push(match_start);
                }
                i += 1;
            } else {
                break;
            }
        }

        matches
    }

    pub fn check_suspicious_regions(regions: &[MemoryRegion]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        for region in regions {
            if region.permissions.contains("RWX")
                || region.permissions.contains("EXECUTE_READWRITE")
            {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: "memory-scan".into(),
                    target_id: String::new(),
                    title: format!("Suspicious memory region: {} ({})", region.name, region.permissions),
                    description: format!(
                        "Found a {}-byte memory region with {} permissions at 0x{:x}. RWX regions allow both writing and executing code, which is a security risk and may indicate code injection, shellcode, or JIT spraying.",
                        region.size, region.permissions, region.base_address
                    ),
                    vulnerability_class: VulnerabilityClass::CodeCave,
                    severity: Severity::High,
                    confidence: 0.85,
                    status: FindingStatus::Open,
                    severity_score_estimate: Some(7.0),
                    cve_id: None,
                    cwe_id: Some("CWE-122".into()),
                    evidence: serde_json::json!({
                        "base_address": format!("0x{:x}", region.base_address),
                        "size": region.size,
                        "permissions": region.permissions,
                        "name": region.name,
                    }),
                    poc: None,
                    remediation: Some("Ensure memory regions are either writable OR executable, never both. Check for injected code.".into()),
                    location: serde_json::json!({"address": format!("0x{:x}", region.base_address)}),
                    false_positive_history: None,
                    tags: vec!["memory".into(), "rwx".into(), "suspicious".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }

            if region.permissions.contains("W")
                && !region.permissions.contains("E")
                && region.name.is_empty()
            {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: "memory-scan".into(),
                    target_id: String::new(),
                    title: format!("Unnamed writable memory region at 0x{:x}", region.base_address),
                    description: format!("Found an unnamed {}-byte writable memory region. This could be allocated by malware or unpacked code.", region.size),
                    vulnerability_class: VulnerabilityClass::DLLInjection,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    status: FindingStatus::Open,
                    severity_score_estimate: Some(4.5),
                    cve_id: None,
                    cwe_id: None,
                    evidence: serde_json::json!({"base_address": format!("0x{:x}", region.base_address), "size": region.size}),
                    poc: None,
                    remediation: Some("Investigate the source of this memory allocation.".into()),
                    location: serde_json::json!({"address": format!("0x{:x}", region.base_address)}),
                    false_positive_history: None,
                    tags: vec!["memory".into(), "writable".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        findings
    }

    pub fn detect_hooks(region_data: &[(&MemoryRegion, Vec<u8>)]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let hook_patterns = [
            ("JMP near (E9)", "E9 ?? ?? ?? ??"),
            ("JMP far (FF 25)", "FF 25"),
            ("PUSH/RET", "68 ?? ?? ?? ?? C3"),
            ("MOV RAX/RET", "48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0"),
            ("JMP [RIP+x]", "FF 25 ?? ?? ?? ??"),
        ];

        for (region, data) in region_data {
            if region.is_executable() {
                for (hook_name, pattern) in &hook_patterns {
                    let matches = MemoryScanner::scan_pattern_fast(data, pattern);

                    for offset in matches {
                        let addr = region.base_address + offset as u64;
                        if addr.is_multiple_of(16) || addr.is_multiple_of(8) {
                            findings.push(Finding {
                                id: new_id(),
                                scan_id: "memory-scan".into(),
                                target_id: String::new(),
                                title: format!("Potential {} hook detected at 0x{:x} in {}", hook_name, addr, region.name),
                                description: format!(
                                    "Found a {} pattern at offset {} in region '{}'. This may indicate an inline hook, which is commonly used by anti-cheat, malware, or debugging tools.",
                                    hook_name, offset, region.name
                                ),
                                vulnerability_class: VulnerabilityClass::ImportTableHooking,
                                severity: Severity::Medium,
                                confidence: 0.7,
                                status: FindingStatus::Open,
                                severity_score_estimate: None,
                                cve_id: None,
                                cwe_id: None,
                                evidence: serde_json::json!({
                                    "address": format!("0x{:x}", addr),
                                    "offset": offset,
                                    "region": region.name,
                                    "pattern": pattern,
                                    "hook_type": hook_name,
                                }),
                                poc: None,
                                remediation: Some("Verify this is expected behavior. If not, investigate for malicious code injection.".into()),
                                location: serde_json::json!({"address": format!("0x{:x}", addr)}),
                                false_positive_history: None,
                                tags: vec!["memory".into(), "hook".into(), hook_name.to_lowercase()],
                                metadata: serde_json::json!({}),
                                discovered_at: now,
                                updated_at: now,
                            });
                        }
                    }
                }

                let shellcode_patterns = [
                    ("Shellcode: socket/connect", "6A 02 5B B8"),
                    ("Shellcode: URLDownloadToFile", "55 8B EC"),
                    ("Shellcode: CreateProcess", "6A 00 6A 00"),
                    ("Shellcode: VirtualAlloc", "6A 40 68 00 30"),
                ];

                for (shell_name, pattern) in &shellcode_patterns {
                    let matches = MemoryScanner::scan_pattern_fast(data, pattern);
                    for offset in matches {
                        let addr = region.base_address + offset as u64;
                        findings.push(Finding {
                            id: new_id(),
                            scan_id: "memory-scan".into(),
                            target_id: String::new(),
                            title: format!("Potential shellcode pattern: {} at 0x{:x}", shell_name, addr),
                            description: format!("Found potential shellcode pattern '{}' in region '{}'. This may indicate injected malicious code.", shell_name, region.name),
                            vulnerability_class: VulnerabilityClass::CodeCave,
                            severity: Severity::Critical,
                            confidence: 0.75,
                            status: FindingStatus::Open,
                            severity_score_estimate: Some(9.0),
                            cve_id: None,
                            cwe_id: Some("CWE-506".into()),
                            evidence: serde_json::json!({"address": format!("0x{:x}", addr), "pattern": pattern, "region": region.name}),
                            poc: None,
                            remediation: Some("Immediately investigate. Dump the region and analyze with a disassembler.".into()),
                            location: serde_json::json!({"address": format!("0x{:x}", addr)}),
                            false_positive_history: None,
                            tags: vec!["memory".into(), "shellcode".into(), "critical".into()],
                            metadata: serde_json::json!({}),
                            discovered_at: now,
                            updated_at: now,
                        });
                    }
                }
            }
        }

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        findings.retain(|f| {
            let addr = f
                .location
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            seen.insert(addr.to_string())
        });

        findings
    }

    pub fn scan_value(data: &[u8], value: &[u8]) -> Vec<usize> {
        MemoryScanner::scan_pattern_fast(
            data,
            &value
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    pub fn find_pointers(data: &[u8], target_addr: u64, base_addr: u64) -> Vec<u64> {
        let mut pointers = Vec::new();
        let target_bytes = target_addr.to_le_bytes();

        for i in 0..data.len().saturating_sub(8) {
            if data[i..i + 8] == target_bytes[..] {
                pointers.push(base_addr + i as u64);
            }
        }

        pointers
    }

    /// Fabricated memory map for the **simulation harness only**.
    ///
    /// This does not inspect any live process. Prefer calling via
    /// [`MemoryScanner::with_simulation_allowed`] / [`MemoryScanMode::Simulation`].
    pub fn get_simulated_regions(platform: &str) -> Vec<MemoryRegion> {
        match platform {
            "windows" => vec![
                MemoryRegion {
                    name: "game.exe".into(),
                    base_address: 0x00400000,
                    size: 0x500000,
                    permissions: "RX".into(),
                    module_name: Some("game.exe".into()),
                },
                MemoryRegion {
                    name: "game.exe".into(),
                    base_address: 0x00900000,
                    size: 0x100000,
                    permissions: "RW".into(),
                    module_name: Some("game.exe".into()),
                },
                MemoryRegion {
                    name: "ntdll.dll".into(),
                    base_address: 0x7FFE0000,
                    size: 0x1A0000,
                    permissions: "RX".into(),
                    module_name: Some("ntdll.dll".into()),
                },
                MemoryRegion {
                    name: "".into(),
                    base_address: 0x01000000,
                    size: 0x10000,
                    permissions: "RWX".into(),
                    module_name: None,
                },
            ],
            "linux" => vec![
                MemoryRegion {
                    name: "game".into(),
                    base_address: 0x555555554000,
                    size: 0x300000,
                    permissions: "RX".into(),
                    module_name: Some("game".into()),
                },
                MemoryRegion {
                    name: "[heap]".into(),
                    base_address: 0x555555580000,
                    size: 0x200000,
                    permissions: "RW".into(),
                    module_name: None,
                },
                MemoryRegion {
                    name: "[anon]".into(),
                    base_address: 0x7FFFF7C00000,
                    size: 0x40000,
                    permissions: "RWX".into(),
                    module_name: None,
                },
            ],
            "macos" => vec![
                MemoryRegion {
                    name: "__TEXT".into(),
                    base_address: 0x100000000,
                    size: 0x200000,
                    permissions: "RX".into(),
                    module_name: Some("game".into()),
                },
                MemoryRegion {
                    name: "__DATA".into(),
                    base_address: 0x100200000,
                    size: 0x100000,
                    permissions: "RW".into(),
                    module_name: Some("game".into()),
                },
            ],
            _ => vec![],
        }
    }

    pub fn detect_platform() -> &'static str {
        if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unknown"
        }
    }

    /// Fabricate bytes for the **simulation harness only**.
    ///
    /// Does not read process memory. The `base` address is unused for acquisition
    /// (retained only so callers can keep address math consistent in tests).
    pub fn read_memory(base: u64, size: usize) -> Vec<u8> {
        Self::fabricate_simulated_memory(base, size)
    }

    /// Explicit name for fabricated simulation bytes (same as [`Self::read_memory`]).
    pub fn fabricate_simulated_memory(base: u64, size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];

        for (i, byte) in data.iter_mut().enumerate().take(size) {
            *byte = (i % 256) as u8;
        }

        if size > 256 {
            data[0x100..0x105].copy_from_slice(&[0xE9, 0x45, 0x23, 0x01, 0x00]);
            data[0x200..0x204].copy_from_slice(&[0x6A, 0x02, 0x5B, 0xB8]);
            data[0x150] = 0xC3;
            data[0x180] = 0xC3;
            data[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0x58, 0xC3]);
        }

        let _ = base; // unused: no real process-memory acquisition
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub name: String,
    pub base_address: u64,
    pub size: u64,
    pub permissions: String,
    pub module_name: Option<String>,
}

impl MemoryRegion {
    pub fn is_executable(&self) -> bool {
        self.permissions.contains('E') || self.permissions.contains('X')
    }

    pub fn is_writable(&self) -> bool {
        self.permissions.contains('W')
    }

    pub fn is_readable(&self) -> bool {
        self.permissions.contains('R')
    }

    pub fn is_rwx(&self) -> bool {
        self.permissions.contains("RWX") || self.permissions.contains("EXECUTE_READWRITE")
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for MemoryScanner {
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
        match self.mode {
            MemoryScanMode::Unsupported => Err(VestError::Unsupported(
                "Real process-memory acquisition is not implemented; pass --allow-memory-simulation to run the explicit simulation harness"
                    .into(),
            )),
            MemoryScanMode::Simulation => self.scan_simulation(target).await,
        }
    }
}

impl MemoryScanner {
    /// Explicit simulation harness — fabricated regions and bytes only.
    async fn scan_simulation(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let platform = MemoryScanner::detect_platform();
        tracing::warn!(
            platform = platform,
            target_id = %target.id,
            pid = ?target.pid,
            "Running MEMORY SIMULATION harness (not real process acquisition; PID is not used)"
        );

        let mut all_findings = Vec::new();

        let regions = MemoryScanner::get_simulated_regions(platform);
        tracing::info!("Simulated {} memory regions", regions.len());

        if !self.suspicious_regions.is_empty() {
            let suspicious = MemoryScanner::check_suspicious_regions(&regions);
            all_findings.extend(suspicious);
        }

        if self.hook_detection {
            let mut region_data: Vec<(&MemoryRegion, Vec<u8>)> = Vec::new();
            for region in &regions {
                if region.is_executable()
                    && region.size <= self.max_memory_per_scan_mb * 1024 * 1024
                {
                    let data = MemoryScanner::fabricate_simulated_memory(
                        region.base_address,
                        region.size.min(4096) as usize,
                    );
                    region_data.push((region, data));
                }
            }

            let hook_findings = MemoryScanner::detect_hooks(&region_data);
            all_findings.extend(hook_findings);
        }

        for f in &mut all_findings {
            f.target_id = target.id.clone();
            Self::mark_finding_simulated(f);
        }

        tracing::info!(
            "Memory SIMULATION complete: {} total findings (all tagged simulation=true)",
            all_findings.len()
        );
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_scan_simple() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03];
        let pattern = "01 02 03";
        let matches = MemoryScanner::scan_pattern(&data, pattern);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], 1);
        assert_eq!(matches[1], 5);
    }

    #[test]
    fn test_pattern_scan_with_wildcards() {
        let data = vec![
            0xE9, 0x45, 0x23, 0x01, 0x00, 0x90, 0xE9, 0x67, 0x45, 0x23, 0x00,
        ];
        let pattern = "E9 ?? ?? ?? ??";
        let matches = MemoryScanner::scan_pattern(&data, pattern);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_pattern_scan_no_match() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let pattern = "FF FF FF";
        let matches = MemoryScanner::scan_pattern(&data, pattern);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_pattern_scan_fast_equivalent() {
        let data: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        let pattern = "64 65 66";
        let slow = MemoryScanner::scan_pattern(&data, pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
        assert_eq!(slow, fast);
    }

    #[test]
    fn test_pattern_scan_empty_pattern() {
        let data = vec![0x00, 0x01];
        let matches = MemoryScanner::scan_pattern(&data, "");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_value() {
        let data = vec![0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42, 0x00];
        let matches = MemoryScanner::scan_value(&data, &[0x42]);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_find_pointers() {
        let mut data = vec![0u8; 100];
        let target_addr: u64 = 0xDEADBEEF;
        let addr_bytes = target_addr.to_le_bytes();
        data[10..18].copy_from_slice(&addr_bytes);
        data[50..58].copy_from_slice(&addr_bytes);

        let pointers = MemoryScanner::find_pointers(&data, target_addr, 0x1000);
        assert_eq!(pointers.len(), 2);
        assert_eq!(pointers[0], 0x1000 + 10);
        assert_eq!(pointers[1], 0x1000 + 50);
    }

    #[test]
    fn test_memory_region_is_rwx() {
        let rwx = MemoryRegion {
            name: "".into(),
            base_address: 0,
            size: 0,
            permissions: "RWX".into(),
            module_name: None,
        };
        assert!(rwx.is_rwx());

        let rx = MemoryRegion {
            name: "".into(),
            base_address: 0,
            size: 0,
            permissions: "RX".into(),
            module_name: None,
        };
        assert!(!rx.is_rwx());
    }

    #[test]
    fn test_check_suspicious_regions() {
        let regions = vec![
            MemoryRegion {
                name: "code".into(),
                base_address: 0x1000,
                size: 4096,
                permissions: "RX".into(),
                module_name: Some("game.exe".into()),
            },
            MemoryRegion {
                name: "".into(),
                base_address: 0x5000,
                size: 4096,
                permissions: "RWX".into(),
                module_name: None,
            },
        ];
        let findings = MemoryScanner::check_suspicious_regions(&regions);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("Suspicious")));
    }

    #[test]
    fn test_get_simulated_regions_windows() {
        let regions = MemoryScanner::get_simulated_regions("windows");
        assert!(!regions.is_empty());
        assert!(regions.iter().any(|r| r.is_rwx()));
    }

    #[test]
    fn test_get_simulated_regions_linux() {
        let regions = MemoryScanner::get_simulated_regions("linux");
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_detect_platform() {
        let platform = MemoryScanner::detect_platform();
        assert!(!platform.is_empty());
        assert!(
            platform != "unknown"
                || cfg!(not(any(
                    target_os = "windows",
                    target_os = "linux",
                    target_os = "macos"
                )))
        );
    }

    #[test]
    fn test_detect_hooks() {
        let regions = [MemoryRegion {
            name: "game.exe".into(),
            base_address: 0x1000,
            size: 4096,
            permissions: "RX".into(),
            module_name: Some("game.exe".into()),
        }];
        let mut data = vec![0x90u8; 1024];
        data[0x100] = 0xE9;
        data[0x101] = 0x45;
        data[0x102] = 0x23;
        data[0x103] = 0x01;
        data[0x104] = 0x00;
        data[0x200] = 0x6A;
        data[0x201] = 0x02;
        data[0x202] = 0x5B;
        data[0x203] = 0xB8;
        let region_data = vec![(&regions[0], data)];
        let findings = MemoryScanner::detect_hooks(&region_data);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scanner_default_values() {
        let scanner = MemoryScanner::new();
        assert!(scanner.enabled);
        assert!(scanner.hook_detection);
        assert!(scanner.pattern_scan_acceleration);
        assert_eq!(scanner.max_memory_per_scan_mb, 4096);
        assert_eq!(scanner.mode(), MemoryScanMode::Unsupported);
    }

    #[tokio::test]
    async fn test_scan_default_returns_unsupported() {
        use vest_core::traits::Scanner;
        let scanner = MemoryScanner::new();
        let target = Target {
            id: "t".into(),
            name: "t".into(),
            target_type: vest_core::types::TargetType::Process,
            path: None,
            url_str: None,
            pid: Some(1234),
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let err = scanner.scan(&target).await.unwrap_err();
        assert!(
            matches!(err, VestError::Unsupported(_)),
            "expected Unsupported, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("not implemented"));
        assert!(msg.contains("--allow-memory-simulation"));
    }

    #[tokio::test]
    async fn test_scan_simulation_tags_findings() {
        use vest_core::traits::Scanner;
        let scanner = MemoryScanner::new().with_simulation_allowed(true);
        assert_eq!(scanner.mode(), MemoryScanMode::Simulation);
        let target = Target {
            id: "sim-target".into(),
            name: "sim".into(),
            target_type: vest_core::types::TargetType::Process,
            path: None,
            url_str: None,
            pid: Some(9999),
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let findings = scanner.scan(&target).await.unwrap();
        assert!(
            !findings.is_empty(),
            "simulation harness should produce findings on known platforms"
        );
        for f in &findings {
            assert_eq!(f.target_id, "sim-target");
            assert!(
                f.title.contains("SIMULATED"),
                "title must say SIMULATED: {}",
                f.title
            );
            assert!(
                f.description.starts_with("SIMULATED:"),
                "description must say SIMULATED: {}",
                f.description
            );
            assert_eq!(f.metadata["simulation"], serde_json::json!(true));
            assert!(f.tags.iter().any(|t| t == "simulation"));
        }
    }

    #[test]
    fn test_read_memory_is_fabricated_not_pid_backed() {
        // Same fabricated pattern regardless of base — proves no real acquisition.
        let a = MemoryScanner::read_memory(0x1000, 64);
        let b = MemoryScanner::fabricate_simulated_memory(0xDEAD_BEEF, 64);
        assert_eq!(a, b);
    }

    #[test]
    fn test_pattern_scan_fast_wildcard_leading_fixed() {
        let data = vec![0x42, 0x41, 0x42, 0x43];
        let pattern = "?? 41 42";
        let slow = MemoryScanner::scan_pattern(&data, pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
        assert_eq!(slow, fast, "Mismatch for wildcard-leading pattern");
    }

    #[test]
    fn test_pattern_scan_fast_multiple_leading_wildcards() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x41, 0x42];
        let pattern = "?? ?? ?? 41 42";
        let slow = MemoryScanner::scan_pattern(&data, pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
        assert_eq!(slow, fast);
    }

    #[test]
    fn test_pattern_scan_fast_wildcards_at_both_ends() {
        let data = vec![0x00, 0x41, 0x42, 0x00, 0x41, 0x42, 0x00];
        let pattern = "?? 41 42 ??";
        let slow = MemoryScanner::scan_pattern(&data, pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
        assert_eq!(slow, fast);
    }

    #[test]
    fn test_pattern_scan_fast_wildcard_only_leading_no_match() {
        let data = vec![0x41, 0x43, 0x42];
        let pattern = "?? 41 42";
        let slow = MemoryScanner::scan_pattern(&data, pattern);
        let fast = MemoryScanner::scan_pattern_fast(&data, pattern);
        assert_eq!(slow, fast);
        assert!(slow.is_empty());
    }
}
