use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

pub struct BinaryScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub sink_catalogs: Vec<String>,
    pub check_mitigations: bool,
    pub find_rop_gadgets: bool,
}

impl BinaryScanner {
    pub fn new() -> Self {
        Self {
            name: "binary-scanner".into(),
            description:
                "Scans binary files for vulnerabilities using goblin, capstone, and sink catalog matching"
                    .into(),
            enabled: true,
            sink_catalogs: vec![],
            check_mitigations: true,
            find_rop_gadgets: false,
        }
    }

    pub fn with_sink_catalogs(mut self, catalogs: Vec<String>) -> Self {
        self.sink_catalogs = catalogs;
        self
    }

    pub fn with_mitigations(mut self, check: bool) -> Self {
        self.check_mitigations = check;
        self
    }

    pub fn with_rop(mut self, find: bool) -> Self {
        self.find_rop_gadgets = find;
        self
    }

    fn load_sink_catalog(path: &Path) -> Result<Vec<String>, VestError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            VestError::Config(format!(
                "Failed to read sink catalog {}: {}",
                path.display(),
                e
            ))
        })?;
        let sinks: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        Ok(sinks)
    }

    fn parse_binary(&self, path: &Path) -> Result<BinaryInfo, VestError> {
        let data = std::fs::read(path).map_err(VestError::Io)?;

        if let Ok(elf) = goblin::elf::Elf::parse(&data) {
            return Ok(BinaryInfo::from_elf(&elf, path));
        }
        if let Ok(pe) = goblin::pe::PE::parse(&data) {
            return Ok(BinaryInfo::from_pe(&pe, &data, path));
        }
        if let Ok(macho) = goblin::mach::Mach::parse(&data) {
            return Ok(BinaryInfo::from_mach(&macho, path));
        }

        Err(VestError::UnsupportedFormat(format!(
            "Could not parse {} as ELF, PE, or Mach-O",
            path.display()
        )))
    }

    fn scan_sinks(&self, binary: &BinaryInfo) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen: HashMap<String, Vec<String>> = HashMap::new();

        for catalog_path in &self.sink_catalogs {
            let path = Path::new(catalog_path);
            let sinks = match Self::load_sink_catalog(path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to load sink catalog {}: {}", catalog_path, e);
                    continue;
                }
            };

            for sink in &sinks {
                for sym in &binary.symbols {
                    if sym.contains(sink.as_str()) || sym.eq_ignore_ascii_case(sink) {
                        seen.entry(sink.clone())
                            .or_default()
                            .push(format!("symbol:{}", sym));
                    }
                }
                for s in &binary.strings {
                    if s.contains(sink.as_str()) {
                        seen.entry(sink.clone())
                            .or_default()
                            .push(format!("string:{}", s));
                    }
                }
            }
        }

        let now = chrono::Utc::now();
        for (sink_name, locations) in &seen {
            if locations.is_empty() {
                continue;
            }
            let severity = match sink_name.to_lowercase().as_str() {
                "strcpy" | "strcat" | "gets" | "sprintf" | "system" | "popen" => Severity::High,
                "memcpy" | "strncpy" | "malloc" | "fopen" => Severity::Medium,
                _ => Severity::Low,
            };

            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: format!("Potentially dangerous function: {}", sink_name),
                description: format!(
                    "Found {} reference(s) to '{}' in binary. This function may lead to vulnerabilities with untrusted input.",
                    locations.len(),
                    sink_name
                ),
                vulnerability_class: VulnerabilityClass::BufferOverflow,
                severity,
                confidence: 0.7,
                status: FindingStatus::Open,
                cvss_score: None,
                cve_id: None,
                cwe_id: Some("CWE-120".into()),
                evidence: serde_json::json!({
                    "function": sink_name,
                    "locations": locations,
                }),
                poc: None,
                remediation: Some(format!(
                    "Replace '{}' with a safer alternative. Use bounds-checked functions and validate all input lengths.",
                    sink_name
                )),
                location: serde_json::json!({
                    "file": binary.path.to_string_lossy(),
                    "type": "binary",
                }),
                false_positive_history: None,
                tags: vec!["sink-catalog".into(), "static-analysis".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        findings
    }

    fn check_mitigations(&self, binary: &BinaryInfo) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        if !binary.mitigations.nx_enabled {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: "NX/DEP (Data Execution Prevention) not enabled".into(),
                description: "The binary has executable stack or writable+executable sections, making it vulnerable to stack/heap code injection attacks.".into(),
                vulnerability_class: VulnerabilityClass::DEPBypass,
                severity: Severity::High,
                confidence: 0.95,
                status: FindingStatus::Open,
                cvss_score: Some(7.8),
                cve_id: None,
                cwe_id: Some("CWE-122".into()),
                evidence: serde_json::json!({"format": binary.format, "nx": false}),
                poc: None,
                remediation: Some("Compile with -z noexecstack (ELF), /NXCOMPAT (PE), or -Wl,-no_pie equivalent flags.".into()),
                location: serde_json::json!({"file": binary.path.to_string_lossy()}),
                false_positive_history: None,
                tags: vec!["mitigation".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        if !binary.mitigations.aslr_enabled {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: "ASLR/PIE (Address Space Layout Randomization) not enabled".into(),
                description: "The binary is not position-independent, making it easier to predict memory addresses for exploits.".into(),
                vulnerability_class: VulnerabilityClass::ASLRBypass,
                severity: Severity::Medium,
                confidence: 0.95,
                status: FindingStatus::Open,
                cvss_score: Some(6.2),
                cve_id: None,
                cwe_id: Some("CWE-122".into()),
                evidence: serde_json::json!({"format": binary.format, "aslr": false}),
                poc: None,
                remediation: Some("Compile with -fPIE -pie (ELF), /DYNAMICBASE (PE), or equivalent flags.".into()),
                location: serde_json::json!({"file": binary.path.to_string_lossy()}),
                false_positive_history: None,
                tags: vec!["mitigation".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        if !binary.mitigations.stack_canaries {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: "Stack canaries not enabled".into(),
                description: "The binary does not use stack canaries, making it vulnerable to stack buffer overflow attacks.".into(),
                vulnerability_class: VulnerabilityClass::StackCanaryBypass,
                severity: Severity::Medium,
                confidence: 0.9,
                status: FindingStatus::Open,
                cvss_score: Some(5.6),
                cve_id: None,
                cwe_id: Some("CWE-121".into()),
                evidence: serde_json::json!({"format": binary.format, "canaries": false}),
                poc: None,
                remediation: Some("Compile with -fstack-protector-strong or /GS (MSVC).".into()),
                location: serde_json::json!({"file": binary.path.to_string_lossy()}),
                false_positive_history: None,
                tags: vec!["mitigation".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        if binary.format == "pe" && !binary.mitigations.safe_seh {
            findings.push(Finding {
                id: new_id(),
                scan_id: String::new(),
                target_id: String::new(),
                title: "SafeSEH not enabled (Windows)".into(),
                description: "The PE binary does not use SafeSEH, making it vulnerable to SEH overwrite attacks.".into(),
                vulnerability_class: VulnerabilityClass::SEHOverwrite,
                severity: Severity::Medium,
                confidence: 0.85,
                status: FindingStatus::Open,
                cvss_score: Some(5.5),
                cve_id: None,
                cwe_id: Some("CWE-122".into()),
                evidence: serde_json::json!({"format": "pe", "safeseh": false}),
                poc: None,
                remediation: Some("Compile with /SAFESEH linker flag.".into()),
                location: serde_json::json!({"file": binary.path.to_string_lossy()}),
                false_positive_history: None,
                tags: vec!["mitigation".into(), "windows".into()],
                metadata: serde_json::json!({}),
                discovered_at: now,
                updated_at: now,
            });
        }

        findings
    }

    fn find_rop_gadgets(&self, binary: &BinaryInfo) -> Result<Vec<Finding>, VestError> {
        let data = std::fs::read(&binary.path).map_err(VestError::Io)?;

        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        for section in &binary.executable_sections {
            if section.offset + section.size > data.len() as u64 {
                continue;
            }
            let start = section.offset as usize;
            let end = (section.offset + section.size) as usize;
            let section_data = &data[start..end];

            let mut gadget_count = 0u32;
            let mut example_gadgets: Vec<String> = Vec::new();

            for i in 0..section_data.len().saturating_sub(1) {
                if section_data[i] == 0xC3
                    || (i + 1 < section_data.len() && section_data[i] == 0xC2)
                {
                    let mut offset = i;
                    let max_back = 20usize.min(i);
                    for _ in 0..max_back {
                        if offset == 0 {
                            break;
                        }
                        offset -= 1;
                        if section_data[offset] == 0x90 || section_data[offset] == 0xCC {
                            break;
                        }
                    }

                    let gadget_len = (i - offset).min(32);
                    let gadget_bytes = &section_data[offset..=i.min(offset + gadget_len)];

                    gadget_count += 1;
                    if example_gadgets.len() < 5 {
                        example_gadgets.push(format!(
                            "0x{:x}: {}",
                            section.offset as usize + offset,
                            gadget_bytes
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ")
                        ));
                    }
                }
            }

            if gadget_count > 0 {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!(
                        "ROP gadgets found in section '{}': {} gadgets",
                        section.name, gadget_count
                    ),
                    description: format!(
                        "Found {} potential ROP gadgets in the '{}' section. Example: {}",
                        gadget_count,
                        section.name,
                        example_gadgets
                            .iter()
                            .take(3)
                            .map(|g| g.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                    vulnerability_class: VulnerabilityClass::ROPGadget,
                    severity: Severity::Medium,
                    confidence: 0.8,
                    status: FindingStatus::Open,
                    cvss_score: Some(5.0),
                    cve_id: None,
                    cwe_id: Some("CWE-122".into()),
                    evidence: serde_json::json!({
                        "section": section.name,
                        "gadget_count": gadget_count,
                        "examples": example_gadgets,
                    }),
                    poc: None,
                    remediation: Some(
                        "Enable Control Flow Guard (CFG) / CET, or use compiler flags like -fcf-protection."
                            .into(),
                    ),
                    location: serde_json::json!({"file": binary.path.to_string_lossy(), "section": section.name}),
                    false_positive_history: None,
                    tags: vec!["rop".into(), "gadgets".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        Ok(findings)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BinaryInfo {
    path: std::path::PathBuf,
    format: String,
    architecture: String,
    symbols: Vec<String>,
    strings: Vec<String>,
    executable_sections: Vec<SectionInfo>,
    mitigations: MitigationInfo,
    entry_point: Option<u64>,
    is_pie: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct SectionInfo {
    name: String,
    offset: u64,
    size: u64,
    is_executable: bool,
    is_writable: bool,
}

#[derive(Debug, Clone, Default)]
struct MitigationInfo {
    nx_enabled: bool,
    aslr_enabled: bool,
    stack_canaries: bool,
    safe_seh: bool,
}

impl BinaryInfo {
    fn from_elf(elf: &goblin::elf::Elf, path: &Path) -> Self {
        let symbols: Vec<String> = elf
            .syms
            .iter()
            .filter_map(|sym| elf.strtab.get_at(sym.st_name).map(|s| s.to_string()))
            .collect();

        let strings: Vec<String> = Vec::new();

        let executable_sections: Vec<SectionInfo> = elf
            .section_headers
            .iter()
            .map(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                let is_exec =
                    (sh.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64) != 0;
                let is_write = (sh.sh_flags & goblin::elf::section_header::SHF_WRITE as u64) != 0;
                SectionInfo {
                    name,
                    offset: sh.sh_offset,
                    size: sh.sh_size,
                    is_executable: is_exec,
                    is_writable: is_write,
                }
            })
            .filter(|s| s.is_executable)
            .collect();

        let nx_enabled = elf.program_headers.iter().any(|ph| {
            ph.p_type == goblin::elf::program_header::PT_GNU_STACK
                && (ph.p_flags & goblin::elf::program_header::PF_X) == 0
        });

        let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;

        let stack_canaries = symbols
            .iter()
            .any(|s| s.contains("__stack_chk") || s.contains("__stack_smash_handler"));

        let arch = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64".into(),
            goblin::elf::header::EM_386 => "x86".into(),
            goblin::elf::header::EM_AARCH64 => "aarch64".into(),
            m => format!("machine_{}", m),
        };

        Self {
            path: path.to_path_buf(),
            format: "elf".into(),
            architecture: arch,
            symbols,
            strings,
            executable_sections,
            mitigations: MitigationInfo {
                nx_enabled,
                aslr_enabled: is_pie,
                stack_canaries,
                safe_seh: true,
            },
            entry_point: Some(elf.header.e_entry),
            is_pie,
        }
    }

    fn from_pe(pe: &goblin::pe::PE, data: &[u8], path: &Path) -> Self {
        let symbols: Vec<String> = pe
            .exports
            .iter()
            .flat_map(|e| e.name.map(|n| n.to_string()))
            .collect();

        let imports: Vec<String> = pe.imports.iter().map(|imp| imp.name.to_string()).collect();

        let all_symbols: Vec<String> = symbols.into_iter().chain(imports).collect();

        let executable_sections: Vec<SectionInfo> = pe
            .sections
            .iter()
            .map(|s| {
                let characteristics = s.characteristics;
                SectionInfo {
                    name: s.name().unwrap_or("").to_string(),
                    offset: s.pointer_to_raw_data as u64,
                    size: s.size_of_raw_data as u64,
                    is_executable: characteristics & 0x20000000 != 0,
                    is_writable: characteristics & 0x80000000 != 0,
                }
            })
            .filter(|s| s.is_executable)
            .collect();

        let dll_chars = pe
            .header
            .optional_header
            .as_ref()
            .map(|oh| oh.windows_fields.dll_characteristics)
            .unwrap_or(0);

        let nx_enabled = dll_chars & 0x0100 != 0;
        let aslr_enabled = dll_chars & 0x0040 != 0;
        let safe_seh = false;

        let stack_canaries = all_symbols
            .iter()
            .any(|s| s.contains("__security_check") || s.contains("__GSHandlerCheck"));

        let strings: Vec<String> = pe
            .sections
            .iter()
            .filter(|s| {
                let name = s.name().unwrap_or("");
                name == ".rdata" || name == ".data"
            })
            .flat_map(|s| {
                let start = s.pointer_to_raw_data as usize;
                let end = (start + s.size_of_raw_data as usize).min(data.len());
                if start < end {
                    extract_strings(&data[start..end])
                } else {
                    Vec::new()
                }
            })
            .collect();

        Self {
            path: path.to_path_buf(),
            format: "pe".into(),
            architecture: if pe.is_64 {
                "x86_64".into()
            } else {
                "x86".into()
            },
            symbols: all_symbols,
            strings,
            executable_sections,
            mitigations: MitigationInfo {
                nx_enabled,
                aslr_enabled,
                stack_canaries,
                safe_seh,
            },
            entry_point: Some(pe.entry as u64),
            is_pie: false,
        }
    }

    fn from_mach(_mach: &goblin::mach::Mach, path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            format: "macho".into(),
            architecture: "unknown".into(),
            symbols: vec![],
            strings: vec![],
            executable_sections: vec![],
            mitigations: MitigationInfo {
                nx_enabled: true,
                aslr_enabled: true,
                stack_canaries: true,
                safe_seh: true,
            },
            entry_point: Some(0),
            is_pie: true,
        }
    }
}

fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for &byte in data {
        if (0x20..0x7f).contains(&byte) {
            current.push(byte);
        } else {
            if current.len() >= 4 {
                strings.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        strings.push(String::from_utf8_lossy(&current).to_string());
    }
    strings
}

impl Default for BinaryScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for BinaryScanner {
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
            Some(p) => Path::new(p),
            None => return Err(VestError::Config("Binary target requires a path".into())),
        };

        if !path.exists() {
            return Err(VestError::Config(format!(
                "Binary file not found: {}",
                path.display()
            )));
        }

        tracing::info!("Starting binary scan of: {}", path.display());

        let binary = self.parse_binary(path)?;
        tracing::info!(
            "Detected format: {}, arch: {}",
            binary.format,
            binary.architecture
        );

        let mut all_findings = Vec::new();

        let set_target = |mut findings: Vec<Finding>, tid: &str| -> Vec<Finding> {
            for f in &mut findings {
                f.target_id = tid.to_string();
                if f.scan_id.is_empty() {
                    f.scan_id = "binary-scan".into();
                }
            }
            findings
        };

        if !self.sink_catalogs.is_empty() {
            tracing::info!(
                "Running sink catalog matching with {} catalogs",
                self.sink_catalogs.len()
            );
            let sink_findings = self.scan_sinks(&binary);
            tracing::info!(
                "Found {} potential dangerous function references",
                sink_findings.len()
            );
            all_findings.extend(set_target(sink_findings, &target.id));
        }

        if self.check_mitigations {
            tracing::info!("Checking security mitigations");
            let mit_findings = self.check_mitigations(&binary);
            tracing::info!("Found {} missing mitigations", mit_findings.len());
            all_findings.extend(set_target(mit_findings, &target.id));
        }

        if self.find_rop_gadgets {
            tracing::info!("Scanning for ROP gadgets (this may take a while)");
            match self.find_rop_gadgets(&binary) {
                Ok(rop_findings) => {
                    tracing::info!("Found {} ROP gadget sections", rop_findings.len());
                    all_findings.extend(set_target(rop_findings, &target.id));
                }
                Err(e) => {
                    tracing::warn!("ROP gadget scanning failed: {}", e);
                }
            }
        }

        tracing::info!(
            "Binary scan complete: {} total findings",
            all_findings.len()
        );
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_sink_catalog() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_sinks_c.txt");
        std::fs::write(&path, "# Comment\nstrcpy\nstrcat\ngets\nsystem\n").unwrap();

        let sinks = BinaryScanner::load_sink_catalog(&path).unwrap();
        assert!(sinks.contains(&"strcpy".to_string()));
        assert!(sinks.contains(&"gets".to_string()));
        assert!(!sinks.contains(&"Comment".to_string()));
        assert_eq!(sinks.len(), 4);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_sink_catalog_empty_lines() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_sinks_empty.txt");
        std::fs::write(&path, "\n\n# comment\n\nstrcpy\n\n").unwrap();

        let sinks = BinaryScanner::load_sink_catalog(&path).unwrap();
        assert_eq!(sinks, vec!["strcpy"]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_nonexistent_catalog() {
        let result = BinaryScanner::load_sink_catalog(Path::new("/nonexistent/path.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_strings() {
        let data = b"Hello World\x00Test String\x00ABC";
        let strings = extract_strings(&data[..]);
        assert!(strings.contains(&"Hello World".to_string()));
        assert!(strings.contains(&"Test String".to_string()));
        assert!(!strings.iter().any(|s| s == "ABC"));
    }

    #[test]
    fn test_extract_strings_binary_data() {
        let mut data = vec![0x00u8; 100];
        data[10..15].copy_from_slice(b"hello");
        data[50..61].copy_from_slice(b"binary_test");
        let strings = extract_strings(&data);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"binary_test".to_string()));
    }

    #[test]
    fn test_scanner_rejects_nonexistent_path() {
        let scanner = BinaryScanner::new();
        let target = Target {
            id: "test".into(),
            name: "nonexistent.exe".into(),
            target_type: vest_core::types::TargetType::Binary,
            path: Some("/definitely/not/real/binary".into()),
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
    fn test_scanner_rejects_no_path() {
        let scanner = BinaryScanner::new();
        let target = Target {
            id: "test".into(),
            name: "notarget".into(),
            target_type: vest_core::types::TargetType::Binary,
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

    #[test]
    fn test_sinks_not_run_when_no_catalogs() {
        let scanner = BinaryScanner::new();
        let binary = BinaryInfo {
            path: Path::new("/fake/path").to_path_buf(),
            format: "elf".into(),
            architecture: "x86_64".into(),
            symbols: vec!["strcpy".into()],
            strings: vec![],
            executable_sections: vec![],
            mitigations: MitigationInfo::default(),
            entry_point: None,
            is_pie: false,
        };
        let findings = scanner.scan_sinks(&binary);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_default_values() {
        let scanner = BinaryScanner::new();
        assert!(scanner.enabled);
        assert_eq!(scanner.name, "binary-scanner");
        assert!(scanner.check_mitigations);
        assert!(!scanner.find_rop_gadgets);
    }

    #[test]
    fn test_mitigation_info_default() {
        let info = MitigationInfo::default();
        assert!(!info.nx_enabled);
        assert!(!info.aslr_enabled);
        assert!(!info.stack_canaries);
        assert!(!info.safe_seh);
    }
}
