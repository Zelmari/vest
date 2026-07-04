use async_trait::async_trait;
use vest_core::error::VestError;
use vest_core::ids::new_id;
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::Scanner;

pub struct NetworkScanner {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub check_ports: bool,
    pub check_tls: bool,
    pub check_dns: bool,
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            name: "network-scanner".into(),
            description: "Scans network targets for port, TLS, and DNS vulnerabilities".into(),
            enabled: true,
            check_ports: true,
            check_tls: true,
            check_dns: true,
        }
    }

    pub fn with_ports(mut self, check: bool) -> Self {
        self.check_ports = check;
        self
    }

    pub fn with_tls(mut self, check: bool) -> Self {
        self.check_tls = check;
        self
    }

    pub fn with_dns(mut self, check: bool) -> Self {
        self.check_dns = check;
        self
    }

    fn analyze_ports(&self, _host: &str, metadata: &serde_json::Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let dangerous_ports: Vec<(&str, u16, &str, Severity)> = vec![
            (
                "FTP",
                21,
                "FTP transmits credentials in cleartext",
                Severity::High,
            ),
            (
                "Telnet",
                23,
                "Telnet transmits all data in cleartext",
                Severity::Critical,
            ),
            (
                "SMTP",
                25,
                "Open SMTP relay may be abused for spam",
                Severity::Medium,
            ),
            ("DNS", 53, "DNS service exposed to public", Severity::Medium),
            (
                "RDP",
                3389,
                "RDP exposed to network; brute-force target",
                Severity::High,
            ),
            (
                "MySQL",
                3306,
                "Database port exposed to network",
                Severity::Critical,
            ),
            (
                "PostgreSQL",
                5432,
                "Database port exposed to network",
                Severity::Critical,
            ),
            (
                "MongoDB",
                27017,
                "NoSQL database exposed to network",
                Severity::Critical,
            ),
            (
                "Redis",
                6379,
                "In-memory store exposed to network",
                Severity::Critical,
            ),
            (
                "SMB",
                445,
                "SMB exposed to network; ransomware target",
                Severity::Critical,
            ),
            (
                "NetBIOS",
                139,
                "Legacy NetBIOS service exposed",
                Severity::Medium,
            ),
            (
                "MSRPC",
                135,
                "Microsoft RPC endpoint exposed",
                Severity::Medium,
            ),
            (
                "VNC",
                5900,
                "Remote desktop exposed without encryption",
                Severity::High,
            ),
            (
                "Docker",
                2375,
                "Docker daemon exposed without TLS",
                Severity::Critical,
            ),
            (
                "Kubernetes",
                6443,
                "Kubernetes API server exposed",
                Severity::High,
            ),
        ];

        if let Some(ports) = metadata.get("open_ports").and_then(|v| v.as_array()) {
            for port_entry in ports {
                let port_num = port_entry.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let protocol = port_entry
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                for (service_name, svc_port, reason, severity) in &dangerous_ports {
                    if port_num == *svc_port {
                        findings.push(Finding {
                            id: new_id(),
                            scan_id: String::new(),
                            target_id: String::new(),
                            title: format!(
                                "Dangerous service exposed: {} (port {})",
                                service_name, svc_port
                            ),
                            description: format!(
                                "Port {} ({}) is open. {}.",
                                svc_port, service_name, reason
                            ),
                            vulnerability_class: VulnerabilityClass::Unknown,
                            severity: *severity,
                            confidence: 0.9,
                            status: FindingStatus::Open,
                            cvss_score: match severity {
                                Severity::Critical => Some(9.0),
                                Severity::High => Some(7.5),
                                Severity::Medium => Some(5.0),
                                _ => Some(3.0),
                            },
                            cve_id: None,
                            cwe_id: Some("CWE-200".into()),
                            evidence: serde_json::json!({
                                "port": svc_port,
                                "service": service_name,
                                "detected_service": protocol,
                            }),
                            poc: None,
                            remediation: Some(format!(
                                "Restrict access to port {} using firewall rules. Disable {} if not required, or require authentication and encryption.",
                                svc_port, service_name
                            )),
                            location: serde_json::json!({
                                "port": svc_port,
                                "service": service_name,
                            }),
                            false_positive_history: None,
                            tags: vec!["network".into(), "port".into(), "exposed-service".into()],
                            metadata: serde_json::json!({}),
                            discovered_at: now,
                            updated_at: now,
                        });
                    }
                }
            }
        }

        if let Some(port_list) = metadata.get("ports").and_then(|v| v.as_array()) {
            for port in port_list {
                let port_num = port.as_u64().unwrap_or(0) as u16;
                for (service_name, svc_port, reason, severity) in &dangerous_ports {
                    if port_num == *svc_port {
                        let already_found = findings.iter().any(|f| {
                            f.evidence.get("port").and_then(|v| v.as_u64())
                                == Some(*svc_port as u64)
                        });
                        if !already_found {
                            findings.push(Finding {
                                id: new_id(),
                                scan_id: String::new(),
                                target_id: String::new(),
                                title: format!(
                                    "Dangerous service exposed: {} (port {})",
                                    service_name, svc_port
                                ),
                                description: format!(
                                    "Port {} ({}) is open. {}.",
                                    svc_port, service_name, reason
                                ),
                                vulnerability_class: VulnerabilityClass::Unknown,
                                severity: *severity,
                                confidence: 0.9,
                                status: FindingStatus::Open,
                                cvss_score: match severity {
                                    Severity::Critical => Some(9.0),
                                    Severity::High => Some(7.5),
                                    Severity::Medium => Some(5.0),
                                    _ => Some(3.0),
                                },
                                cve_id: None,
                                cwe_id: Some("CWE-200".into()),
                                evidence: serde_json::json!({
                                    "port": svc_port,
                                    "service": service_name,
                                }),
                                poc: None,
                                remediation: Some(format!(
                                    "Restrict access to port {}. Disable {} if not required.",
                                    svc_port, service_name
                                )),
                                location: serde_json::json!({
                                    "port": svc_port,
                                    "service": service_name,
                                }),
                                false_positive_history: None,
                                tags: vec![
                                    "network".into(),
                                    "port".into(),
                                    "exposed-service".into(),
                                ],
                                metadata: serde_json::json!({}),
                                discovered_at: now,
                                updated_at: now,
                            });
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            if let Some(hostname) = metadata.get("hostname").or_else(|| metadata.get("host")) {
                let host = hostname.as_str().unwrap_or("unknown");
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("No port data available for host: {}", host),
                    description: "No open port information found in target metadata. A port scan is recommended to identify exposed services.".into(),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: Severity::Info,
                    confidence: 0.3,
                    status: FindingStatus::Open,
                    cvss_score: None,
                    cve_id: None,
                    cwe_id: None,
                    evidence: serde_json::json!({ "host": host }),
                    poc: None,
                    remediation: Some("Run a port scan (e.g., nmap) to discover open ports and services.".into()),
                    location: serde_json::json!({ "host": host }),
                    false_positive_history: None,
                    tags: vec!["network".into(), "port-scan-recommended".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        findings
    }

    fn analyze_tls(&self, _target: &Target, metadata: &serde_json::Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        let tls_info = metadata.get("tls").or_else(|| metadata.get("tls_config"));

        if let Some(tls) = tls_info {
            if let Some(version) = tls.get("version").and_then(|v| v.as_str()) {
                if version.contains("1.0") || version.contains("1.1") {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: format!("Deprecated TLS version in use: {}", version),
                        description: format!(
                            "TLS {} is obsolete and contains known vulnerabilities (POODLE, BEAST, etc.). Upgrade to TLS 1.2 or TLS 1.3.",
                            version
                        ),
                        vulnerability_class: VulnerabilityClass::ProtocolExploit,
                        severity: Severity::High,
                        confidence: 0.95,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.4),
                        cve_id: None,
                        cwe_id: Some("CWE-326".into()),
                        evidence: serde_json::json!({
                            "tls_version": version,
                        }),
                        poc: None,
                        remediation: Some("Upgrade to TLS 1.2 minimum, preferably TLS 1.3. Disable TLS 1.0 and 1.1 in server configuration.".into()),
                        location: serde_json::json!({ "tls_version": version }),
                        false_positive_history: None,
                        tags: vec!["tls".into(), "encryption".into(), "deprecated".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }

            if let Some(ciphers) = tls.get("ciphers").and_then(|v| v.as_array()) {
                let weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"];
                let mut found_weak = Vec::new();

                for cipher in ciphers {
                    let cipher_str = cipher.as_str().unwrap_or("");
                    for weak in &weak_ciphers {
                        if cipher_str.to_uppercase().contains(weak) {
                            found_weak.push(cipher_str.to_string());
                            break;
                        }
                    }
                }

                if !found_weak.is_empty() {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: format!("Weak cipher suites detected ({} found)", found_weak.len()),
                        description: format!(
                            "Weak cipher suites detected: {}. These ciphers are cryptographically broken and should be disabled.",
                            found_weak.join(", ")
                        ),
                        vulnerability_class: VulnerabilityClass::ProtocolExploit,
                        severity: Severity::High,
                        confidence: 0.9,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.0),
                        cve_id: None,
                        cwe_id: Some("CWE-327".into()),
                        evidence: serde_json::json!({
                            "weak_ciphers": found_weak,
                        }),
                        poc: None,
                        remediation: Some("Disable weak cipher suites. Use only strong ciphers such as AES-GCM or ChaCha20-Poly1305.".into()),
                        location: serde_json::json!({ "type": "tls" }),
                        false_positive_history: None,
                        tags: vec!["tls".into(), "ciphers".into(), "weak-crypto".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }

            if let Some(cert_valid) = tls.get("certificate_valid").and_then(|v| v.as_bool()) {
                if !cert_valid {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: "Invalid or expired TLS certificate".into(),
                        description: "The TLS certificate is invalid or has expired. This can allow man-in-the-middle attacks.".into(),
                        vulnerability_class: VulnerabilityClass::AuthBypass,
                        severity: Severity::High,
                        confidence: 0.95,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.4),
                        cve_id: None,
                        cwe_id: Some("CWE-295".into()),
                        evidence: serde_json::json!({
                            "certificate_valid": false,
                        }),
                        poc: None,
                        remediation: Some("Renew the TLS certificate or fix certificate chain issues. Ensure the certificate is issued by a trusted CA.".into()),
                        location: serde_json::json!({ "type": "tls" }),
                        false_positive_history: None,
                        tags: vec!["tls".into(), "certificate".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }
        } else {
            if let Some(url) = metadata.get("url").and_then(|v| v.as_str()) {
                if url.starts_with("http://") {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: "HTTP (no TLS) endpoint detected".into(),
                        description: format!(
                            "The target URL '{}' uses HTTP without TLS encryption. All traffic is transmitted in cleartext.",
                            url
                        ),
                        vulnerability_class: VulnerabilityClass::Unknown,
                        severity: Severity::High,
                        confidence: 0.95,
                        status: FindingStatus::Open,
                        cvss_score: Some(7.5),
                        cve_id: None,
                        cwe_id: Some("CWE-319".into()),
                        evidence: serde_json::json!({
                            "url": url,
                            "encrypted": false,
                        }),
                        poc: None,
                        remediation: Some("Switch to HTTPS. Obtain a TLS certificate and enforce HTTPS with HSTS.".into()),
                        location: serde_json::json!({ "url": url }),
                        false_positive_history: None,
                        tags: vec!["http".into(), "cleartext".into(), "tls".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }
        }

        findings
    }

    fn analyze_dns(&self, metadata: &serde_json::Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now();

        if let Some(dns) = metadata.get("dns").or_else(|| metadata.get("dns_records")) {
            if let Some(records) = dns.as_array() {
                if records.is_empty() {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: "No DNS records returned".into(),
                        description: "DNS query returned no records. This may indicate a DNS misconfiguration or that the domain does not exist.".into(),
                        vulnerability_class: VulnerabilityClass::Unknown,
                        severity: Severity::Low,
                        confidence: 0.5,
                        status: FindingStatus::Open,
                        cvss_score: Some(2.6),
                        cve_id: None,
                        cwe_id: None,
                        evidence: serde_json::json!({"dns_records": []}),
                        poc: None,
                        remediation: Some("Verify DNS configuration and ensure proper DNS records are set.".into()),
                        location: serde_json::json!({"type": "dns"}),
                        false_positive_history: None,
                        tags: vec!["dns".into(), "misconfiguration".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }

            if let Some(records) = dns.as_array() {
                for record in records {
                    let rtype = record.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let value = record.get("value").and_then(|v| v.as_str()).unwrap_or("");

                    if rtype == "TXT" && value.contains("v=spf1") && value.contains("+all") {
                        findings.push(Finding {
                            id: new_id(),
                            scan_id: String::new(),
                            target_id: String::new(),
                            title: "Misconfigured SPF record: +all".into(),
                            description: "SPF record uses '+all' which allows any host to send email for this domain, bypassing SPF protection.".into(),
                            vulnerability_class: VulnerabilityClass::Unknown,
                            severity: Severity::High,
                            confidence: 0.95,
                            status: FindingStatus::Open,
                            cvss_score: Some(7.5),
                            cve_id: None,
                            cwe_id: Some("CWE-290".into()),
                            evidence: serde_json::json!({
                                "record_type": "TXT",
                                "record_value": value,
                            }),
                            poc: None,
                            remediation: Some("Change the SPF record to use '-all' or '~all' instead of '+all'.".into()),
                            location: serde_json::json!({"type": "dns"}),
                            false_positive_history: None,
                            tags: vec!["dns".into(), "spf".into(), "email-security".into()],
                            metadata: serde_json::json!({}),
                            discovered_at: now,
                            updated_at: now,
                        });
                    }
                }
            }

            if let Some(dnssec) = dns.get("dnssec_enabled").and_then(|v| v.as_bool()) {
                if !dnssec {
                    findings.push(Finding {
                        id: new_id(),
                        scan_id: String::new(),
                        target_id: String::new(),
                        title: "DNSSEC not enabled".into(),
                        description: "DNSSEC is not enabled for this domain. DNS responses are not cryptographically verified, making DNS spoofing/cache poisoning possible.".into(),
                        vulnerability_class: VulnerabilityClass::CachePoisoning,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        status: FindingStatus::Open,
                        cvss_score: Some(5.9),
                        cve_id: None,
                        cwe_id: Some("CWE-350".into()),
                        evidence: serde_json::json!({
                            "dnssec_enabled": false,
                        }),
                        poc: None,
                        remediation: Some("Enable DNSSEC for the domain to cryptographically sign DNS records.".into()),
                        location: serde_json::json!({"type": "dns"}),
                        false_positive_history: None,
                        tags: vec!["dns".into(), "dnssec".into()],
                        metadata: serde_json::json!({}),
                        discovered_at: now,
                        updated_at: now,
                    });
                }
            }
        }

        if let Some(hostname) = metadata.get("hostname").or_else(|| metadata.get("host")) {
            let host = hostname.as_str().unwrap_or("");
            if host.contains("..") {
                findings.push(Finding {
                    id: new_id(),
                    scan_id: String::new(),
                    target_id: String::new(),
                    title: format!("Suspicious hostname with double dots: {}", host),
                    description: "Hostname contains consecutive dots, which may indicate a DNS spoofing attempt or typo-squatting attack.".into(),
                    vulnerability_class: VulnerabilityClass::Unknown,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    status: FindingStatus::Open,
                    cvss_score: Some(4.0),
                    cve_id: None,
                    cwe_id: Some("CWE-350".into()),
                    evidence: serde_json::json!({
                        "hostname": host,
                    }),
                    poc: None,
                    remediation: Some("Verify the hostname is correct and not the result of DNS poisoning.".into()),
                    location: serde_json::json!({"hostname": host}),
                    false_positive_history: None,
                    tags: vec!["dns".into(), "hostname".into(), "suspicious".into()],
                    metadata: serde_json::json!({}),
                    discovered_at: now,
                    updated_at: now,
                });
            }
        }

        findings
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for NetworkScanner {
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
        let host = target.host.as_deref().unwrap_or("unknown");
        let metadata = &target.metadata;

        tracing::info!("Starting network scan of: {}", host);

        let mut all_findings = Vec::new();

        let set_target = |mut findings: Vec<Finding>, tid: &str| -> Vec<Finding> {
            for f in &mut findings {
                f.target_id = tid.to_string();
                if f.scan_id.is_empty() {
                    f.scan_id = "network-scan".into();
                }
            }
            findings
        };

        if self.check_ports {
            tracing::info!("Analyzing network ports");
            let port_findings = self.analyze_ports(host, metadata);
            tracing::info!("Found {} port-related issues", port_findings.len());
            all_findings.extend(set_target(port_findings, &target.id));
        }

        if self.check_tls {
            tracing::info!("Analyzing TLS configuration");
            let tls_findings = self.analyze_tls(target, metadata);
            tracing::info!("Found {} TLS-related issues", tls_findings.len());
            all_findings.extend(set_target(tls_findings, &target.id));
        }

        if self.check_dns {
            tracing::info!("Analyzing DNS security");
            let dns_findings = self.analyze_dns(metadata);
            tracing::info!("Found {} DNS-related issues", dns_findings.len());
            all_findings.extend(set_target(dns_findings, &target.id));
        }

        tracing::info!(
            "Network scan complete: {} total findings",
            all_findings.len()
        );
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target_with_metadata(metadata: serde_json::Value) -> Target {
        Target {
            id: "test-network-target".into(),
            name: "network-test".into(),
            target_type: vest_core::types::TargetType::Network,
            path: None,
            url_str: None,
            pid: None,
            host: Some("test-host.local".into()),
            metadata,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_default_values() {
        let scanner = NetworkScanner::new();
        assert!(scanner.enabled);
        assert_eq!(scanner.name, "network-scanner");
        assert!(scanner.check_ports);
        assert!(scanner.check_tls);
        assert!(scanner.check_dns);
    }

    #[test]
    fn test_dangerous_port_detection() {
        let scanner = NetworkScanner::new();
        let metadata = serde_json::json!({
            "open_ports": [
                {"port": 23, "service": "telnet"},
                {"port": 3306, "service": "mysql"},
                {"port": 445, "service": "smb"}
            ]
        });
        let findings = scanner.analyze_ports("test-host", &metadata);
        assert_eq!(findings.len(), 3);
        let has_telnet = findings.iter().any(|f| f.title.contains("Telnet"));
        let has_mysql = findings.iter().any(|f| f.title.contains("MySQL"));
        let has_smb = findings.iter().any(|f| f.title.contains("SMB"));
        assert!(has_telnet);
        assert!(has_mysql);
        assert!(has_smb);
    }

    #[test]
    fn test_tls_version_deprecated() {
        let scanner = NetworkScanner::new();
        let target = make_target_with_metadata(serde_json::json!({
            "tls": {
                "version": "TLS 1.0",
                "ciphers": ["AES-GCM"],
                "certificate_valid": true
            }
        }));
        let findings = scanner.analyze_tls(&target, &target.metadata);
        assert!(!findings.is_empty());
        let has_tls_warning = findings.iter().any(|f| f.title.contains("Deprecated TLS"));
        assert!(has_tls_warning);
    }

    #[test]
    fn test_weak_cipher_detection() {
        let scanner = NetworkScanner::new();
        let target = make_target_with_metadata(serde_json::json!({
            "tls": {
                "version": "TLS 1.2",
                "ciphers": ["RC4-MD5", "DES-CBC-SHA", "AES-GCM"],
                "certificate_valid": true
            }
        }));
        let findings = scanner.analyze_tls(&target, &target.metadata);
        assert!(!findings.is_empty());
        let has_cipher_warning = findings.iter().any(|f| f.title.contains("cipher"));
        assert!(has_cipher_warning);
    }

    #[test]
    fn test_http_no_tls_detection() {
        let scanner = NetworkScanner::new();
        let target = make_target_with_metadata(serde_json::json!({
            "url": "http://insecure.example.com"
        }));
        let findings = scanner.analyze_tls(&target, &target.metadata);
        assert!(!findings.is_empty());
        let has_http_warning = findings.iter().any(|f| f.title.contains("HTTP"));
        assert!(has_http_warning);
    }

    #[test]
    fn test_invalid_cert_detection() {
        let scanner = NetworkScanner::new();
        let target = make_target_with_metadata(serde_json::json!({
            "tls": {
                "version": "TLS 1.3",
                "ciphers": ["AES-GCM"],
                "certificate_valid": false
            }
        }));
        let findings = scanner.analyze_tls(&target, &target.metadata);
        assert!(!findings.is_empty());
        let has_cert_warning = findings.iter().any(|f| f.title.contains("certificate"));
        assert!(has_cert_warning);
    }

    #[test]
    fn test_spf_plus_all_detection() {
        let scanner = NetworkScanner::new();
        let metadata = serde_json::json!({
            "dns": [
                {"type": "TXT", "value": "v=spf1 +all"}
            ]
        });
        let findings = scanner.analyze_dns(&metadata);
        assert!(!findings.is_empty());
        let has_spf = findings.iter().any(|f| f.title.contains("SPF"));
        assert!(has_spf);
    }

    #[test]
    fn test_dnssec_not_enabled() {
        let scanner = NetworkScanner::new();
        let metadata = serde_json::json!({
            "dns": {
                "dnssec_enabled": false
            }
        });
        let findings = scanner.analyze_dns(&metadata);
        assert!(!findings.is_empty());
        let has_dnssec = findings.iter().any(|f| f.title.contains("DNSSEC"));
        assert!(has_dnssec);
    }

    #[test]
    fn test_ports_from_simple_array() {
        let scanner = NetworkScanner::new();
        let metadata = serde_json::json!({
            "ports": [6379, 27017]
        });
        let findings = scanner.analyze_ports("test-host", &metadata);
        assert_eq!(findings.len(), 2);
        let has_redis = findings.iter().any(|f| f.title.contains("Redis"));
        let has_mongo = findings.iter().any(|f| f.title.contains("MongoDB"));
        assert!(has_redis);
        assert!(has_mongo);
    }

    #[test]
    fn test_no_port_data_fallback() {
        let scanner = NetworkScanner::new();
        let metadata = serde_json::json!({
            "hostname": "api.example.com"
        });
        let findings = scanner.analyze_ports("api.example.com", &metadata);
        assert!(!findings.is_empty());
        let has_info = findings.iter().any(|f| f.severity == Severity::Info);
        assert!(has_info);
    }

    #[test]
    fn test_suspicious_hostname_double_dots() {
        let scanner = NetworkScanner::new();
        let metadata = serde_json::json!({
            "hostname": "evil..example.com"
        });
        let findings = scanner.analyze_dns(&metadata);
        assert!(!findings.is_empty());
        let has_suspicious = findings.iter().any(|f| f.title.contains("double dots"));
        assert!(has_suspicious);
    }

    #[test]
    fn test_with_methods() {
        let scanner = NetworkScanner::new()
            .with_ports(false)
            .with_tls(false)
            .with_dns(false);
        assert!(!scanner.check_ports);
        assert!(!scanner.check_tls);
        assert!(!scanner.check_dns);
    }
}
