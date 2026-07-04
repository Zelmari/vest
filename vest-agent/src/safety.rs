use std::collections::HashMap;
use tokio::sync::RwLock;
use vest_core::error::VestError;

pub struct SafetyChecker {
    config: SafetyConfig,
    approvals_granted: RwLock<HashMap<String, bool>>,
    rate_limiter: RwLock<RateLimiterState>,
}

#[derive(Debug, Clone)]
pub struct SafetyConfig {
    pub write_approval: bool,
    pub exploit_approval: bool,
    pub network_write_approval: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_requests_per_second: u32,
    pub rate_limit_burst: u32,
    pub sandbox_enabled: bool,
    pub sandbox_image: String,
    pub max_scan_duration_seconds: u64,
    pub max_concurrent_exploits: u32,
    pub allowed_targets: Vec<String>,
    pub blocked_targets: Vec<String>,
    pub allowed_networks: Vec<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            write_approval: true,
            exploit_approval: true,
            network_write_approval: true,
            rate_limit_enabled: true,
            rate_limit_requests_per_second: 10,
            rate_limit_burst: 30,
            sandbox_enabled: true,
            sandbox_image: "vest-sandbox:latest".into(),
            max_scan_duration_seconds: 3600,
            max_concurrent_exploits: 1,
            allowed_targets: Vec::new(),
            blocked_targets: Vec::new(),
            allowed_networks: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last_refill: std::time::Instant,
}

impl SafetyChecker {
    pub fn new(config: SafetyConfig) -> Self {
        Self {
            config,
            approvals_granted: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(RateLimiterState {
                tokens: 30.0,
                last_refill: std::time::Instant::now(),
            }),
        }
    }

    pub fn permissive() -> Self {
        Self {
            config: SafetyConfig {
                write_approval: false,
                exploit_approval: false,
                network_write_approval: false,
                rate_limit_enabled: false,
                ..Default::default()
            },
            approvals_granted: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(RateLimiterState {
                tokens: f64::MAX,
                last_refill: std::time::Instant::now(),
            }),
        }
    }

    pub fn new_allowing(allowed: bool) -> Self {
        if allowed {
            Self::permissive()
        } else {
            Self {
                config: SafetyConfig::default(),
                approvals_granted: RwLock::new(HashMap::new()),
                rate_limiter: RwLock::new(RateLimiterState {
                    tokens: 0.0,
                    last_refill: std::time::Instant::now(),
                }),
            }
        }
    }

    pub fn approve_tool_call(
        &self,
        tool_name: &str,
        _args: &serde_json::Value,
    ) -> Result<bool, VestError> {
        let category = self.categorize_tool(tool_name);

        match category {
            ActionCategory::MemoryWrite | ActionCategory::FileWrite => {
                if self.config.write_approval {
                    return Ok(self.check_approval_cache("write").unwrap_or(false));
                }
                Ok(true)
            }
            ActionCategory::Exploit => {
                if self.config.exploit_approval {
                    return Ok(self.check_approval_cache("exploit").unwrap_or(false));
                }
                Ok(true)
            }
            ActionCategory::NetworkWrite => {
                if self.config.network_write_approval {
                    return Ok(self.check_approval_cache("network_write").unwrap_or(false));
                }
                Ok(true)
            }
            ActionCategory::ReadOnly => Ok(true),
            ActionCategory::Command => {
                if self.config.write_approval {
                    return Ok(self.check_approval_cache("command").unwrap_or(false));
                }
                Ok(true)
            }
        }
    }

    pub async fn check_rate_limit(&self) -> Result<(), VestError> {
        if !self.config.rate_limit_enabled {
            return Ok(());
        }

        let mut limiter = self.rate_limiter.write().await;
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(limiter.last_refill).as_secs_f64();

        limiter.tokens = (limiter.tokens
            + elapsed * self.config.rate_limit_requests_per_second as f64)
            .min(self.config.rate_limit_burst as f64);
        limiter.last_refill = now;

        if limiter.tokens >= 1.0 {
            limiter.tokens -= 1.0;
            Ok(())
        } else {
            Err(VestError::RateLimited(format!(
                "Rate limit reached ({} req/s, burst {}). Try again later.",
                self.config.rate_limit_requests_per_second, self.config.rate_limit_burst
            )))
        }
    }

    pub fn is_target_allowed(&self, target_name: &str) -> bool {
        if !self.config.blocked_targets.is_empty() {
            for blocked in &self.config.blocked_targets {
                if target_name.contains(blocked) {
                    return false;
                }
            }
        }
        if !self.config.allowed_targets.is_empty() {
            for allowed in &self.config.allowed_targets {
                if target_name.contains(allowed) {
                    return true;
                }
            }
            return false;
        }
        true
    }

    pub async fn grant_approval(&self, category: &str) {
        let mut approvals = self.approvals_granted.write().await;
        approvals.insert(category.to_string(), true);
    }

    pub async fn request_approval(
        &self,
        action: &str,
        _target: &str,
        _details: &str,
        _risk: &str,
    ) -> Result<bool, VestError> {
        Ok(self.check_approval_cache(action).unwrap_or(false))
    }

    fn categorize_tool(&self, tool_name: &str) -> ActionCategory {
        let name = tool_name.to_lowercase();
        if name.contains("read")
            || name.contains("list")
            || name.contains("get")
            || name.contains("show")
        {
            ActionCategory::ReadOnly
        } else if name.contains("write_memory")
            || name.contains("write_process")
            || name.contains("inject")
        {
            ActionCategory::MemoryWrite
        } else if name.contains("write_file")
            || name.contains("modify_file")
            || name.contains("create_file")
        {
            ActionCategory::FileWrite
        } else if name.contains("exploit") || name.contains("poc") || name.contains("payload") {
            ActionCategory::Exploit
        } else if name.contains("network") || name.contains("send") || name.contains("request") {
            ActionCategory::NetworkWrite
        } else if name.contains("execute")
            || name.contains("command")
            || name.contains("shell")
            || name.contains("run")
        {
            ActionCategory::Command
        } else {
            ActionCategory::ReadOnly
        }
    }

    fn check_approval_cache(&self, category: &str) -> Option<bool> {
        self.approvals_granted
            .try_read()
            .ok()
            .and_then(|approvals| approvals.get(category).copied())
    }

    pub fn config(&self) -> &SafetyConfig {
        &self.config
    }

    pub fn with_overrides(&self, overrides: SafetyConfig) -> Self {
        Self {
            config: SafetyConfig {
                write_approval: overrides.write_approval,
                exploit_approval: overrides.exploit_approval,
                network_write_approval: overrides.network_write_approval,
                rate_limit_enabled: overrides.rate_limit_enabled,
                rate_limit_requests_per_second: overrides.rate_limit_requests_per_second,
                rate_limit_burst: overrides.rate_limit_burst,
                sandbox_enabled: overrides.sandbox_enabled,
                sandbox_image: overrides.sandbox_image,
                max_scan_duration_seconds: overrides.max_scan_duration_seconds,
                max_concurrent_exploits: overrides.max_concurrent_exploits,
                allowed_targets: overrides.allowed_targets,
                blocked_targets: overrides.blocked_targets,
                allowed_networks: overrides.allowed_networks,
            },
            approvals_granted: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(RateLimiterState {
                tokens: 30.0,
                last_refill: std::time::Instant::now(),
            }),
        }
    }
}

impl Default for SafetyChecker {
    fn default() -> Self {
        Self::new(SafetyConfig::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCategory {
    ReadOnly,
    MemoryWrite,
    FileWrite,
    Exploit,
    NetworkWrite,
    Command,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_safety_is_restrictive() {
        let checker = SafetyChecker::new(SafetyConfig::default());
        assert!(checker.config.write_approval);
        assert!(checker.config.exploit_approval);
        assert!(checker.config.network_write_approval);
    }

    #[test]
    fn test_permissive_allows_all() {
        let checker = SafetyChecker::permissive();
        assert!(!checker.config.write_approval);
        assert!(!checker.config.exploit_approval);
    }

    #[test]
    fn test_categorize_read_only_tool() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.categorize_tool("read_memory"),
            ActionCategory::ReadOnly
        );
        assert_eq!(
            checker.categorize_tool("list_files"),
            ActionCategory::ReadOnly
        );
        assert_eq!(
            checker.categorize_tool("get_target"),
            ActionCategory::ReadOnly
        );
    }

    #[test]
    fn test_categorize_write_tool() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.categorize_tool("write_memory"),
            ActionCategory::MemoryWrite
        );
        assert_eq!(
            checker.categorize_tool("inject_dll"),
            ActionCategory::MemoryWrite
        );
    }

    #[test]
    fn test_categorize_exploit_tool() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.categorize_tool("exploit_buffer_overflow"),
            ActionCategory::Exploit
        );
        assert_eq!(
            checker.categorize_tool("generate_poc"),
            ActionCategory::Exploit
        );
        assert_eq!(
            checker.categorize_tool("send_payload"),
            ActionCategory::Exploit
        );
    }

    #[test]
    fn test_categorize_command_tool() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.categorize_tool("execute_command"),
            ActionCategory::Command
        );
        assert_eq!(
            checker.categorize_tool("run_shell"),
            ActionCategory::Command
        );
        assert_eq!(
            checker.categorize_tool("shell_exec"),
            ActionCategory::Command
        );
    }

    #[tokio::test]
    async fn test_rate_limit_allows_initial_burst() {
        let checker = SafetyChecker::new(SafetyConfig {
            rate_limit_enabled: true,
            rate_limit_requests_per_second: 10,
            rate_limit_burst: 5,
            ..Default::default()
        });
        for _ in 0..5 {
            assert!(
                checker.check_rate_limit().await.is_ok(),
                "Burst request should be allowed"
            );
        }
        let result = checker.check_rate_limit().await;
        assert!(matches!(result, Err(VestError::RateLimited(_))));
    }

    #[tokio::test]
    async fn test_rate_limit_disabled_allows_all() {
        let checker = SafetyChecker::permissive();
        for _ in 0..1000 {
            assert!(checker.check_rate_limit().await.is_ok());
        }
    }

    #[test]
    fn test_is_target_allowed_empty_lists() {
        let checker = SafetyChecker::default();
        assert!(checker.is_target_allowed("example.com"));
        assert!(checker.is_target_allowed("anything.exe"));
    }

    #[test]
    fn test_is_target_allowed_blocked() {
        let checker = SafetyChecker::new(SafetyConfig {
            blocked_targets: vec!["internal.company.com".into()],
            ..Default::default()
        });
        assert!(!checker.is_target_allowed("internal.company.com"));
        assert!(checker.is_target_allowed("public.company.com"));
    }

    #[test]
    fn test_is_target_allowed_whitelist() {
        let checker = SafetyChecker::new(SafetyConfig {
            allowed_targets: vec!["test.com".into()],
            ..Default::default()
        });
        assert!(checker.is_target_allowed("test.com"));
        assert!(!checker.is_target_allowed("other.com"));
    }

    #[test]
    fn test_approve_read_only_tool_always_ok() {
        let checker = SafetyChecker::default();
        assert!(checker
            .approve_tool_call("read_memory", &serde_json::json!({}))
            .unwrap());
        assert!(checker
            .approve_tool_call("list_files", &serde_json::json!({}))
            .unwrap());
    }

    #[test]
    fn test_approve_write_tool_needs_approval() {
        let checker = SafetyChecker::new(SafetyConfig {
            write_approval: true,
            ..Default::default()
        });
        let result = checker
            .approve_tool_call("write_memory", &serde_json::json!({"address": "0x1000"}))
            .unwrap();
        assert!(!result, "Write should not be approved without user consent");
    }

    #[test]
    fn test_approve_write_tool_permissive() {
        let checker = SafetyChecker::permissive();
        let result = checker
            .approve_tool_call("write_memory", &serde_json::json!({}))
            .unwrap();
        assert!(result, "Permissive mode should allow writes");
    }

    #[test]
    fn test_categorize_unknown_tool_safe_default() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.categorize_tool("completely_unknown_tool"),
            ActionCategory::ReadOnly
        );
    }

    #[test]
    fn test_categorize_network_write_tool() {
        let checker = SafetyChecker::default();
        assert_eq!(
            checker.categorize_tool("send_http_request"),
            ActionCategory::NetworkWrite
        );
        assert_eq!(
            checker.categorize_tool("network_connect"),
            ActionCategory::NetworkWrite
        );
    }
}
