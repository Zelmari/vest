//! Network origin scope matching using parsed URLs (not substring checks).

use url::Url;

/// Authorised network origins (scheme + host + effective port).
#[derive(Debug, Clone, Default)]
pub struct ApprovedNetworkScope {
    origins: Vec<NetworkOrigin>,
    /// Test-only: accept any parseable URL.
    unrestricted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkOrigin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl NetworkOrigin {
    pub fn from_url(url: &Url) -> Option<Self> {
        let host = url.host_str()?.to_ascii_lowercase();
        let scheme = url.scheme().to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        Some(Self { scheme, host, port })
    }

    pub fn matches(&self, other: &NetworkOrigin) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetScopeError {
    InvalidUrl(String),
    OutsideScope,
    NoOrigins,
}

impl std::fmt::Display for NetScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetScopeError::InvalidUrl(u) => write!(f, "invalid URL: {u}"),
            NetScopeError::OutsideScope => {
                write!(f, "URL origin is outside authorised network scope")
            }
            NetScopeError::NoOrigins => write!(f, "no authorised network origins configured"),
        }
    }
}

impl std::error::Error for NetScopeError {}

impl ApprovedNetworkScope {
    pub fn new(origins: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self, NetScopeError> {
        let mut parsed = Vec::new();
        for raw in origins {
            let raw = raw.as_ref();
            let url = parse_flexible_origin(raw)?;
            let origin = NetworkOrigin::from_url(&url)
                .ok_or_else(|| NetScopeError::InvalidUrl(raw.to_string()))?;
            parsed.push(origin);
        }
        Ok(Self {
            origins: parsed,
            unrestricted: false,
        })
    }

    pub fn empty() -> Self {
        Self {
            origins: Vec::new(),
            unrestricted: false,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn unrestricted() -> Self {
        Self {
            origins: Vec::new(),
            unrestricted: true,
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    pub fn origins(&self) -> &[NetworkOrigin] {
        &self.origins
    }

    pub fn contains_url(&self, raw: &str) -> Result<bool, NetScopeError> {
        if self.unrestricted {
            // Still require parseable URL.
            let _ = Url::parse(raw).map_err(|_| NetScopeError::InvalidUrl(raw.to_string()))?;
            return Ok(true);
        }
        if self.origins.is_empty() {
            return Err(NetScopeError::NoOrigins);
        }
        let url = Url::parse(raw).map_err(|_| NetScopeError::InvalidUrl(raw.to_string()))?;
        let origin = NetworkOrigin::from_url(&url)
            .ok_or_else(|| NetScopeError::InvalidUrl(raw.to_string()))?;
        Ok(self.origins.iter().any(|o| o.matches(&origin)))
    }

    pub fn authorise_url(&self, raw: &str) -> Result<Url, NetScopeError> {
        if self.contains_url(raw)? {
            Url::parse(raw).map_err(|_| NetScopeError::InvalidUrl(raw.to_string()))
        } else {
            Err(NetScopeError::OutsideScope)
        }
    }

    /// Structural host/target match for allow/block lists (exact host or full origin).
    pub fn host_equals(candidate: &str, pattern: &str) -> bool {
        let c = candidate.trim().to_ascii_lowercase();
        let p = pattern.trim().to_ascii_lowercase();
        if c == p {
            return true;
        }
        // Compare as origins when both parse.
        let c_url = parse_flexible_origin(&c).ok();
        let p_url = parse_flexible_origin(&p).ok();
        match (c_url, p_url) {
            (Some(cu), Some(pu)) => {
                match (NetworkOrigin::from_url(&cu), NetworkOrigin::from_url(&pu)) {
                    (Some(a), Some(b)) => a.matches(&b),
                    _ => false,
                }
            }
            _ => {
                // Bare hostname equality only (no substring / prefix).
                let c_host = c
                    .strip_prefix("https://")
                    .or_else(|| c.strip_prefix("http://"))
                    .unwrap_or(&c);
                let p_host = p
                    .strip_prefix("https://")
                    .or_else(|| p.strip_prefix("http://"))
                    .unwrap_or(&p);
                let c_host = c_host.split('/').next().unwrap_or(c_host);
                let p_host = p_host.split('/').next().unwrap_or(p_host);
                // Strip ports for bare compare when both lack scheme inconsistencies.
                let c_host = c_host.split(':').next().unwrap_or(c_host);
                let p_host = p_host.split(':').next().unwrap_or(p_host);
                c_host == p_host
            }
        }
    }
}

fn parse_flexible_origin(raw: &str) -> Result<Url, NetScopeError> {
    let trimmed = raw.trim();
    if trimmed.contains("://") {
        Url::parse(trimmed).map_err(|_| NetScopeError::InvalidUrl(trimmed.to_string()))
    } else {
        // Bare host → https default for origin comparison.
        Url::parse(&format!("https://{trimmed}"))
            .map_err(|_| NetScopeError::InvalidUrl(trimmed.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_allowed() {
        let scope = ApprovedNetworkScope::new(["https://example.com"]).unwrap();
        assert!(scope.contains_url("https://example.com/path").unwrap());
    }

    #[test]
    fn different_host_denied() {
        let scope = ApprovedNetworkScope::new(["https://example.com"]).unwrap();
        assert!(!scope.contains_url("https://evil.com/").unwrap());
    }

    #[test]
    fn prefix_host_collision_denied() {
        let scope = ApprovedNetworkScope::new(["https://example.com"]).unwrap();
        assert!(!scope.contains_url("https://example.com.evil/").unwrap());
    }

    #[test]
    fn host_equals_no_substring() {
        assert!(ApprovedNetworkScope::host_equals("test.com", "test.com"));
        assert!(!ApprovedNetworkScope::host_equals(
            "nottest.com",
            "test.com"
        ));
        assert!(!ApprovedNetworkScope::host_equals(
            "test.com.evil",
            "test.com"
        ));
    }

    #[test]
    fn port_distinguishes_origin() {
        let scope = ApprovedNetworkScope::new(["https://example.com:8443"]).unwrap();
        assert!(scope.contains_url("https://example.com:8443/x").unwrap());
        assert!(!scope.contains_url("https://example.com/x").unwrap());
    }
}
