//! Private / metadata target classification and connect-time DNS checks (B1).

use std::net::{IpAddr, SocketAddr};
use url::Url;
use vest_core::error::VestError;

/// True for loopback, RFC1918, link-local, unspecified, and known cloud-metadata hostnames.
///
/// Literal-host / known-name check (no DNS). Connect-time resolution is layered on top via
/// [`ensure_connect_addrs_allowed`] when `deny_private_targets` is enabled.
pub fn is_private_or_metadata_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let host = host.split('%').next().unwrap_or(host.as_str());

    match host {
        "metadata"
        | "metadata.google.internal"
        | "metadata.goog"
        | "metadata.aws.internal"
        | "kubernetes.default"
        | "kubernetes.default.svc"
        | "kubernetes.default.svc.cluster.local" => return true,
        _ => {}
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_is_denied_private_or_metadata(ip);
    }
    false
}

/// Extract a host from a URL or bare host/IP and apply [`is_private_or_metadata_host`].
pub fn is_private_or_metadata_target(host_or_url: &str) -> bool {
    let raw = host_or_url.trim();
    if raw.contains("://") {
        if let Ok(url) = Url::parse(raw) {
            if let Some(host) = url.host_str() {
                return is_private_or_metadata_host(host);
            }
        }
        return false;
    }
    let host = if raw.starts_with('[') {
        raw.split(']').next().unwrap_or(raw).trim_start_matches('[')
    } else {
        raw.split('/')
            .next()
            .unwrap_or(raw)
            .split(':')
            .next()
            .unwrap_or(raw)
    };
    is_private_or_metadata_host(host)
}

pub fn ip_is_denied_private_or_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // Carrier-grade NAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unique_local() || v6.is_unspecified() {
                return true;
            }
            // fe80::/10 link-local
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_denied_private_or_metadata(IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Resolve `host:port` and fail closed if any address is private/metadata.
///
/// Returns addresses suitable for `reqwest` `resolve_to_addrs` pinning when all are allowed.
/// IP literals and known metadata hostnames are denied without trusting DNS answers alone.
pub async fn ensure_connect_addrs_allowed(
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, VestError> {
    if is_private_or_metadata_host(host) {
        return Err(VestError::Scan(format!(
            "target host '{host}' is loopback/private/link-local/metadata (denied by safety.deny_private_targets)"
        )));
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            VestError::Scan(format!(
                "DNS resolution failed for '{host}' (fail-closed under deny_private_targets): {e}"
            ))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(VestError::Scan(format!(
            "DNS resolution returned no addresses for '{host}' (fail-closed under deny_private_targets)"
        )));
    }

    for addr in &addrs {
        if ip_is_denied_private_or_metadata(addr.ip()) {
            return Err(VestError::Scan(format!(
                "resolved address {} for host '{host}' is loopback/private/link-local/metadata (denied by safety.deny_private_targets)",
                addr.ip()
            )));
        }
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_metadata_and_loopback_denied() {
        assert!(is_private_or_metadata_host("169.254.169.254"));
        assert!(is_private_or_metadata_host("127.0.0.1"));
        assert!(is_private_or_metadata_host("10.0.0.5"));
        assert!(is_private_or_metadata_host("192.168.1.1"));
        assert!(is_private_or_metadata_host("metadata.google.internal"));
        assert!(!is_private_or_metadata_host("example.com"));
        assert!(is_private_or_metadata_target(
            "http://169.254.169.254/latest/meta-data/"
        ));
    }

    #[tokio::test]
    async fn resolve_check_denies_literal_private_hosts() {
        // Documents B1: ensure_connect_addrs_allowed applies the same IP-literal policy
        // before connect (no mock DNS required for literals).
        let err = ensure_connect_addrs_allowed("169.254.169.254", 80)
            .await
            .expect_err("metadata IP must deny");
        assert!(
            err.to_string().contains("169.254.169.254")
                && err.to_string().contains("deny_private_targets"),
            "got: {err}"
        );

        let err = ensure_connect_addrs_allowed("127.0.0.1", 80)
            .await
            .expect_err("loopback must deny");
        assert!(err.to_string().contains("127.0.0.1"), "got: {err}");
    }
}
