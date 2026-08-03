use reqwest::Client;
use std::time::Duration;

/// Default HTTP timeout when `ProviderConfig.timeout_seconds` is unset.
pub const DEFAULT_PROVIDER_TIMEOUT_SECS: u64 = 120;

/// Build a reqwest client with a hard request timeout (PROV-3).
pub fn build_provider_client(timeout_seconds: Option<u64>) -> Client {
    let secs = timeout_seconds
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_PROVIDER_TIMEOUT_SECS);
    Client::builder()
        .timeout(Duration::from_secs(secs))
        .build()
        .expect("failed to build provider HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_provider_client_accepts_explicit_timeout() {
        let _ = build_provider_client(Some(1));
    }

    #[test]
    fn build_provider_client_defaults_when_none_or_zero() {
        let _ = build_provider_client(None);
        let _ = build_provider_client(Some(0));
    }
}
