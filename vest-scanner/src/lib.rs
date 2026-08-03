pub mod binary;
#[cfg(feature = "browser")]
pub mod browser;
pub mod files;
pub mod http_client;
pub mod memory;
pub mod net_safety;
pub mod network;
pub mod nuclei;
pub mod registry;
pub mod scanner;
pub mod web;

pub use http_client::{BodyLimitPolicy, HttpClientBudgets, ScopedHttpClient};
pub use net_safety::{
    ensure_connect_addrs_allowed, ip_is_denied_private_or_metadata, is_private_or_metadata_host,
    is_private_or_metadata_target,
};
pub use registry::ScannerRegistry;
pub use scanner::ScanResult;
