use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub mode: Option<String>,
    pub phases: Option<Vec<String>>,
    pub agents: Option<Vec<String>>,
    pub scanners: Option<Vec<String>>,
    pub max_iterations: Option<u32>,
    pub max_tokens_per_iteration: Option<u32>,
    pub max_depth: Option<u32>,
    pub max_children: Option<u32>,
    pub parallelism: Option<u32>,
    pub diversity_seeds: Option<u32>,
    pub merge_strategy: Option<String>,
}
