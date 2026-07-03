use vest_core::types::{Finding, Target};

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub target: Target,
    pub duration_ms: u64,
}

impl ScanResult {
    pub fn new(target: Target) -> Self {
        Self {
            findings: Vec::new(),
            target,
            duration_ms: 0,
        }
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }
}
