use std::collections::HashMap;
use std::sync::Arc;
use vest_core::Scanner;

pub struct ScannerRegistry {
    scanners: HashMap<String, Arc<dyn Scanner>>,
}

impl ScannerRegistry {
    pub fn new() -> Self {
        Self {
            scanners: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: impl Into<String>, scanner: Arc<dyn Scanner>) {
        self.scanners.insert(name.into(), scanner);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Scanner>> {
        self.scanners.get(name).cloned()
    }

    pub fn list_enabled(&self) -> Vec<String> {
        self.scanners.keys().cloned().collect()
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
