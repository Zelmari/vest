pub struct NucleiTool;

impl NucleiTool {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &str {
        "nuclei"
    }
}

impl Default for NucleiTool {
    fn default() -> Self {
        Self::new()
    }
}
