pub struct SqlmapTool;

impl SqlmapTool {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &str {
        "sqlmap"
    }
}

impl Default for SqlmapTool {
    fn default() -> Self {
        Self::new()
    }
}
