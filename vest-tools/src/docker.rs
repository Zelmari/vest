pub struct DockerTool;

impl DockerTool {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &str {
        "docker"
    }
}

impl Default for DockerTool {
    fn default() -> Self {
        Self::new()
    }
}
