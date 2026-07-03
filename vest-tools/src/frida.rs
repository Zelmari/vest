pub struct FridaTool;

impl FridaTool {
    pub fn new() -> Self {
        Self
    }

    pub fn name(&self) -> &str {
        "frida"
    }
}

impl Default for FridaTool {
    fn default() -> Self {
        Self::new()
    }
}
