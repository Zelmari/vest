use crate::ToolsArgs;
use std::process::Command;

#[allow(dead_code)]
const KNOWN_TOOLS: &[&str] = &["nuclei", "sqlmap", "frida", "docker", "ollama"];

pub async fn run(args: ToolsArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        ToolsArgs::Install { tool } => install_tool(&tool),
        ToolsArgs::Update { tool } => update_tool(&tool),
        ToolsArgs::List => list_tools(),
    }
    Ok(())
}

#[allow(dead_code)]
fn is_known_tool(tool: &str) -> bool {
    KNOWN_TOOLS.contains(&tool)
}

fn install_tool(tool: &str) {
    println!("Installing external tool: {}", tool);
    match tool {
        "nuclei" => {
            if !which_succeeds("go") {
                println!("  Go is not installed. Install Go first: https://go.dev/dl/");
                println!("  Then run:");
            } else {
                println!("  Run:");
            }
            println!("  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest");
        }
        "sqlmap" => {
            println!("  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git");
            println!("  cd sqlmap");
            println!("  python sqlmap.py");
        }
        "frida" => {
            println!("  pip install frida-tools");
        }
        "docker" => {
            println!("  Visit: https://docs.docker.com/get-docker/");
        }
        "ollama" => {
            println!("  curl -fsSL https://ollama.com/install.sh | sh");
        }
        _ => println!("  Unknown tool: {}. Try: vest tools list", tool),
    }
}

fn update_tool(tool: &str) {
    println!("Updating external tool: {}", tool);
    match tool {
        "nuclei" => {
            if vest_tools::NucleiTool::check_installed() {
                println!("  Run: nuclei -update-templates");
            } else {
                println!("  Nuclei is not installed. Run 'vest tools install nuclei' first.");
            }
        }
        "sqlmap" => {
            println!("  cd sqlmap && git pull");
        }
        "frida" => {
            println!("  pip install --upgrade frida-tools");
        }
        "docker" => {
            println!("  Docker updates are platform-specific. Check your Docker Desktop or package manager.");
        }
        "ollama" => {
            println!("  curl -fsSL https://ollama.com/install.sh | sh");
        }
        _ => println!("  Unknown tool: {}. Try: vest tools list", tool),
    }
}

type CheckerFn = fn(&str) -> (bool, Option<String>);

fn list_tools() {
    println!("Installed tools:");

    let tools: &[(&str, &str, CheckerFn)] = &[
        ("nuclei", "Template-based scanner", check_nuclei),
        ("sqlmap", "SQL injection testing", check_which),
        ("frida", "Dynamic instrumentation", check_which),
        ("docker", "Container platform", check_which),
        ("ollama", "Local LLM runner", check_which),
    ];

    for (name, desc, checker) in tools {
        let (installed, version) = checker(name);
        let mark = if installed { "x" } else { " " };
        match version {
            Some(v) => println!("  [{}] {:<10} - {} ({})", mark, name, desc, v),
            None => println!("  [{}] {:<10} - {}", mark, name, desc),
        }
    }

    println!("  Run 'vest tools install <name>' to set up a tool");
}

fn check_nuclei(_name: &str) -> (bool, Option<String>) {
    if !vest_tools::NucleiTool::check_installed() {
        return (false, None);
    }
    if let Some(tool) = vest_tools::NucleiTool::new() {
        if let Ok(v) = tool.version() {
            return (true, Some(v));
        }
    }
    (true, None)
}

fn check_which(name: &str) -> (bool, Option<String>) {
    if which_succeeds(name) {
        (true, None)
    } else {
        (false, None)
    }
}

fn which_succeeds(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_known_tool() {
        assert!(is_known_tool("nuclei"));
        assert!(is_known_tool("sqlmap"));
        assert!(is_known_tool("frida"));
        assert!(is_known_tool("docker"));
        assert!(is_known_tool("ollama"));
    }

    #[test]
    fn test_is_known_tool_unknown() {
        assert!(!is_known_tool("unknown_tool_xyz"));
        assert!(!is_known_tool(""));
        assert!(!is_known_tool("nuclie")); // typo
    }

    #[test]
    fn test_which_succeeds_not_found() {
        assert!(!which_succeeds("nonexistent_tool_xyz_abc_123"));
    }

    #[test]
    fn test_which_succeeds_found() {
        assert!(which_succeeds("sh"));
    }

    #[test]
    fn test_check_nuclei_not_installed() {
        let (installed, version) = check_nuclei("nuclei");
        if installed {
            assert!(
                version.is_some(),
                "if nuclei is installed, version must be returned"
            );
        } else {
            assert!(version.is_none());
        }
    }

    #[test]
    fn test_check_which_not_found() {
        let (installed, version) = check_which("nonexistent_tool_xyz_abc_123");
        assert!(!installed);
        assert!(version.is_none());
    }

    #[test]
    fn test_known_tools_slice_contains_all() {
        assert_eq!(KNOWN_TOOLS.len(), 5);
        assert!(KNOWN_TOOLS.contains(&"nuclei"));
        assert!(KNOWN_TOOLS.contains(&"sqlmap"));
        assert!(KNOWN_TOOLS.contains(&"frida"));
        assert!(KNOWN_TOOLS.contains(&"docker"));
        assert!(KNOWN_TOOLS.contains(&"ollama"));
    }
}
