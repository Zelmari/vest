use crate::SandboxArgs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DOCKER_NOT_INSTALLED_MSG: &str =
    "Docker is not installed. Install from https://docs.docker.com/get-docker/";
const IMAGE_NAME: &str = "vest-sandbox";
const NO_DOCKERFILE_MSG: &str = "No Dockerfile found in the current directory or ~/.vest/.\n\
     Create a Dockerfile in the current directory or place one in ~/.vest/Dockerfile.";

fn binary_installed(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_dockerfile() -> Result<PathBuf, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;
    let local = cwd.join("Dockerfile");
    if local.exists() {
        return Ok(local);
    }

    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable is not set".to_string())?;
    let vest_dockerfile = PathBuf::from(home).join(".vest").join("Dockerfile");
    if vest_dockerfile.exists() {
        return Ok(vest_dockerfile);
    }

    Err(NO_DOCKERFILE_MSG.to_string())
}

pub async fn run(args: SandboxArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !binary_installed("docker") {
        eprintln!("{}", DOCKER_NOT_INSTALLED_MSG);
        return Err("Docker is not installed".into());
    }

    match args {
        SandboxArgs::Build => {
            let dockerfile = find_dockerfile()?;
            let dir = dockerfile.parent().unwrap_or(Path::new("."));
            let status = build_command(dir).status()?;
            if !status.success() {
                return Err("docker build failed".into());
            }
        }
        SandboxArgs::Start { extra_args } => {
            let status = start_command(&extra_args).status()?;
            if !status.success() {
                return Err("docker run failed".into());
            }
        }
        SandboxArgs::Clean => {
            remove_containers()?;
            remove_image()?;
        }
    }

    Ok(())
}

fn build_command(dir: &Path) -> Command {
    let mut cmd = Command::new("docker");
    cmd.args(["build", "-t", IMAGE_NAME, "."]);
    cmd.current_dir(dir);
    cmd
}

fn start_command(extra_args: &[String]) -> Command {
    let mut cmd = Command::new("docker");
    cmd.arg("run").arg("--rm").arg("-it");
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.arg(IMAGE_NAME);
    cmd
}

fn remove_containers() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("docker")
        .args(["ps", "-aq", "--filter", &format!("ancestor={}", IMAGE_NAME)])
        .output()?;

    if !output.status.success() {
        return Err("docker ps failed".into());
    }

    let ids = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ids.is_empty() {
        return Ok(());
    }

    let mut cmd = Command::new("docker");
    cmd.arg("rm").arg("-f");
    for id in ids.split_whitespace() {
        cmd.arg(id);
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err("docker rm failed".into());
    }

    Ok(())
}

fn remove_image() -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("docker").args(["rmi", IMAGE_NAME]).status()?;
    if !status.success() {
        eprintln!(
            "Note: Could not remove image '{}' (it may not exist or is in use).",
            IMAGE_NAME
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn test_binary_not_installed() {
        assert!(!binary_installed("nonexistent_binary_xyz_12345"));
    }

    #[test]
    fn test_build_command_construction() {
        let dir = Path::new("/tmp/testdir");
        let cmd = build_command(dir);

        assert_eq!(cmd.get_program(), OsStr::new("docker"));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "build");
        assert_eq!(args[1], "-t");
        assert_eq!(args[2], IMAGE_NAME);
        assert_eq!(args[3], ".");
        assert_eq!(cmd.get_current_dir(), Some(dir));
    }

    #[test]
    fn test_start_command_construction_no_extra_args() {
        let cmd = start_command(&[]);

        assert_eq!(cmd.get_program(), OsStr::new("docker"));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "--rm");
        assert_eq!(args[2], "-it");
        assert_eq!(args[3], IMAGE_NAME);
        assert_eq!(args.len(), 4);
    }

    #[test]
    fn test_start_command_construction_with_extra_args() {
        let extra = vec![
            "-p".to_string(),
            "8080:80".to_string(),
            "-v".to_string(),
            "/host:/container".to_string(),
        ];
        let cmd = start_command(&extra);

        assert_eq!(cmd.get_program(), OsStr::new("docker"));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "--rm");
        assert_eq!(args[2], "-it");
        assert_eq!(args[3], "-p");
        assert_eq!(args[4], "8080:80");
        assert_eq!(args[5], "-v");
        assert_eq!(args[6], "/host:/container");
        assert_eq!(args[7], IMAGE_NAME);
        assert_eq!(args.len(), 8);
    }

    #[test]
    fn test_build_command_contains_image_name() {
        let cmd = build_command(Path::new("."));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(args[2], IMAGE_NAME);
    }

    #[test]
    fn test_start_always_includes_image_name() {
        let cmd = start_command(&["--rm".into()]);
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(args.last(), Some(&OsStr::new(IMAGE_NAME)));
    }

    #[test]
    fn test_find_dockerfile_not_found() {
        let result = find_dockerfile();
        if let Err(msg) = result {
            assert!(msg.contains("No Dockerfile found"));
        }
    }
}
