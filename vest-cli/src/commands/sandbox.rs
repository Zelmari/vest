use crate::SandboxArgs;
use std::path::{Path, PathBuf};
use std::process::Command;
use vest_core::VestError;

const DOCKER_NOT_INSTALLED_MSG: &str =
    "Docker is not installed. Install from https://docs.docker.com/get-docker/";
const IMAGE_NAME: &str = "vest-sandbox";
const EXPERIMENTAL_WARNING: &str =
    "Note: `vest sandbox` is an experimental Docker helper, not a verified OS sandbox for agent tools.";
const NO_DOCKERFILE_MSG: &str = "No Dockerfile found in the current directory or ~/.vest/.\n\
     Create a Dockerfile in the current directory or place one in ~/.vest/Dockerfile.\n\
     Note: `vest sandbox` is an experimental Docker helper, not a verified OS sandbox for agent tools.";

fn binary_installed(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_dockerfile() -> Result<PathBuf, VestError> {
    let cwd = std::env::current_dir().map_err(VestError::Io)?;
    let local = cwd.join("Dockerfile");
    if local.exists() {
        return Ok(local);
    }

    let home = std::env::var("HOME")
        .map_err(|_| VestError::Sandbox("HOME environment variable is not set".into()))?;
    let vest_dockerfile = PathBuf::from(home).join(".vest").join("Dockerfile");
    if vest_dockerfile.exists() {
        return Ok(vest_dockerfile);
    }

    Err(VestError::Sandbox(NO_DOCKERFILE_MSG.to_string()))
}

/// Reject docker run passthrough flags that weaken isolation (CLI-SANDBOX).
fn validate_extra_args(extra_args: &[String]) -> Result<(), VestError> {
    let mut i = 0;
    while i < extra_args.len() {
        let arg = &extra_args[i];

        if is_privileged_flag(arg) {
            return Err(VestError::ApprovalDenied(format!(
                "Refusing dangerous docker sandbox flag `{arg}` (grants full host capabilities). {EXPERIMENTAL_WARNING}"
            )));
        }

        if let Some(value) = option_value(arg, &["-v", "--volume"]) {
            deny_dangerous_volume(arg, value)?;
            i += 1;
            continue;
        }
        if arg == "-v" || arg == "--volume" {
            let value = expect_value(extra_args, i, arg)?;
            deny_dangerous_volume(arg, value)?;
            i += 2;
            continue;
        }

        if let Some(value) = option_value(arg, &["--mount"]) {
            deny_dangerous_mount(arg, value)?;
            i += 1;
            continue;
        }
        if arg == "--mount" {
            let value = expect_value(extra_args, i, arg)?;
            deny_dangerous_mount(arg, value)?;
            i += 2;
            continue;
        }

        const HOST_NS: &[&str] = &[
            "--pid",
            "--network",
            "--net",
            "--ipc",
            "--uts",
            "--userns",
            "--cgroupns",
        ];
        if let Some(value) = option_value(arg, HOST_NS) {
            deny_host_namespace(arg, value)?;
            i += 1;
            continue;
        }
        if HOST_NS.contains(&arg.as_str()) {
            let value = expect_value(extra_args, i, arg)?;
            deny_host_namespace(arg, value)?;
            i += 2;
            continue;
        }

        if let Some(value) = option_value(arg, &["--cap-add"]) {
            deny_dangerous_cap(arg, value)?;
            i += 1;
            continue;
        }
        if arg == "--cap-add" {
            let value = expect_value(extra_args, i, arg)?;
            deny_dangerous_cap(arg, value)?;
            i += 2;
            continue;
        }

        if let Some(value) = option_value(arg, &["--security-opt"]) {
            deny_dangerous_security_opt(arg, value)?;
            i += 1;
            continue;
        }
        if arg == "--security-opt" {
            let value = expect_value(extra_args, i, arg)?;
            deny_dangerous_security_opt(arg, value)?;
            i += 2;
            continue;
        }

        if let Some(value) = option_value(arg, &["--device"]) {
            deny_dangerous_device(arg, value)?;
            i += 1;
            continue;
        }
        if arg == "--device" {
            let value = expect_value(extra_args, i, arg)?;
            deny_dangerous_device(arg, value)?;
            i += 2;
            continue;
        }

        i += 1;
    }
    Ok(())
}

fn expect_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, VestError> {
    args.get(i + 1).map(|s| s.as_str()).ok_or_else(|| {
        VestError::InvalidInput(format!(
            "Missing value for docker flag `{flag}`. {EXPERIMENTAL_WARNING}"
        ))
    })
}

fn option_value<'a>(arg: &'a str, flags: &[&str]) -> Option<&'a str> {
    for flag in flags {
        let prefix = format!("{flag}=");
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value);
        }
    }
    None
}

fn is_privileged_flag(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower == "--privileged" || lower.starts_with("--privileged=")
}

fn deny_host_namespace(flag: &str, value: &str) -> Result<(), VestError> {
    if value.eq_ignore_ascii_case("host") {
        return Err(VestError::ApprovalDenied(format!(
            "Refusing dangerous docker sandbox flag `{flag}={value}` (host namespace). {EXPERIMENTAL_WARNING}"
        )));
    }
    Ok(())
}

fn deny_dangerous_cap(flag: &str, value: &str) -> Result<(), VestError> {
    let lower = value.to_ascii_lowercase();
    if lower == "all" || lower.contains("sys_admin") || lower.contains("sys_ptrace") {
        return Err(VestError::ApprovalDenied(format!(
            "Refusing dangerous docker sandbox flag `{flag}={value}` (capability escalation). {EXPERIMENTAL_WARNING}"
        )));
    }
    Ok(())
}

fn deny_dangerous_security_opt(flag: &str, value: &str) -> Result<(), VestError> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("seccomp=unconfined")
        || lower.contains("apparmor=unconfined")
        || lower.contains("label=disable")
    {
        return Err(VestError::ApprovalDenied(format!(
            "Refusing dangerous docker sandbox flag `{flag}={value}` (disables confinement). {EXPERIMENTAL_WARNING}"
        )));
    }
    Ok(())
}

fn deny_dangerous_device(flag: &str, value: &str) -> Result<(), VestError> {
    let lower = value.to_ascii_lowercase();
    if lower == "/" || lower == "all" || lower.starts_with("/dev/") {
        return Err(VestError::ApprovalDenied(format!(
            "Refusing dangerous docker sandbox flag `{flag}={value}` (host device access). {EXPERIMENTAL_WARNING}"
        )));
    }
    Ok(())
}

fn deny_dangerous_volume(flag: &str, value: &str) -> Result<(), VestError> {
    if is_dangerous_volume_spec(value) {
        return Err(VestError::ApprovalDenied(format!(
            "Refusing dangerous docker volume mount `{flag} {value}` (host root / sensitive path). {EXPERIMENTAL_WARNING}"
        )));
    }
    Ok(())
}

fn deny_dangerous_mount(flag: &str, value: &str) -> Result<(), VestError> {
    if is_dangerous_mount_spec(value) {
        return Err(VestError::ApprovalDenied(format!(
            "Refusing dangerous docker mount `{flag} {value}` (host root / sensitive path). {EXPERIMENTAL_WARNING}"
        )));
    }
    Ok(())
}

fn is_dangerous_volume_spec(spec: &str) -> bool {
    // docker -v/--volume: HOST:CONTAINER[:OPTS]
    // Use `:/` so host path `/` in `/:/host` is not lost to naive split(':').
    let host = if let Some(idx) = spec.find(":/") {
        &spec[..idx]
    } else if let Some((host, _)) = spec.split_once(':') {
        host
    } else {
        spec
    };
    is_sensitive_host_path(host.trim())
}

fn is_dangerous_mount_spec(spec: &str) -> bool {
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(src) = part
            .strip_prefix("source=")
            .or_else(|| part.strip_prefix("src="))
        {
            return is_sensitive_host_path(src);
        }
    }
    false
}

fn is_sensitive_host_path(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }
    let normalized = path.trim_end_matches('/');
    let normalized = if normalized.is_empty() {
        "/"
    } else {
        normalized
    };
    matches!(
        normalized,
        "/" | "/etc"
            | "/proc"
            | "/sys"
            | "/dev"
            | "/var/run/docker.sock"
            | "/run/docker.sock"
            | "/root"
            | "/home"
    ) || normalized.starts_with("/etc/")
        || normalized.starts_with("/proc/")
        || normalized.starts_with("/sys/")
        || normalized.starts_with("/dev/")
        || normalized.ends_with("docker.sock")
}

pub async fn run(args: SandboxArgs) -> Result<(), VestError> {
    eprintln!("{EXPERIMENTAL_WARNING}");

    if !binary_installed("docker") {
        eprintln!("{}", DOCKER_NOT_INSTALLED_MSG);
        return Err(VestError::Sandbox("Docker is not installed".into()));
    }

    match args {
        SandboxArgs::Build => {
            let dockerfile = find_dockerfile()?;
            let dir = dockerfile.parent().unwrap_or(Path::new("."));
            let status = build_command(dir).status()?;
            if !status.success() {
                return Err(VestError::Sandbox("docker build failed".into()));
            }
        }
        SandboxArgs::Start { extra_args } => {
            validate_extra_args(&extra_args)?;
            let status = start_command(&extra_args).status()?;
            if !status.success() {
                return Err(VestError::Sandbox("docker run failed".into()));
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

fn remove_containers() -> Result<(), VestError> {
    let output = Command::new("docker")
        .args(["ps", "-aq", "--filter", &format!("ancestor={}", IMAGE_NAME)])
        .output()?;

    if !output.status.success() {
        return Err(VestError::Sandbox("docker ps failed".into()));
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
        return Err(VestError::Sandbox("docker rm failed".into()));
    }

    Ok(())
}

fn remove_image() -> Result<(), VestError> {
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
            "/tmp/work:/container".to_string(),
        ];
        assert!(validate_extra_args(&extra).is_ok());
        let cmd = start_command(&extra);

        assert_eq!(cmd.get_program(), OsStr::new("docker"));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "--rm");
        assert_eq!(args[2], "-it");
        assert_eq!(args[3], "-p");
        assert_eq!(args[4], "8080:80");
        assert_eq!(args[5], "-v");
        assert_eq!(args[6], "/tmp/work:/container");
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
            assert!(msg.to_string().contains("No Dockerfile found"));
            assert!(msg.to_string().contains("experimental"));
        }
    }

    #[test]
    fn rejects_privileged() {
        let err = validate_extra_args(&["--privileged".into()]).unwrap_err();
        assert!(err.to_string().contains("--privileged"));
        assert!(err.to_string().contains("experimental"));
    }

    #[test]
    fn denials_are_typed_approval_denied() {
        let err = validate_extra_args(&["--privileged".into()]).unwrap_err();
        assert!(
            matches!(err, VestError::ApprovalDenied(_)),
            "dangerous flag denial must map to exit 4: {err}"
        );
        let err = validate_extra_args(&["--pid".into(), "host".into()]).unwrap_err();
        assert!(matches!(err, VestError::ApprovalDenied(_)));
    }

    #[test]
    fn missing_flag_value_is_typed_invalid_input() {
        let err = validate_extra_args(&["-v".into()]).unwrap_err();
        assert!(
            matches!(err, VestError::InvalidInput(_)),
            "missing docker flag value must map to exit 2: {err}"
        );
    }

    #[test]
    fn rejects_pid_host_forms() {
        for args in [
            vec!["--pid=host".into()],
            vec!["--pid".into(), "host".into()],
            vec!["--network=host".into()],
            vec!["--userns".into(), "host".into()],
            vec!["--ipc=host".into()],
        ] {
            let err = validate_extra_args(&args).unwrap_err();
            assert!(
                err.to_string().contains("host"),
                "expected host-namespace rejection for {args:?}: {err}"
            );
            assert!(err.to_string().contains("experimental"));
        }
    }

    #[test]
    fn rejects_host_root_volume_mounts() {
        for args in [
            vec!["-v".into(), "/:/host".into()],
            vec!["--volume=/:/host".into()],
            vec!["-v".into(), "/etc:/etc".into()],
            vec![
                "-v".into(),
                "/var/run/docker.sock:/var/run/docker.sock".into(),
            ],
            vec!["--mount".into(), "type=bind,source=/,target=/host".into()],
        ] {
            let err = validate_extra_args(&args).unwrap_err();
            assert!(
                err.to_string().contains("volume") || err.to_string().contains("mount"),
                "expected volume/mount rejection for {args:?}: {err}"
            );
            assert!(err.to_string().contains("experimental"));
        }
    }

    #[test]
    fn allows_benign_passthrough() {
        let args = vec![
            "-e".into(),
            "FOO=bar".into(),
            "-p".into(),
            "8080:8080".into(),
            "-v".into(),
            "/tmp/vest-work:/work".into(),
            "--name".into(),
            "vest-helper".into(),
        ];
        assert!(validate_extra_args(&args).is_ok());
    }

    #[test]
    fn rejects_cap_add_all_and_unconfined_seccomp() {
        let err = validate_extra_args(&["--cap-add=ALL".into()]).unwrap_err();
        assert!(err.to_string().contains("--cap-add"));
        let err = validate_extra_args(&["--security-opt".into(), "seccomp=unconfined".into()])
            .unwrap_err();
        assert!(err.to_string().contains("security-opt") || err.to_string().contains("seccomp"));
    }

    #[test]
    fn root_volume_host_path_parsed() {
        assert!(is_dangerous_volume_spec("/:/host"));
        assert!(is_dangerous_volume_spec("/:/host:ro"));
        assert!(!is_dangerous_volume_spec("/tmp/work:/work"));
        assert!(!is_dangerous_volume_spec("/host:/container"));
    }
}
