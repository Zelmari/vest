mod commands;

use clap::{Args, CommandFactory, Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "vest")]
#[command(about = "Vulnerability Exploitation & Scanning Toolkit", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Config file path
    #[arg(short = 'c', long, default_value = "vest.toml")]
    pub config: String,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a vulnerability scan
    Scan(Box<ScanArgs>),
    /// Configuration management
    #[command(subcommand)]
    Config(ConfigArgs),
    /// LLM provider management
    #[command(subcommand)]
    Providers(ProvidersArgs),
    /// Target management
    #[command(subcommand)]
    Targets(TargetsArgs),
    /// Scan history management
    #[command(subcommand)]
    Scans(ScansArgs),
    /// Finding management
    #[command(subcommand)]
    Findings(FindingsArgs),
    /// Report generation
    #[command(subcommand)]
    Report(ReportArgs),
    /// External tool management
    #[command(subcommand)]
    Tools(ToolsArgs),
    /// Experimental Docker helper (build/start/clean) — not an OS sandbox for agent tools
    #[command(subcommand)]
    Sandbox(SandboxArgs),
    /// Print local diagnostics (config, paths, provider env presence, policy)
    Doctor,
    /// Generate shell completions
    Completions(CompletionsArgs),
}

#[derive(Args)]
pub struct ScanArgs {
    /// Target to scan (URL, path, PID, host:port)
    #[arg(value_name = "TARGET")]
    pub target: String,

    /// Use a saved scan profile
    #[arg(long)]
    pub profile: Option<String>,

    /// Override scan mode (pipeline, swarm, tool-use, hierarchical)
    #[arg(long)]
    pub mode: Option<String>,

    /// Override LLM provider
    #[arg(long)]
    pub provider: Option<String>,

    /// Override LLM model
    #[arg(long)]
    pub model: Option<String>,

    /// Limit to specific scanners (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub scanner: Vec<String>,

    /// Output report path
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    /// Output format (json, sarif, terminal, markdown)
    #[arg(short = 'f', long, default_value = "terminal")]
    pub format: String,

    /// Pre-approve LocalWrite for this session (effect+session grant; not a policy bypass)
    #[arg(long)]
    pub approve_writes: bool,

    /// Pre-approve exploit-class effects for this session
    /// (ActiveNetworkProbe, StateChangingNetworkRequest, CommandExecution)
    #[arg(long)]
    pub approve_exploits: bool,

    /// Pre-approve a specific ToolEffect by snake_case name (repeatable)
    #[arg(long = "approve-effect", value_name = "EFFECT", action = clap::ArgAction::Append)]
    pub approve_effect: Vec<String>,

    /// Do not prompt for approvals; deny approval-required operations (fail closed).
    /// This is NOT an unrestricted / allow-all mode.
    #[arg(long, conflicts_with_all = ["approve_writes", "approve_exploits", "approve_effect"])]
    pub no_approval: bool,

    /// Override rate limit (requests per second)
    #[arg(long)]
    pub rate: Option<u32>,

    /// Disable rate limiting entirely
    #[arg(long)]
    pub no_rate_limit: bool,

    /// Max scan duration in seconds (0 = unlimited)
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Plan the scan without executing
    #[arg(long)]
    pub dry_run: bool,

    /// Resume a previous scan (not implemented; hidden until checkpoint storage exists)
    #[arg(long, hide = true, value_name = "SCAN_ID")]
    pub resume: Option<String>,

    /// Target type (process, binary, web, network, browser, file)
    #[arg(long)]
    pub target_type: Option<String>,

    /// PID for process targets
    #[arg(long)]
    pub pid: Option<u32>,

    /// Opt in to the explicit memory-scan simulation harness (fabricated regions/bytes).
    /// Real process-memory acquisition is not implemented; without this flag memory
    /// scanning fails closed / reports unsupported.
    #[arg(long)]
    pub allow_memory_simulation: bool,

    /// Opt in to active web vulnerability probes (.env/.git exposure, XSS/SQLi, etc.).
    /// Off by default; OR'd with `scanner.web.allow_active_probes` in config.
    /// Probes stay off unless also confirmed via `--confirm-active-probes` or `--approve-exploits`.
    #[arg(long)]
    pub allow_active_probes: bool,

    /// Second consent key for active web probes (with `--allow-active-probes` or config).
    /// Also satisfied by `--approve-exploits`. Config/allow alone is not enough.
    #[arg(long)]
    pub confirm_active_probes: bool,

    /// Include finding evidence/PoC in JSON and Markdown reports.
    /// Off by default (REP-1); secrets are still redacted best-effort when enabled.
    /// OR'd with `general.include_report_evidence` in config.
    #[arg(long)]
    pub include_evidence: bool,

    /// Force offline / no AI: equivalent to `--provider none` (scanner-only).
    #[arg(long)]
    pub offline: bool,

    /// Alias for `--offline`: disable LLM providers for this scan.
    #[arg(long = "no-ai")]
    pub no_ai: bool,
}

#[derive(Subcommand)]
pub enum ConfigArgs {
    /// Create vest.toml from template
    Init,
    /// Display current configuration
    Show,
    /// Validate configuration
    Validate,
    /// Show config file path
    Path,
    /// Set a config value
    Set { key: String, value: String },
}

#[derive(Subcommand)]
pub enum ProvidersArgs {
    /// List configured providers
    List,
    /// Test all configured providers
    Test {
        /// Test one provider instead of all configured providers
        #[arg(short, long)]
        provider: Option<String>,
    },
    /// List available models for a provider
    Models {
        #[arg(short, long)]
        provider: String,
    },
    /// Pull a model into Ollama
    Pull {
        #[arg(value_name = "MODEL")]
        model: String,
    },
    /// Check provider health
    Status,
    /// Print instructions for configuring a provider API key via the environment
    SetKey {
        /// Provider name (openai, deepseek, anthropic, google, groq, openrouter)
        #[arg(value_name = "PROVIDER")]
        provider: String,
        /// Deprecated: accepting a key on the CLI is insecure (shell history / process list).
        /// The value is never printed. Prefer environment variables.
        #[arg(short, long, hide = true)]
        key: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TargetsArgs {
    /// List previously scanned targets
    List,
    /// Show target details
    Show {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Add a target to the database
    Add {
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Remove a target
    Remove {
        #[arg(value_name = "ID")]
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ScansArgs {
    /// List stored scans
    List {
        /// Filter by target id
        #[arg(long)]
        target_id: Option<String>,
        /// Maximum rows to show
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show scan details and top findings
    Show {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Delete a stored scan
    Delete {
        #[arg(value_name = "ID")]
        id: String,
    },
}

#[derive(Subcommand)]
pub enum FindingsArgs {
    /// List findings (filterable)
    List {
        #[arg(long)]
        scan_id: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        vulnerability_class: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Show finding details with evidence
    Show {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Manually re-validate a finding
    Validate {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Export finding as bug bounty submission
    Export {
        #[arg(value_name = "ID")]
        id: String,
        #[arg(long)]
        format: Option<String>,
    },
    /// Statistics dashboard
    Stats,
}

#[derive(Subcommand)]
pub enum ReportArgs {
    /// Generate report for a scan
    Generate {
        #[arg(value_name = "SCAN_ID")]
        scan_id: String,
        /// Output format (terminal, json, sarif, markdown)
        #[arg(short = 'f', long, default_value = "terminal")]
        format: String,
        /// Output report path
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Include finding evidence/PoC in JSON and Markdown reports.
        /// Off by default (REP-1); secrets are still redacted best-effort when enabled.
        #[arg(long)]
        include_evidence: bool,
    },
    /// Summary of all scans
    Summary,
    /// Compare two scans
    Compare { scan_a: String, scan_b: String },
}

#[derive(Subcommand)]
pub enum ToolsArgs {
    /// Install external tool
    Install {
        #[arg(value_name = "TOOL")]
        tool: String,
    },
    /// Update external tool
    Update {
        #[arg(value_name = "TOOL")]
        tool: String,
    },
    /// List installed tools and versions
    List,
}

#[derive(Subcommand)]
pub enum SandboxArgs {
    /// Build the experimental vest-sandbox Docker image (requires a local Dockerfile)
    Build,
    /// Start the experimental helper container (not a verified agent sandbox)
    #[command(allow_hyphen_values = true)]
    Start {
        /// Additional arguments to pass through to docker run
        extra_args: Vec<String>,
    },
    /// Clean up helper containers and the vest-sandbox image
    Clean,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: String,
}

/// Only Vest/provider-related keys may be loaded from `.env` files.
/// Existing process environment values are never overwritten.
const DOTENV_ALLOWLIST: &[&str] = &[
    "VEST_HOME",
    "VEST_DB_PATH",
    "VEST_CONFIG",
    "RUST_LOG",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "OLLAMA_HOST",
    "OLLAMA_API_KEY",
];

fn dotenv_key_allowed(key: &str) -> bool {
    DOTENV_ALLOWLIST.iter().any(|k| k.eq_ignore_ascii_case(key))
}

fn load_dotenv() {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let paths = [
        std::path::PathBuf::from(".env"),
        std::path::PathBuf::from(&home).join(".vest").join(".env"),
    ];
    for path in &paths {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = trimmed.split_once('=') {
                    let key = key.trim();
                    if !dotenv_key_allowed(key) {
                        continue;
                    }
                    let value = value.trim().trim_matches('"').trim_matches('\'');
                    // Never override an existing process environment value.
                    if std::env::var(key).is_err() {
                        std::env::set_var(key, value);
                    }
                }
            }
        }
    }
}

/// Process exit codes for the `vest` CLI.
///
/// | Code | Meaning |
/// |------|---------|
/// | 0 | Success |
/// | 1 | Unexpected internal / unclassified error |
/// | 2 | Invalid command or input |
/// | 3 | Configuration error |
/// | 4 | Authorisation denied |
/// | 5 | Scanner failure |
/// | 6 | Persistence failure |
/// | 7 | Provider-only failure with preserved local result (soft failure) |
pub mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const INTERNAL: i32 = 1;
    pub const INVALID_INPUT: i32 = 2;
    pub const CONFIG: i32 = 3;
    pub const AUTHORISATION: i32 = 4;
    pub const SCANNER: i32 = 5;
    pub const PERSISTENCE: i32 = 6;
    pub const PROVIDER_SOFT: i32 = 7;
}

fn exit_code_for_error(err: &(dyn std::error::Error + 'static)) -> i32 {
    // Prefer typed VestError mapping (no substring search).
    if let Some(vest) = err.downcast_ref::<vest_core::VestError>() {
        return vest.cli_exit_code();
    }
    // Walk sources for a nested VestError.
    let mut source = err.source();
    while let Some(s) = source {
        if let Some(vest) = s.downcast_ref::<vest_core::VestError>() {
            return vest.cli_exit_code();
        }
        source = s.source();
    }
    // Last-resort heuristics for remaining untyped `Box<dyn Error>` call sites
    // (non-scan subcommands). Scan/completions prefer typed VestError (K14).
    exit_code_for_message_legacy(&err.to_string())
}

fn exit_code_for_message_legacy(msg: &str) -> i32 {
    let lower = msg.to_lowercase();
    if lower.contains("config") || lower.contains("parse config") || lower.contains("vest.toml") {
        return exit_code::CONFIG;
    }
    if lower.contains("authoris")
        || lower.contains("authoriz")
        || lower.contains("denied")
        || lower.contains("approval")
        || lower.contains("safety")
    {
        return exit_code::AUTHORISATION;
    }
    if lower.contains("persist") || lower.contains("sqlite") || lower.contains("database") {
        return exit_code::PERSISTENCE;
    }
    if lower.contains("scanner") || lower.contains("scan failed") {
        return exit_code::SCANNER;
    }
    if lower.contains("unsupported shell")
        || (lower.contains("unknown") && lower.contains("format"))
        || lower.contains("invalid")
    {
        return exit_code::INVALID_INPUT;
    }
    exit_code::INTERNAL
}

#[tokio::main]
async fn main() {
    load_dotenv();
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    // Logs go to stderr so machine-readable stdout (JSON reports) stays clean.
    fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("VEST v{} starting up", env!("CARGO_PKG_VERSION"));

    if let Err(e) = dispatch(cli).await {
        // Never print the raw error chain if it might echo secrets; prefer Display.
        let display = e.to_string();
        eprintln!("Error: {display}");
        tracing::error!("command failed");
        std::process::exit(exit_code_for_error(e.as_ref()));
    }
}

async fn dispatch(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Scan(args) => commands::scan::run(*args, &cli.config).await?,
        Commands::Config(args) => commands::config::run(args, &cli.config).await?,
        Commands::Providers(args) => commands::providers::run(args).await?,
        Commands::Targets(args) => commands::targets::run(args).await?,
        Commands::Scans(args) => commands::scans::run(args).await?,
        Commands::Findings(args) => commands::findings::run(args).await?,
        Commands::Report(args) => commands::report::run(args).await?,
        Commands::Tools(args) => commands::tools::run(args).await?,
        Commands::Sandbox(args) => commands::sandbox::run(args).await?,
        Commands::Doctor => commands::doctor::run(&cli.config).await?,
        Commands::Completions(args) => {
            let shell = match args.shell.as_str() {
                "bash" => clap_complete::Shell::Bash,
                "zsh" => clap_complete::Shell::Zsh,
                "fish" => clap_complete::Shell::Fish,
                _ => {
                    return Err(vest_core::VestError::InvalidInput(format!(
                        "Unsupported shell: {}. Supported: bash, zsh, fish",
                        args.shell
                    ))
                    .into());
                }
            };
            clap_complete::generate(shell, &mut Cli::command(), "vest", &mut std::io::stdout());
        }
    }
    Ok(())
}

#[cfg(test)]
mod exit_code_tests {
    use super::*;

    #[test]
    fn typed_vest_error_preferred() {
        let err: Box<dyn std::error::Error> =
            Box::new(vest_core::VestError::Config("bad toml".into()));
        assert_eq!(exit_code_for_error(err.as_ref()), exit_code::CONFIG);
        let err: Box<dyn std::error::Error> =
            Box::new(vest_core::VestError::ApprovalDenied("no".into()));
        assert_eq!(exit_code_for_error(err.as_ref()), exit_code::AUTHORISATION);
    }

    #[test]
    fn legacy_string_fallback() {
        assert_eq!(
            exit_code_for_message_legacy("Failed to load config: parse error"),
            exit_code::CONFIG
        );
        assert_eq!(
            exit_code_for_message_legacy("Unsupported shell: foo"),
            exit_code::INVALID_INPUT
        );
    }

    #[test]
    fn dotenv_allowlist() {
        assert!(dotenv_key_allowed("OPENAI_API_KEY"));
        assert!(dotenv_key_allowed("vest_home"));
        assert!(!dotenv_key_allowed("PATH"));
        assert!(!dotenv_key_allowed("AWS_SECRET_ACCESS_KEY"));
    }
}
