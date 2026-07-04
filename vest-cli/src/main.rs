mod commands;
mod tui;

use clap::{Args, Parser, Subcommand};
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
    Scan(ScanArgs),
    /// Configuration management
    #[command(subcommand)]
    Config(ConfigArgs),
    /// LLM provider management
    #[command(subcommand)]
    Providers(ProvidersArgs),
    /// Target management
    #[command(subcommand)]
    Targets(TargetsArgs),
    /// Finding management
    #[command(subcommand)]
    Findings(FindingsArgs),
    /// Report generation
    #[command(subcommand)]
    Report(ReportArgs),
    /// External tool management
    #[command(subcommand)]
    Tools(ToolsArgs),
    /// Docker sandbox management
    #[command(subcommand)]
    Sandbox(SandboxArgs),
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

    /// Output format (json, terminal, markdown)
    #[arg(short = 'f', long, default_value = "terminal")]
    pub format: String,

    /// Pre-approve all write operations
    #[arg(long)]
    pub approve_writes: bool,

    /// Pre-approve all exploit attempts
    #[arg(long)]
    pub approve_exploits: bool,

    /// Completely disable all approval gates
    #[arg(long, conflicts_with_all = ["approve_writes", "approve_exploits"])]
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

    /// Resume a previous scan
    #[arg(long)]
    pub resume: Option<String>,

    /// Target type (process, binary, web, network, browser, file)
    #[arg(long)]
    pub target_type: Option<String>,

    /// PID for process targets
    #[arg(long)]
    pub pid: Option<u32>,
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
    Test,
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
    /// Store an API key for a provider
    SetKey {
        /// Provider name (openai, deepseek, anthropic, google, groq, openrouter)
        #[arg(value_name = "PROVIDER")]
        provider: String,
        /// API key (if not provided, will prompt interactively)
        #[arg(short, long)]
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
    /// Update all external tools
    Update,
    /// List installed tools and versions
    List,
}

#[derive(Subcommand)]
pub enum SandboxArgs {
    /// Build sandbox Docker image
    Build,
    /// Start sandbox container
    Start,
    /// Clean up sandbox containers
    Clean,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    fmt().with_env_filter(env_filter).init();

    tracing::info!("VEST v{} starting up", env!("CARGO_PKG_VERSION"));

    if let Err(e) = dispatch(cli).await {
        tracing::error!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Scan(args) => commands::scan::run(args).await?,
        Commands::Config(args) => commands::config::run(args).await?,
        Commands::Providers(args) => commands::providers::run(args).await?,
        Commands::Targets(args) => commands::targets::run(args).await?,
        Commands::Findings(args) => commands::findings::run(args).await?,
        Commands::Report(args) => commands::report::run(args).await?,
        Commands::Tools(args) => commands::tools::run(args).await?,
        Commands::Sandbox(args) => commands::sandbox::run(args).await?,
        Commands::Completions(_args) => println!("Shell completions not yet implemented"),
    }
    Ok(())
}
