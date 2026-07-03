use crate::ScanArgs;

pub async fn run(args: ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("\u{250c}{}\u{2510}", "\u{2500}".repeat(50));
    println!("\u{2502} {:^48} \u{2502}", "VEST SCAN");
    println!("\u{251c}{}\u{2524}", "\u{2500}".repeat(50));
    println!(
        "\u{2502} Target:      {:<35} \u{2502}",
        &args.target[..args.target.len().min(35)]
    );
    println!(
        "\u{2502} Profile:     {:<35} \u{2502}",
        args.profile.as_deref().unwrap_or("default")
    );
    println!(
        "\u{2502} Mode:        {:<35} \u{2502}",
        args.mode.as_deref().unwrap_or("from config")
    );
    println!(
        "\u{2502} Provider:    {:<35} \u{2502}",
        args.provider.as_deref().unwrap_or("from config")
    );
    println!(
        "\u{2502} Model:       {:<35} \u{2502}",
        args.model.as_deref().unwrap_or("from config")
    );
    println!(
        "\u{2502} Output:      {:<35} \u{2502}",
        args.output.as_deref().unwrap_or("terminal")
    );
    println!("\u{2502} Format:      {:<35} \u{2502}", args.format);
    println!("\u{251c}{}\u{2524}", "\u{2500}".repeat(50));

    if args.dry_run {
        println!("\u{2502} {:^48} \u{2502}", "DRY RUN - No actions taken");
        println!(
            "\u{2502} {:^48} \u{2502}",
            "Would run scan with above config"
        );
    } else {
        println!(
            "\u{2502} {:^48} \u{2502}",
            "Scan engine requires LLM provider"
        );
        println!(
            "\u{2502} {:^48} \u{2502}",
            "Configure a provider in vest.toml"
        );
    }

    println!(
        "\u{2502} {:^48} \u{2502}",
        format!(
            "Scanners: {}",
            if args.scanner.is_empty() {
                "all enabled".to_string()
            } else {
                args.scanner.join(", ")
            }
        )
    );

    if args.no_approval {
        println!("\u{2502} {:^48} \u{2502}", "ALL SAFETY GATES DISABLED");
    }
    if args.approve_writes {
        println!("\u{2502} {:^48} \u{2502}", "Write operations pre-approved");
    }
    if args.approve_exploits {
        println!("\u{2502} {:^48} \u{2502}", "Exploit attempts pre-approved");
    }
    if let Some(timeout) = args.timeout {
        println!("\u{2502} Timeout:      {}s{:<25} \u{2502}", timeout, "");
    }

    println!("\u{2514}{}\u{2518}", "\u{2500}".repeat(50));
    Ok(())
}
