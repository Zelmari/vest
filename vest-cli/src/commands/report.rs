use crate::commands::db;
use crate::ReportArgs;
use vest_core::Reporter;
use vest_storage::{findings, scans, ConnectionPool};

pub async fn run(args: ReportArgs) -> Result<(), Box<dyn std::error::Error>> {
    let pool = db::open_pool()?;

    match args {
        ReportArgs::Generate {
            scan_id,
            format,
            output,
            include_evidence,
        } => generate_report(&pool, scan_id, format, output, include_evidence).await,
        ReportArgs::Summary => scan_summary(&pool),
        ReportArgs::Compare { scan_a, scan_b } => compare_scans(&pool, scan_a, scan_b),
    }
}

async fn generate_report(
    pool: &ConnectionPool,
    scan_id: String,
    format: String,
    output: Option<String>,
    include_evidence: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();
    match scans::get_scan(conn, &scan_id) {
        Ok(scan) => {
            let finding_list = findings::list_findings_by_scan(conn, &scan_id).unwrap_or_default();
            let report = match format.as_str() {
                "json" => {
                    vest_report::JsonReporter::new()
                        .include_evidence(include_evidence)
                        .generate_report(&scan, &finding_list)
                        .await?
                }
                "markdown" | "md" => {
                    vest_report::MarkdownReporter::new()
                        .include_evidence(include_evidence)
                        .generate_report(&scan, &finding_list)
                        .await?
                }
                "terminal" | "text" => {
                    vest_report::TerminalReporter
                        .generate_report(&scan, &finding_list)
                        .await?
                }
                other => {
                    return Err(format!(
                        "Unknown report format '{}'. Use terminal, json, or markdown.",
                        other
                    )
                    .into())
                }
            };
            println!("{}", report);

            let report_path = output.map(std::path::PathBuf::from).unwrap_or_else(|| {
                let ext = match format.as_str() {
                    "json" => "json",
                    "markdown" | "md" => "md",
                    _ => "txt",
                };
                db::db_path()
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join(format!(
                        "report-{}.{}",
                        &scan_id[..scan_id.len().min(8)],
                        ext
                    ))
            });
            if let Some(parent) = report_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&report_path, report)?;
            println!("\n  Report saved to: {}", report_path.display());
        }
        Err(e) => {
            return Err(format!("Scan '{scan_id}' not found: {e}").into());
        }
    }
    Ok(())
}

fn scan_summary(pool: &ConnectionPool) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();
    let scan_list = scans::list_scans(conn).unwrap_or_default();

    println!();
    println!("  Scan Summary");
    println!("  {}", "-".repeat(12));
    println!();
    if scan_list.is_empty() {
        println!("  No scans found.");
        return Ok(());
    }
    println!(
        "  {:<36} | {:<12} | {:<14} | {:<12}",
        "Scan ID", "Status", "Mode", "Findings"
    );
    println!("  {}", "-".repeat(80));

    for scan in &scan_list {
        let short_id = &scan.id[..scan.id.len().min(34)];
        println!(
            "  {:<36} | {:<12} | {:<14} | {:>12}",
            short_id,
            scan.status.to_string(),
            scan.mode.to_string(),
            scan.total_findings
        );
    }
    println!();
    println!("  Total scans: {}", scan_list.len());
    Ok(())
}

fn compare_scans(
    pool: &ConnectionPool,
    scan_a: String,
    scan_b: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();

    let a_findings = findings::list_findings_by_scan(conn, &scan_a).unwrap_or_default();
    let b_findings = findings::list_findings_by_scan(conn, &scan_b).unwrap_or_default();

    println!();
    println!("  Scan Comparison");
    println!("  {}", "-".repeat(15));
    println!();
    println!("  {:<30} {:>15} {:>15}", "Metric", "Scan A", "Scan B");
    println!("  {}", "-".repeat(62));
    println!(
        "  {:<30} {:>15} {:>15}",
        "Total Findings",
        a_findings.len(),
        b_findings.len()
    );

    let count_sev = |findings: &[vest_core::types::Finding], sev: &str| -> usize {
        findings
            .iter()
            .filter(|f| f.severity.to_string() == sev)
            .count()
    };

    for sev in &["critical", "high", "medium", "low", "info"] {
        println!(
            "  {:<30} {:>15} {:>15}",
            sev,
            count_sev(&a_findings, sev),
            count_sev(&b_findings, sev)
        );
    }

    let a_confirmed = a_findings
        .iter()
        .filter(|f| f.status == vest_core::types::FindingStatus::Confirmed)
        .count();
    let b_confirmed = b_findings
        .iter()
        .filter(|f| f.status == vest_core::types::FindingStatus::Confirmed)
        .count();
    println!(
        "  {:<30} {:>15} {:>15}",
        "Confirmed", a_confirmed, b_confirmed
    );

    let a_fp = a_findings
        .iter()
        .filter(|f| f.status == vest_core::types::FindingStatus::FalsePositive)
        .count();
    let b_fp = b_findings
        .iter()
        .filter(|f| f.status == vest_core::types::FindingStatus::FalsePositive)
        .count();
    println!("  {:<30} {:>15} {:>15}", "False Positives", a_fp, b_fp);

    let a_avg = if a_findings.is_empty() {
        0.0
    } else {
        a_findings.iter().map(|f| f.confidence).sum::<f64>() / a_findings.len() as f64
    };
    let b_avg = if b_findings.is_empty() {
        0.0
    } else {
        b_findings.iter().map(|f| f.confidence).sum::<f64>() / b_findings.len() as f64
    };
    println!("  {:<30} {:>14.2} {:>15.2}", "Avg Confidence", a_avg, b_avg);

    println!();
    Ok(())
}
