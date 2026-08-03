use crate::commands::db;
use crate::ScansArgs;
use vest_core::types::{Finding, ScanSession};
use vest_core::VestError;
use vest_storage::{findings, scans, targets};

pub async fn run(args: ScansArgs) -> Result<(), Box<dyn std::error::Error>> {
    let pool = db::open_pool()?;

    match args {
        ScansArgs::List { target_id, limit } => list_scans(&pool, target_id, limit),
        ScansArgs::Show { id } => show_scan(&pool, id),
        ScansArgs::Delete { id } => match scans::delete_scan(pool.conn(), &id) {
            Ok(()) => {
                println!("Deleted scan {}", id);
                Ok(())
            }
            Err(e) => Err(match &e {
                vest_storage::StorageError::NotFound(_) => VestError::InvalidInput(e.to_string()),
                other => VestError::Storage(other.to_string()),
            }
            .into()),
        },
    }
}

fn list_scans(
    pool: &vest_storage::ConnectionPool,
    target_id: Option<String>,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut scan_list = if let Some(target_id) = target_id {
        scans::list_scans_by_target(pool.conn(), &target_id)
            .map_err(|e| VestError::Storage(e.to_string()))?
    } else {
        scans::list_scans(pool.conn()).map_err(|e| VestError::Storage(e.to_string()))?
    };

    if let Some(limit) = limit {
        scan_list.truncate(limit);
    }

    if scan_list.is_empty() {
        println!("No scans found.");
        return Ok(());
    }

    println!(
        "{:<36} | {:<22} | {:<12} | {:<12} | {:>8}",
        "Scan ID", "Target", "Status", "Mode", "Findings"
    );
    println!("{}", "-".repeat(102));
    for scan in &scan_list {
        println!(
            "{:<36} | {:<22} | {:<12} | {:<12} | {:>8}",
            truncate(&scan.id, 36),
            truncate(&target_label(scan), 22),
            scan.status,
            scan.mode,
            scan.total_findings
        );
    }
    println!("Total: {}", scan_list.len());
    Ok(())
}

fn show_scan(
    pool: &vest_storage::ConnectionPool,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let scan = scans::get_scan(pool.conn(), &id).map_err(|e| match &e {
        vest_storage::StorageError::NotFound(_) => VestError::InvalidInput(e.to_string()),
        other => VestError::Storage(other.to_string()),
    })?;
    let finding_list = findings::list_findings_by_scan(pool.conn(), &id)
        .map_err(|e| VestError::Storage(e.to_string()))?;
    let target = targets::get_target(pool.conn(), &scan.target_id).ok();

    println!("Scan: {}", scan.id);
    println!("  Target:   {}", target_label(&scan));
    if let Some(target) = target {
        println!("  Target ID: {}", target.id);
        println!("  Type:      {}", target.target_type);
    } else {
        println!("  Target ID: {}", scan.target_id);
    }
    println!("  Status:   {}", scan.status);
    println!("  Mode:     {}", scan.mode);
    println!(
        "  Model:    {}",
        scan.agent_model.as_deref().unwrap_or("N/A")
    );
    println!("  Started:  {}", optional_time(scan.started_at));
    println!("  Finished: {}", optional_time(scan.completed_at));
    println!(
        "  Duration: {}",
        scan.duration_ms
            .map(|ms| format!("{} ms", ms))
            .unwrap_or_else(|| "N/A".into())
    );
    println!();
    println!(
        "  Findings: {} total | critical={} high={} medium={} low={} info={}",
        scan.total_findings,
        scan.critical_count,
        scan.high_count,
        scan.medium_count,
        scan.low_count,
        scan.info_count
    );

    if !finding_list.is_empty() {
        println!();
        println!("  Top Findings");
        println!("  {}", "-".repeat(12));
        for finding in top_findings(&finding_list).into_iter().take(10) {
            println!(
                "  [{:<8}] {:<44} {:.2}",
                finding.severity,
                truncate(&finding.title, 44),
                finding.confidence
            );
        }
    }

    Ok(())
}

fn top_findings(findings: &[Finding]) -> Vec<&Finding> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    sorted
}

fn target_label(scan: &ScanSession) -> String {
    scan.metadata
        .get("target")
        .and_then(|target| target.get("name"))
        .and_then(|name| name.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(&scan.target_id)
        .to_string()
}

fn optional_time(value: Option<chrono::DateTime<chrono::Utc>>) -> String {
    value
        .map(|time| time.to_rfc3339())
        .unwrap_or_else(|| "N/A".into())
}

fn severity_rank(severity: vest_core::types::Severity) -> u8 {
    match severity {
        vest_core::types::Severity::Critical => 5,
        vest_core::types::Severity::High => 4,
        vest_core::types::Severity::Medium => 3,
        vest_core::types::Severity::Low => 2,
        vest_core::types::Severity::Info => 1,
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut out: String = value.chars().take(max_chars).collect();
    if out.len() < value.len() {
        out.push_str("...");
    }
    out
}
