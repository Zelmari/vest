use crate::commands::db;
use crate::FindingsArgs;
use vest_core::error::VestError;
use vest_core::types::FindingStatus;
use vest_storage::{findings, ConnectionPool};

pub async fn run(args: FindingsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let pool = db::open_pool()?;

    match args {
        FindingsArgs::List {
            scan_id,
            severity,
            status,
            vulnerability_class,
            limit,
        } => list_findings(&pool, scan_id, severity, status, vulnerability_class, limit),
        FindingsArgs::Show { id } => show_finding(&pool, id),
        FindingsArgs::Validate { id } => validate_finding(&pool, id),
        FindingsArgs::Export { id, format } => export_finding(&pool, id, format),
        FindingsArgs::Stats => stats_dashboard(&pool),
    }
}

fn list_findings(
    pool: &ConnectionPool,
    scan_id: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    vulnerability_class: Option<String>,
    limit: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();

    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();

    if let Some(ref v) = scan_id {
        conditions.push(format!("scan_id = ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Text(v.clone()));
    }
    if let Some(ref v) = severity {
        conditions.push(format!("severity = ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Text(v.clone()));
    }
    if let Some(ref v) = status {
        conditions.push(format!("status = ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Text(v.clone()));
    }
    if let Some(ref v) = vulnerability_class {
        conditions.push(format!("vulnerability_class = ?{}", params.len() + 1));
        params.push(rusqlite::types::Value::Text(v.clone()));
    }

    let limit_val = limit.map(|l| l.to_string()).unwrap_or_else(|| "100".into());
    let query = if conditions.is_empty() {
        format!(
            "SELECT id, title, severity, confidence, vulnerability_class, status FROM findings ORDER BY severity, confidence DESC LIMIT {}",
            limit_val
        )
    } else {
        format!(
            "SELECT id, title, severity, confidence, vulnerability_class, status FROM findings WHERE {} ORDER BY severity, confidence DESC LIMIT {}",
            conditions.join(" AND "),
            limit_val
        )
    };

    println!("\u{250c}{}\u{2510}", "\u{2500}".repeat(110));
    println!("\u{2502} {:^108} \u{2502}", "FINDINGS LIST");
    println!("\u{251c}{}\u{2524}", "\u{2500}".repeat(110));
    println!(
        "\u{2502} {:<36} | {:<24} | {:<10} | {:<8} | {:<20} \u{2502}",
        "ID", "Title", "Severity", "Conf", "Class"
    );
    println!("\u{2502} {}", "-".repeat(108));

    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(&params), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, f64>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;

    let mut count = 0;
    for row in rows {
        let (id, title, sev, conf, class) = row?;
        let short_id = &id[..id.len().min(34)];
        let short_title = &title[..title.len().min(22)];
        println!(
            "\u{2502} {:<36} | {:<24} | {:<10} | {:<8.2} | {:<20} \u{2502}",
            short_id, short_title, sev, conf, class
        );
        count += 1;
    }
    if count == 0 {
        println!("\u{2502} {:^108} \u{2502}", "No findings found");
    }
    println!("\u{2514}{}\u{2518}", "\u{2500}".repeat(110));
    println!("  {} results", count);
    Ok(())
}

fn show_finding(pool: &ConnectionPool, id: String) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();
    let f = findings::get_finding(conn, &id)
        .map_err(|_| VestError::FindingNotFound(format!("Finding '{id}' not found")))?;
    println!();
    println!("  Title:       {}", f.title);
    println!("  Severity:    {}", f.severity);
    println!("  Class:       {}", f.vulnerability_class);
    println!("  Confidence:  {:.2}", f.confidence);
    println!("  Status:      {}", f.status);
    println!(
        "  Severity est: {}",
        f.severity_score_estimate
            .map(|s| s.to_string())
            .unwrap_or_else(|| "N/A".into())
    );
    println!("  CWE:         {}", f.cwe_id.as_deref().unwrap_or("N/A"));
    println!("  CVE:         {}", f.cve_id.as_deref().unwrap_or("N/A"));
    println!("  Scan ID:     {}", f.scan_id);
    println!("  Target ID:   {}", f.target_id);
    println!();
    println!("  Description:");
    println!("    {}", f.description);
    println!();
    println!("  Location:    {}", f.location);
    if let Some(ref poc) = f.poc {
        println!();
        println!("  Proof of Concept:");
        println!("    {}", poc);
    }
    if let Some(ref rem) = f.remediation {
        println!();
        println!("  Remediation:");
        println!("    {}", rem);
    }
    println!();
    Ok(())
}

fn validate_finding(pool: &ConnectionPool, id: String) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();
    let f = findings::get_finding(conn, &id)
        .map_err(|_| VestError::FindingNotFound(format!("Finding '{id}' not found")))?;
    println!("Validating: {}", f.title);
    if f.confidence < 0.3 {
        println!(
            "  -> Marked as FALSE POSITIVE (low confidence: {:.2})",
            f.confidence
        );
        findings::update_finding_status(conn, &id, &FindingStatus::FalsePositive)?;
    } else if f.confidence > 0.8 {
        println!("  -> CONFIRMED (high confidence: {:.2})", f.confidence);
        findings::update_finding_status(conn, &id, &FindingStatus::Confirmed)?;
    } else {
        println!(
            "  -> UNCERTAIN (confidence: {:.2}), kept as 'open'",
            f.confidence
        );
    }
    Ok(())
}

fn export_finding(
    pool: &ConnectionPool,
    id: String,
    format: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();
    let fmt = format.unwrap_or_else(|| "terminal".into());
    let f = findings::get_finding(conn, &id)
        .map_err(|_| VestError::FindingNotFound(format!("Finding '{id}' not found")))?;
    match fmt.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&f)?;
            println!("{}", json);
        }
        _ => {
            println!("Finding: {}", f.title);
            println!("  Severity: {}", f.severity);
            println!("  Class: {}", f.vulnerability_class);
            println!("  Confidence: {:.2}", f.confidence);
            println!("  Description: {}", f.description);
            if let Some(ref poc) = f.poc {
                println!();
                println!("  Proof of Concept:");
                println!("    {}", poc);
            }
            if let Some(ref rem) = f.remediation {
                println!();
                println!("  Remediation:");
                println!("    {}", rem);
            }
        }
    }
    Ok(())
}

fn stats_dashboard(pool: &ConnectionPool) -> Result<(), Box<dyn std::error::Error>> {
    let conn = pool.conn();

    let total: i64 = conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
    let critical: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE severity='critical'",
        [],
        |r| r.get(0),
    )?;
    let high: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE severity='high'",
        [],
        |r| r.get(0),
    )?;
    let medium: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE severity='medium'",
        [],
        |r| r.get(0),
    )?;
    let low: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE severity='low'",
        [],
        |r| r.get(0),
    )?;
    let info: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE severity='info'",
        [],
        |r| r.get(0),
    )?;
    let confirmed: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE status='confirmed'",
        [],
        |r| r.get(0),
    )?;
    let fps: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE status='false_positive'",
        [],
        |r| r.get(0),
    )?;
    let total_scans: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))?;
    let total_targets: i64 = conn.query_row("SELECT COUNT(*) FROM targets", [], |r| r.get(0))?;

    fn bar(count: i64, width: usize) -> String {
        let n = (count as usize * width / 15).min(width);
        "\u{2588}".repeat(n)
    }

    println!();
    println!("  VEST Statistics Dashboard");
    println!("  {}", "-".repeat(25));
    println!();
    println!("  Findings: {} total", total);
    println!("    Critical: {:>3} {}", critical, bar(critical, 30));
    println!("    High:     {:>3} {}", high, bar(high, 30));
    println!("    Medium:   {:>3} {}", medium, bar(medium, 30));
    println!("    Low:      {:>3} {}", low, bar(low, 30));
    println!("    Info:     {:>3} {}", info, bar(info, 30));
    println!("    Confirmed: {} | False Positives: {}", confirmed, fps);
    println!();
    println!("  Scans:   {}", total_scans);
    println!("  Targets: {}", total_targets);

    println!();
    println!("  Top Vulnerability Classes:");
    let mut stmt = conn.prepare(
        "SELECT vulnerability_class, COUNT(*) as cnt FROM findings GROUP BY vulnerability_class ORDER BY cnt DESC LIMIT 5",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (class, count) = row?;
        println!("    {:<30} {:>3}", class, count);
    }
    println!();
    Ok(())
}
