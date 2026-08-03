use rusqlite::Connection;
use vest_core::types::{Finding, FindingStatus, Severity};

use crate::error::StorageError;
use crate::row::{parse_datetime, parse_json, parse_optional_json, require_rows_affected};

pub fn insert_finding(conn: &Connection, finding: &Finding) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO findings (id, scan_id, target_id, title, description, vulnerability_class,
         severity, confidence, status, cvss_score, cve_id, cwe_id, evidence, poc, remediation,
         location, false_positive_history, tags, metadata, discovered_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        rusqlite::params![
            finding.id,
            finding.scan_id,
            finding.target_id,
            finding.title,
            finding.description,
            finding.vulnerability_class.to_string(),
            finding.severity.to_string(),
            finding.confidence,
            finding.status.to_string(),
            finding.cvss_score,
            finding.cve_id,
            finding.cwe_id,
            serde_json::to_string(&finding.evidence)?,
            finding.poc,
            finding.remediation,
            serde_json::to_string(&finding.location)?,
            finding.false_positive_history.as_ref().map(serde_json::to_string).transpose()?,
            serde_json::to_string(&finding.tags)?,
            serde_json::to_string(&finding.metadata)?,
            finding.discovered_at.to_rfc3339(),
            finding.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_finding(conn: &Connection, id: &str) -> Result<Finding, StorageError> {
    conn.query_row(
        "SELECT id, scan_id, target_id, title, description, vulnerability_class,
         severity, confidence, status, cvss_score, cve_id, cwe_id, evidence, poc, remediation,
         location, false_positive_history, tags, metadata, discovered_at, updated_at
         FROM findings WHERE id = ?1",
        rusqlite::params![id],
        row_to_finding,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Finding not found: {}", id))
        }
        other => StorageError::Database(other),
    })
}

pub fn list_findings_by_scan(
    conn: &Connection,
    scan_id: &str,
) -> Result<Vec<Finding>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, target_id, title, description, vulnerability_class,
         severity, confidence, status, cvss_score, cve_id, cwe_id, evidence, poc, remediation,
         location, false_positive_history, tags, metadata, discovered_at, updated_at
         FROM findings WHERE scan_id = ?1 ORDER BY severity, confidence DESC",
    )?;
    let findings = stmt
        .query_map(rusqlite::params![scan_id], row_to_finding)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(findings)
}

pub fn list_findings_by_target(
    conn: &Connection,
    target_id: &str,
) -> Result<Vec<Finding>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, target_id, title, description, vulnerability_class,
         severity, confidence, status, cvss_score, cve_id, cwe_id, evidence, poc, remediation,
         location, false_positive_history, tags, metadata, discovered_at, updated_at
         FROM findings WHERE target_id = ?1 ORDER BY severity, confidence DESC",
    )?;
    let findings = stmt
        .query_map(rusqlite::params![target_id], row_to_finding)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(findings)
}

pub fn list_findings_by_severity(
    conn: &Connection,
    severity: &Severity,
) -> Result<Vec<Finding>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, target_id, title, description, vulnerability_class,
         severity, confidence, status, cvss_score, cve_id, cwe_id, evidence, poc, remediation,
         location, false_positive_history, tags, metadata, discovered_at, updated_at
         FROM findings WHERE severity = ?1 ORDER BY confidence DESC",
    )?;
    let findings = stmt
        .query_map(rusqlite::params![severity.to_string()], row_to_finding)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(findings)
}

pub fn update_finding_status(
    conn: &Connection,
    id: &str,
    status: &FindingStatus,
) -> Result<(), StorageError> {
    let rows = conn.execute(
        "UPDATE findings SET status = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![status.to_string(), chrono::Utc::now().to_rfc3339(), id,],
    )?;
    require_rows_affected(rows, "Finding", id)
}

pub fn update_finding(conn: &Connection, finding: &Finding) -> Result<(), StorageError> {
    let rows = conn.execute(
        "UPDATE findings SET scan_id = ?1, target_id = ?2, title = ?3, description = ?4,
         vulnerability_class = ?5, severity = ?6, confidence = ?7, status = ?8, cvss_score = ?9,
         cve_id = ?10, cwe_id = ?11, evidence = ?12, poc = ?13, remediation = ?14, location = ?15,
         false_positive_history = ?16, tags = ?17, metadata = ?18, updated_at = ?19
         WHERE id = ?20",
        rusqlite::params![
            finding.scan_id,
            finding.target_id,
            finding.title,
            finding.description,
            finding.vulnerability_class.to_string(),
            finding.severity.to_string(),
            finding.confidence,
            finding.status.to_string(),
            finding.cvss_score,
            finding.cve_id,
            finding.cwe_id,
            serde_json::to_string(&finding.evidence)?,
            finding.poc,
            finding.remediation,
            serde_json::to_string(&finding.location)?,
            finding
                .false_positive_history
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            serde_json::to_string(&finding.tags)?,
            serde_json::to_string(&finding.metadata)?,
            finding.updated_at.to_rfc3339(),
            finding.id,
        ],
    )?;
    require_rows_affected(rows, "Finding", &finding.id)
}

pub fn delete_finding(conn: &Connection, id: &str) -> Result<(), StorageError> {
    conn.execute("DELETE FROM findings WHERE id = ?1", rusqlite::params![id])?;
    Ok(())
}

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let evidence_str: String = row.get(12)?;
    let location_str: String = row.get(15)?;
    let tags_str: String = row.get(17)?;
    let metadata_str: String = row.get(18)?;
    let fp_history_str: Option<String> = row.get(16)?;
    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        target_id: row.get(2)?,
        title: row.get(3)?,
        description: row.get(4)?,
        vulnerability_class: row
            .get::<_, String>(5)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidColumnName(5.to_string()))?,
        severity: row
            .get::<_, String>(6)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidColumnName(6.to_string()))?,
        confidence: row.get(7)?,
        status: row
            .get::<_, String>(8)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidColumnName(8.to_string()))?,
        cvss_score: row.get(9)?,
        cve_id: row.get(10)?,
        cwe_id: row.get(11)?,
        evidence: parse_json(&evidence_str, 12)?,
        poc: row.get(13)?,
        remediation: row.get(14)?,
        location: parse_json(&location_str, 15)?,
        false_positive_history: parse_optional_json(fp_history_str, 16)?,
        tags: parse_json(&tags_str, 17)?,
        metadata: parse_json(&metadata_str, 18)?,
        discovered_at: parse_datetime(&row.get::<_, String>(19)?, 19)?,
        updated_at: parse_datetime(&row.get::<_, String>(20)?, 20)?,
    })
}
