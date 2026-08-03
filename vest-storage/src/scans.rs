use rusqlite::Connection;
use vest_core::types::{ScanSession, ScanStatus};

use crate::error::StorageError;
use crate::row::{parse_datetime, parse_json, parse_optional_datetime, require_rows_affected};

pub fn insert_scan(conn: &Connection, scan: &ScanSession) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO scans (id, target_id, mode, config, status, started_at, completed_at,
         duration_ms, agent_model, total_findings, critical_count, high_count, medium_count,
         low_count, info_count, metadata, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        rusqlite::params![
            scan.id,
            scan.target_id,
            scan.mode.to_string(),
            serde_json::to_string(&scan.config)?,
            scan.status.to_string(),
            scan.started_at.map(|t| t.to_rfc3339()),
            scan.completed_at.map(|t| t.to_rfc3339()),
            scan.duration_ms,
            scan.agent_model,
            scan.total_findings as i64,
            scan.critical_count as i64,
            scan.high_count as i64,
            scan.medium_count as i64,
            scan.low_count as i64,
            scan.info_count as i64,
            serde_json::to_string(&scan.metadata)?,
            scan.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn row_to_scan(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanSession> {
    let config_str: String = row.get(3)?;
    let metadata_str: String = row.get(15)?;
    Ok(ScanSession {
        id: row.get(0)?,
        target_id: row.get(1)?,
        mode: row
            .get::<_, String>(2)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidColumnName(2.to_string()))?,
        config: parse_json(&config_str, 3)?,
        status: row
            .get::<_, String>(4)?
            .parse()
            .map_err(|_| rusqlite::Error::InvalidColumnName(4.to_string()))?,
        agent_model: row.get(5)?,
        started_at: parse_optional_datetime(row.get::<_, Option<String>>(6)?, 6)?,
        completed_at: parse_optional_datetime(row.get::<_, Option<String>>(7)?, 7)?,
        duration_ms: row.get(8)?,
        total_findings: row.get::<_, i64>(9)? as u64,
        critical_count: row.get::<_, i64>(10)? as u64,
        high_count: row.get::<_, i64>(11)? as u64,
        medium_count: row.get::<_, i64>(12)? as u64,
        low_count: row.get::<_, i64>(13)? as u64,
        info_count: row.get::<_, i64>(14)? as u64,
        metadata: parse_json(&metadata_str, 15)?,
        created_at: parse_datetime(&row.get::<_, String>(16)?, 16)?,
    })
}

pub fn get_scan(conn: &Connection, id: &str) -> Result<ScanSession, StorageError> {
    conn.query_row(
        "SELECT id, target_id, mode, config, status, agent_model, started_at, completed_at,
         duration_ms, total_findings, critical_count, high_count, medium_count,
         low_count, info_count, metadata, created_at
         FROM scans WHERE id = ?1",
        rusqlite::params![id],
        row_to_scan,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Scan not found: {}", id))
        }
        other => StorageError::Database(other),
    })
}

pub fn list_scans(conn: &Connection) -> Result<Vec<ScanSession>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, target_id, mode, config, status, agent_model, started_at, completed_at,
         duration_ms, total_findings, critical_count, high_count, medium_count,
         low_count, info_count, metadata, created_at
         FROM scans ORDER BY created_at DESC",
    )?;
    let scans = stmt
        .query_map([], row_to_scan)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(scans)
}

pub fn list_scans_by_target(
    conn: &Connection,
    target_id: &str,
) -> Result<Vec<ScanSession>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, target_id, mode, config, status, agent_model, started_at, completed_at,
         duration_ms, total_findings, critical_count, high_count, medium_count,
         low_count, info_count, metadata, created_at
         FROM scans WHERE target_id = ?1 ORDER BY created_at DESC",
    )?;
    let scans = stmt
        .query_map(rusqlite::params![target_id], row_to_scan)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(scans)
}

pub fn update_scan_status(
    conn: &Connection,
    id: &str,
    status: &ScanStatus,
) -> Result<(), StorageError> {
    let rows = conn.execute(
        "UPDATE scans SET status = ?1 WHERE id = ?2",
        rusqlite::params![status.to_string(), id],
    )?;
    require_rows_affected(rows, "Scan", id)
}

pub fn delete_scan(conn: &Connection, id: &str) -> Result<(), StorageError> {
    conn.execute("DELETE FROM scans WHERE id = ?1", rusqlite::params![id])?;
    Ok(())
}
