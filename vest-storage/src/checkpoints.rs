use chrono::{DateTime, Utc};
use rusqlite::Connection;

use crate::error::StorageError;
use crate::row::parse_datetime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerCheckpoint {
    pub scan_id: String,
    pub scanner: String,
    pub status: String,
    pub completed_at: DateTime<Utc>,
    pub error: Option<String>,
}

/// Upsert a per-scanner checkpoint for a scan (idempotent on `(scan_id, scanner)`).
pub fn upsert_scanner_checkpoint(
    conn: &Connection,
    scan_id: &str,
    scanner: &str,
    status: &str,
    error: Option<&str>,
) -> Result<(), StorageError> {
    let completed_at = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO scan_scanner_checkpoints (scan_id, scanner, status, completed_at, error)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(scan_id, scanner) DO UPDATE SET
           status = excluded.status,
           completed_at = excluded.completed_at,
           error = excluded.error",
        rusqlite::params![scan_id, scanner, status, completed_at, error],
    )?;
    Ok(())
}

pub fn list_scanner_checkpoints(
    conn: &Connection,
    scan_id: &str,
) -> Result<Vec<ScannerCheckpoint>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT scan_id, scanner, status, completed_at, error
         FROM scan_scanner_checkpoints
         WHERE scan_id = ?1
         ORDER BY completed_at ASC, scanner ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![scan_id], |row| {
            Ok(ScannerCheckpoint {
                scan_id: row.get(0)?,
                scanner: row.get(1)?,
                status: row.get(2)?,
                completed_at: parse_datetime(&row.get::<_, String>(3)?, 3)?,
                error: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Scanner names marked `completed` for this scan (order not significant).
pub fn list_completed_scanner_names(
    conn: &Connection,
    scan_id: &str,
) -> Result<Vec<String>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT scanner FROM scan_scanner_checkpoints
         WHERE scan_id = ?1 AND status = 'completed'
         ORDER BY scanner ASC",
    )?;
    let names = stmt
        .query_map(rusqlite::params![scan_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

pub fn delete_checkpoints_for_scan(conn: &Connection, scan_id: &str) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM scan_scanner_checkpoints WHERE scan_id = ?1",
        rusqlite::params![scan_id],
    )?;
    Ok(())
}
