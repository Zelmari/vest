use rusqlite::Connection;
use vest_core::types::Artifact;

use crate::error::StorageError;

pub fn insert_artifact(conn: &Connection, artifact: &Artifact) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO artifacts (id, scan_id, finding_id, type, mime_type, filename, size_bytes,
         content_path, metadata, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            artifact.id,
            artifact.scan_id,
            artifact.finding_id.as_ref().map(|id| id.to_string()),
            artifact.artifact_type,
            artifact.mime_type,
            artifact.filename,
            artifact.size_bytes,
            artifact.content_path,
            serde_json::to_string(&artifact.metadata)?,
            artifact.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_artifact(conn: &Connection, id: &str) -> Result<Artifact, StorageError> {
    conn.query_row(
        "SELECT id, scan_id, finding_id, type, mime_type, filename, size_bytes,
         content_path, metadata, created_at
         FROM artifacts WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            let metadata_str: String = row.get(8)?;
            Ok(Artifact {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                finding_id: row.get(2)?,
                artifact_type: row.get(3)?,
                mime_type: row.get(4)?,
                filename: row.get(5)?,
                size_bytes: row.get(6)?,
                content_path: row.get(7)?,
                metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Artifact not found: {}", id))
        }
        other => StorageError::Database(other),
    })
}

pub fn list_artifacts_by_scan(
    conn: &Connection,
    scan_id: &str,
) -> Result<Vec<Artifact>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, finding_id, type, mime_type, filename, size_bytes,
         content_path, metadata, created_at
         FROM artifacts WHERE scan_id = ?1 ORDER BY created_at",
    )?;
    let artifacts = stmt
        .query_map(rusqlite::params![scan_id], |row| {
            let metadata_str: String = row.get(8)?;
            Ok(Artifact {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                finding_id: row.get(2)?,
                artifact_type: row.get(3)?,
                mime_type: row.get(4)?,
                filename: row.get(5)?,
                size_bytes: row.get(6)?,
                content_path: row.get(7)?,
                metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(artifacts)
}

pub fn list_artifacts_by_finding(
    conn: &Connection,
    finding_id: &str,
) -> Result<Vec<Artifact>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, finding_id, type, mime_type, filename, size_bytes,
         content_path, metadata, created_at
         FROM artifacts WHERE finding_id = ?1 ORDER BY created_at",
    )?;
    let artifacts = stmt
        .query_map(rusqlite::params![finding_id], |row| {
            let metadata_str: String = row.get(8)?;
            Ok(Artifact {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                finding_id: row.get(2)?,
                artifact_type: row.get(3)?,
                mime_type: row.get(4)?,
                filename: row.get(5)?,
                size_bytes: row.get(6)?,
                content_path: row.get(7)?,
                metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(artifacts)
}
