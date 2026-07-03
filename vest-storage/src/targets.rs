use rusqlite::Connection;
use vest_core::types::{Target, TargetType};

use crate::error::StorageError;

pub fn insert_target(conn: &Connection, target: &Target) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO targets (id, name, type, path, url, pid, host, metadata, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            target.id,
            target.name,
            target.target_type.to_string(),
            target.path,
            target.url_str,
            target.pid,
            target.host,
            serde_json::to_string(&target.metadata)?,
            target.created_at.to_rfc3339(),
            target.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_target(conn: &Connection, id: &str) -> Result<Target, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, type, path, url, pid, host, metadata, created_at, updated_at
         FROM targets WHERE id = ?1",
    )?;
    let target = stmt.query_row(rusqlite::params![id], |row| {
        let metadata_str: String = row.get(7)?;
        Ok(Target {
            id: row.get(0)?,
            name: row.get(1)?,
            target_type: row
                .get::<_, String>(2)?
                .parse()
                .map_err(|_| rusqlite::Error::InvalidColumnName("2".into()))?,
            path: row.get(3)?,
            url_str: row.get(4)?,
            pid: row.get(5)?,
            host: row.get(6)?,
            metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                .unwrap()
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                .unwrap()
                .with_timezone(&chrono::Utc),
        })
    })?;
    Ok(target)
}

pub fn list_targets(conn: &Connection) -> Result<Vec<Target>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, type, path, url, pid, host, metadata, created_at, updated_at
         FROM targets ORDER BY created_at DESC",
    )?;
    let targets = stmt
        .query_map([], |row| {
            let metadata_str: String = row.get(7)?;
            Ok(Target {
                id: row.get(0)?,
                name: row.get(1)?,
                target_type: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidColumnName("2".into()))?,
                path: row.get(3)?,
                url_str: row.get(4)?,
                pid: row.get(5)?,
                host: row.get(6)?,
                metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(targets)
}

pub fn list_targets_by_type(
    conn: &Connection,
    target_type: &TargetType,
) -> Result<Vec<Target>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, type, path, url, pid, host, metadata, created_at, updated_at
         FROM targets WHERE type = ?1 ORDER BY created_at DESC",
    )?;
    let targets = stmt
        .query_map(rusqlite::params![target_type.to_string()], |row| {
            let metadata_str: String = row.get(7)?;
            Ok(Target {
                id: row.get(0)?,
                name: row.get(1)?,
                target_type: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidColumnName("2".into()))?,
                path: row.get(3)?,
                url_str: row.get(4)?,
                pid: row.get(5)?,
                host: row.get(6)?,
                metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(targets)
}

pub fn update_target(conn: &Connection, target: &Target) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE targets SET name = ?1, type = ?2, path = ?3, url = ?4, pid = ?5, host = ?6,
         metadata = ?7, updated_at = ?8 WHERE id = ?9",
        rusqlite::params![
            target.name,
            target.target_type.to_string(),
            target.path,
            target.url_str,
            target.pid,
            target.host,
            serde_json::to_string(&target.metadata)?,
            target.updated_at.to_rfc3339(),
            target.id,
        ],
    )?;
    Ok(())
}

pub fn delete_target(conn: &Connection, id: &str) -> Result<(), StorageError> {
    conn.execute("DELETE FROM targets WHERE id = ?1", rusqlite::params![id])?;
    Ok(())
}
