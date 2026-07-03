use rusqlite::Connection;
use vest_core::types::ScanMemoryEntry;

use crate::error::StorageError;

pub fn insert_memory_entry(conn: &Connection, entry: &ScanMemoryEntry) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO scan_memory (id, pattern_hash, pattern_type, target_hash, description,
         evidence, confidence, occurrences, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            entry.id,
            entry.pattern_hash,
            entry.pattern_type.to_string(),
            entry.target_hash,
            entry.description,
            serde_json::to_string(&entry.evidence)?,
            entry.confidence,
            entry.occurrences,
            entry.created_at.to_rfc3339(),
            entry.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_memory_entry(conn: &Connection, id: &str) -> Result<ScanMemoryEntry, StorageError> {
    conn.query_row(
        "SELECT id, pattern_hash, pattern_type, target_hash, description,
         evidence, confidence, occurrences, created_at, updated_at
         FROM scan_memory WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            let evidence_str: String = row.get(5)?;
            Ok(ScanMemoryEntry {
                id: row.get(0)?,
                pattern_hash: row.get(1)?,
                pattern_type: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidColumnName("pattern_type".into()))?,
                target_hash: row.get(3)?,
                description: row.get(4)?,
                evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
                confidence: row.get(6)?,
                occurrences: row.get(7)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Memory entry not found: {}", id))
        }
        other => StorageError::Database(other),
    })
}

pub fn find_memory_by_pattern(
    conn: &Connection,
    pattern_hash: &str,
) -> Result<Vec<ScanMemoryEntry>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, pattern_hash, pattern_type, target_hash, description,
         evidence, confidence, occurrences, created_at, updated_at
         FROM scan_memory WHERE pattern_hash = ?1 ORDER BY updated_at DESC",
    )?;
    let entries = stmt
        .query_map(rusqlite::params![pattern_hash], |row| {
            let evidence_str: String = row.get(5)?;
            Ok(ScanMemoryEntry {
                id: row.get(0)?,
                pattern_hash: row.get(1)?,
                pattern_type: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidColumnName("pattern_type".into()))?,
                target_hash: row.get(3)?,
                description: row.get(4)?,
                evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
                confidence: row.get(6)?,
                occurrences: row.get(7)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}
