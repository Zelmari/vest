use rusqlite::Connection;
use vest_core::types::AgentAction;

use crate::error::StorageError;

pub fn insert_agent_action(conn: &Connection, action: &AgentAction) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO agent_actions (id, scan_id, sequence, agent_role, action_type, action_data, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            action.id,
            action.scan_id,
            action.sequence,
            action.agent_role,
            action.action_type.to_string(),
            serde_json::to_string(&action.action_data)?,
            action.timestamp.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_agent_action(conn: &Connection, id: &str) -> Result<AgentAction, StorageError> {
    conn.query_row(
        "SELECT id, scan_id, sequence, agent_role, action_type, action_data, timestamp
         FROM agent_actions WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            let action_data_str: String = row.get(5)?;
            Ok(AgentAction {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                sequence: row.get(2)?,
                agent_role: row.get(3)?,
                action_type: row
                    .get::<_, String>(4)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidColumnName("action_type".into()))?,
                action_data: serde_json::from_str(&action_data_str).unwrap_or_default(),
                timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Agent action not found: {}", id))
        }
        other => StorageError::Database(other),
    })
}

pub fn list_agent_actions_by_scan(
    conn: &Connection,
    scan_id: &str,
) -> Result<Vec<AgentAction>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, sequence, agent_role, action_type, action_data, timestamp
         FROM agent_actions WHERE scan_id = ?1 ORDER BY sequence",
    )?;
    let actions = stmt
        .query_map(rusqlite::params![scan_id], |row| {
            let action_data_str: String = row.get(5)?;
            Ok(AgentAction {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                sequence: row.get(2)?,
                agent_role: row.get(3)?,
                action_type: row
                    .get::<_, String>(4)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidColumnName("action_type".into()))?,
                action_data: serde_json::from_str(&action_data_str).unwrap_or_default(),
                timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(actions)
}
