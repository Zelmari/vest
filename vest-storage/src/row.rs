//! Shared row-mapping helpers: fail closed on corrupt datetimes / JSON.

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;

/// Parse an RFC3339 timestamp stored as TEXT into UTC.
pub(crate) fn parse_datetime(s: &str, col: usize) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
        })
}

/// Parse optional RFC3339 TEXT into UTC (None stays None).
pub(crate) fn parse_optional_datetime(
    s: Option<String>,
    col: usize,
) -> rusqlite::Result<Option<DateTime<Utc>>> {
    s.map(|v| parse_datetime(&v, col)).transpose()
}

/// Deserialize JSON TEXT; corrupt payloads become a conversion error (no silent default).
pub(crate) fn parse_json<T: DeserializeOwned>(s: &str, col: usize) -> rusqlite::Result<T> {
    serde_json::from_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Deserialize optional JSON TEXT.
pub(crate) fn parse_optional_json<T: DeserializeOwned>(
    s: Option<String>,
    col: usize,
) -> rusqlite::Result<Option<T>> {
    s.map(|v| parse_json(&v, col)).transpose()
}

/// Treat zero rows affected as NotFound for UPDATE paths.
pub(crate) fn require_rows_affected(
    rows: usize,
    entity: &str,
    id: &str,
) -> Result<(), crate::error::StorageError> {
    if rows == 0 {
        Err(crate::error::StorageError::NotFound(format!(
            "{entity} not found: {id}"
        )))
    } else {
        Ok(())
    }
}
