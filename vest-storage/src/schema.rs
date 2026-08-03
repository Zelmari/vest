use crate::error::StorageError;
use rusqlite::Connection;

/// Schema for Vest storage.
///
/// Note: findings keep SQLite column `cvss_score` for compatibility; Rust maps it
/// to [`vest_core::types::Finding::severity_score_estimate`].
pub fn run_migrations(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS targets (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL,
            path        TEXT,
            url         TEXT,
            pid         INTEGER,
            host        TEXT,
            metadata    TEXT NOT NULL DEFAULT '{}',
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id              TEXT PRIMARY KEY,
            target_id       TEXT NOT NULL REFERENCES targets(id),
            mode            TEXT NOT NULL,
            config          TEXT NOT NULL,
            status          TEXT NOT NULL,
            started_at      TEXT,
            completed_at    TEXT,
            duration_ms     INTEGER,
            agent_model     TEXT,
            total_findings  INTEGER DEFAULT 0,
            critical_count  INTEGER DEFAULT 0,
            high_count      INTEGER DEFAULT 0,
            medium_count    INTEGER DEFAULT 0,
            low_count       INTEGER DEFAULT 0,
            info_count      INTEGER DEFAULT 0,
            metadata        TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id                  TEXT PRIMARY KEY,
            scan_id             TEXT NOT NULL REFERENCES scans(id),
            target_id           TEXT NOT NULL REFERENCES targets(id),
            title               TEXT NOT NULL,
            description         TEXT NOT NULL,
            vulnerability_class TEXT NOT NULL,
            severity            TEXT NOT NULL,
            confidence          REAL NOT NULL,
            status              TEXT NOT NULL DEFAULT 'open',
            cvss_score          REAL,
            cve_id              TEXT,
            cwe_id              TEXT,
            evidence            TEXT NOT NULL,
            poc                 TEXT,
            remediation         TEXT,
            location            TEXT NOT NULL,
            false_positive_history TEXT,
            tags                TEXT NOT NULL DEFAULT '[]',
            metadata            TEXT NOT NULL DEFAULT '{}',
            discovered_at       TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            file_path           TEXT GENERATED ALWAYS AS (json_extract(location, '$.file')) VIRTUAL,
            url                 TEXT GENERATED ALWAYS AS (json_extract(location, '$.url')) VIRTUAL,
            memory_address      TEXT GENERATED ALWAYS AS (json_extract(location, '$.address')) VIRTUAL
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL REFERENCES scans(id),
            finding_id      TEXT REFERENCES findings(id),
            type            TEXT NOT NULL,
            mime_type       TEXT,
            filename        TEXT NOT NULL,
            size_bytes      INTEGER,
            content         BLOB,
            content_path    TEXT,
            metadata        TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_memory (
            id              TEXT PRIMARY KEY,
            pattern_hash    TEXT NOT NULL,
            pattern_type    TEXT NOT NULL,
            target_hash     TEXT,
            description     TEXT NOT NULL,
            evidence        TEXT NOT NULL,
            confidence      REAL NOT NULL,
            occurrences     INTEGER DEFAULT 1,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_actions (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL REFERENCES scans(id),
            sequence        INTEGER NOT NULL,
            agent_role      TEXT NOT NULL,
            action_type     TEXT NOT NULL,
            action_data     TEXT NOT NULL,
            timestamp       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_scanner_checkpoints (
            scan_id         TEXT NOT NULL REFERENCES scans(id),
            scanner         TEXT NOT NULL,
            status          TEXT NOT NULL,
            completed_at    TEXT NOT NULL,
            error           TEXT,
            PRIMARY KEY (scan_id, scanner)
        );

        CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(type);
        CREATE INDEX IF NOT EXISTS idx_targets_name ON targets(name);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_vuln_class ON findings(vulnerability_class);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);
        CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_scan ON artifacts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_finding ON artifacts(finding_id);
        CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type);
        CREATE INDEX IF NOT EXISTS idx_memory_pattern ON scan_memory(pattern_hash, pattern_type, COALESCE(target_hash, ''));
        CREATE INDEX IF NOT EXISTS idx_actions_scan ON agent_actions(scan_id);
        CREATE INDEX IF NOT EXISTS idx_actions_sequence ON agent_actions(scan_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_checkpoints_scan ON scan_scanner_checkpoints(scan_id);
        ",
    )
    .map_err(|e| StorageError::Migration(format!("Failed to run migrations: {}", e)))?;

    Ok(())
}
