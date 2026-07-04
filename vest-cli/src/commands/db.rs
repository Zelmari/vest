use std::path::PathBuf;
use vest_storage::{schema, ConnectionPool};

pub fn db_path() -> PathBuf {
    if let Ok(path) = std::env::var("VEST_DB_PATH") {
        return PathBuf::from(path);
    }

    if let Ok(home) = std::env::var("VEST_HOME") {
        return PathBuf::from(home).join("vest.db");
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vest").join("vest.db")
}

pub fn open_pool() -> Result<ConnectionPool, Box<dyn std::error::Error>> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pool = ConnectionPool::new(path.to_str().unwrap_or(":memory:"))?;
    schema::run_migrations(pool.conn())?;
    Ok(pool)
}
