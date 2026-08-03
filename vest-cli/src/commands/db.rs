use std::path::{Path, PathBuf};
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

/// Convert a DB path to the UTF-8 string rusqlite expects.
/// Never falls back to `:memory:` — non-UTF8 paths are a hard error (STOR-2).
pub fn db_path_as_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("database path is not valid UTF-8: {}", path.display()))
}

pub fn open_pool() -> Result<ConnectionPool, Box<dyn std::error::Error>> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let path_str = db_path_as_str(&path)?;
    let pool = ConnectionPool::new(path_str)?;
    schema::run_migrations(pool.conn())?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn utf8_path_accepted() {
        let path = PathBuf::from("/tmp/vest-test.db");
        assert_eq!(db_path_as_str(&path).unwrap(), "/tmp/vest-test.db");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_rejected_not_memory() {
        use std::os::unix::ffi::OsStringExt;
        let bad = PathBuf::from(OsString::from_vec(vec![
            0xff, 0xfe, b'/', b'x', b'.', b'd', b'b',
        ]));
        let err = db_path_as_str(&bad).unwrap_err();
        assert!(
            err.contains("not valid UTF-8"),
            "expected UTF-8 error, got: {err}"
        );
        assert!(
            !err.contains(":memory:"),
            "must not mention or fall back to :memory:"
        );
    }
}
