use crate::error::StorageError;
use rusqlite::Connection;

pub struct ConnectionPool {
    conn: Connection,
}

impl ConnectionPool {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}
