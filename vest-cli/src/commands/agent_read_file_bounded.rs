//! K8 regression: agent `read_file` must cap bytes via limited reader and
//! never absorb an oversized on-disk file into memory.

use super::{agent_read_file, AGENT_READ_FILE_MAX_BYTES};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use vest_agent::{ApprovedFilesystemScope, ApprovedNetworkScope, ExecutionSession};

fn tempfile_root(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("vest-k8-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn session_for_dir(dir: &std::path::Path) -> Arc<ExecutionSession> {
    let fs = ApprovedFilesystemScope::new([dir.to_path_buf()]).unwrap();
    ExecutionSession::new(fs, ApprovedNetworkScope::empty(), false).into_arc()
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_read_file_oversized_returns_at_most_cap() {
    let dir = tempfile_root("oversized");
    let path = dir.join("big.bin");
    // A few MB on disk — far above the read cap — without intending OOM.
    const FILE_BYTES: usize = 3 * 1024 * 1024;
    {
        let mut f = std::fs::File::create(&path).unwrap();
        let chunk = vec![b'A'; 64 * 1024];
        let mut written = 0usize;
        while written < FILE_BYTES {
            let n = (FILE_BYTES - written).min(chunk.len());
            f.write_all(&chunk[..n]).unwrap();
            written += n;
        }
        f.flush().unwrap();
    }

    let on_disk = std::fs::metadata(&path).unwrap().len();
    assert!(
        on_disk as usize >= FILE_BYTES,
        "fixture must be oversized vs cap"
    );
    assert!(on_disk > AGENT_READ_FILE_MAX_BYTES);

    let session = session_for_dir(&dir);
    let out = agent_read_file(&session, path.to_str().unwrap()).unwrap();

    let content = out["content"].as_str().expect("content string");
    let bytes_read = out["bytes_read"].as_u64().expect("bytes_read");
    let size = out["size"].as_u64().expect("size");
    let truncated = out["truncated"].as_bool().expect("truncated");

    assert_eq!(size, on_disk, "size reports metadata len, not absorb");
    assert!(
        bytes_read <= AGENT_READ_FILE_MAX_BYTES,
        "bytes_read {bytes_read} exceeds cap {AGENT_READ_FILE_MAX_BYTES}"
    );
    assert!(
        content.len() as u64 <= AGENT_READ_FILE_MAX_BYTES,
        "content len {} exceeds cap",
        content.len()
    );
    assert_eq!(bytes_read, AGENT_READ_FILE_MAX_BYTES);
    assert_eq!(content.len() as u64, AGENT_READ_FILE_MAX_BYTES);
    assert!(truncated);
    assert!(content.bytes().all(|b| b == b'A'));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_read_file_small_file_untruncated() {
    let dir = tempfile_root("small");
    let path = dir.join("small.txt");
    std::fs::write(&path, b"hello-read-file").unwrap();

    let session = session_for_dir(&dir);
    let out = agent_read_file(&session, path.to_str().unwrap()).unwrap();

    assert_eq!(out["content"], "hello-read-file");
    assert_eq!(out["bytes_read"], 15);
    assert_eq!(out["size"], 15);
    assert_eq!(out["truncated"], false);

    let _ = std::fs::remove_dir_all(&dir);
}
