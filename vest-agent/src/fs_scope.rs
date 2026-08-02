//! Capability-based filesystem path resolution.
//!
//! Paths are resolved with component/canonical checks — never string-prefix alone.
//! Default symlink policy: reject symlinks for agent reads (do not follow out of root).

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Authorised filesystem roots for agent/scanner local reads.
#[derive(Debug, Clone, Default)]
pub struct ApprovedFilesystemScope {
    roots: Vec<PathBuf>,
    /// Test-only escape hatch: accept any path that resolves.
    unrestricted: bool,
}

#[derive(Debug)]
pub enum FsScopeError {
    EmptyPath,
    Escape,
    OutsideRoot,
    SymlinkRejected(String),
    SymlinkLoop,
    NoRoots,
    Io(io::Error),
}

impl std::fmt::Display for FsScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsScopeError::EmptyPath => write!(f, "path is empty"),
            FsScopeError::Escape => write!(f, "path escapes authorised filesystem scope"),
            FsScopeError::OutsideRoot => write!(f, "path is outside authorised roots"),
            FsScopeError::SymlinkRejected(p) => {
                write!(f, "symlink rejected by default do-not-follow policy: {p}")
            }
            FsScopeError::SymlinkLoop => write!(f, "symlink loop detected while resolving path"),
            FsScopeError::NoRoots => write!(f, "no authorised filesystem roots configured"),
            FsScopeError::Io(e) => write!(f, "IO error resolving path: {e}"),
        }
    }
}

impl std::error::Error for FsScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FsScopeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FsScopeError {
    fn from(e: io::Error) -> Self {
        FsScopeError::Io(e)
    }
}

impl ApprovedFilesystemScope {
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Result<Self, FsScopeError> {
        let mut canonical_roots = Vec::new();
        for root in roots {
            let canon = fs::canonicalize(&root).unwrap_or(root);
            canonical_roots.push(canon);
        }
        Ok(Self {
            roots: canonical_roots,
            unrestricted: false,
        })
    }

    pub fn empty() -> Self {
        Self {
            roots: Vec::new(),
            unrestricted: false,
        }
    }

    /// Test-only: do not enforce root membership (policy may still evaluate effects).
    pub fn unrestricted() -> Self {
        Self {
            roots: Vec::new(),
            unrestricted: true,
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn contains_canonical(&self, path: &Path) -> bool {
        if self.unrestricted {
            return true;
        }
        self.roots.iter().any(|root| path_within_root(path, root))
    }
}

/// Resolve a user-supplied path for a read under `root_scope`.
///
/// Existing paths are canonicalised. Non-existent paths canonicalise the nearest
/// existing parent and join the remainder. Symlinks **under authorised roots**
/// are rejected by default (system path prefixes outside the root are not walked
/// for symlink rejection; roots themselves are stored canonicalised).
pub fn resolve_read_path(
    root_scope: &ApprovedFilesystemScope,
    user_path: impl AsRef<Path>,
) -> Result<PathBuf, FsScopeError> {
    let user_path = user_path.as_ref();
    if user_path.as_os_str().is_empty() {
        return Err(FsScopeError::EmptyPath);
    }

    if root_scope.roots.is_empty() && !root_scope.unrestricted {
        return Err(FsScopeError::NoRoots);
    }

    let candidate = if user_path.is_absolute() {
        user_path.to_path_buf()
    } else if let Some(first_root) = root_scope.roots.first() {
        first_root.join(user_path)
    } else {
        std::env::current_dir()?.join(user_path)
    };

    let lexical = lexical_normalize(&candidate);

    if root_scope.unrestricted {
        return finalise_existing_or_parent(&lexical);
    }

    // Match against each authorised (already-canonical) root.
    let mut last_err = FsScopeError::OutsideRoot;
    for root in &root_scope.roots {
        match resolve_under_root(root, &lexical) {
            Ok(p) => return Ok(p),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

const MAX_SYMLINK_ITERATIONS: u32 = 64;

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => resolved.push(p.as_os_str()),
            Component::RootDir => resolved.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    resolved.push(Component::RootDir.as_os_str());
                }
            }
            Component::Normal(name) => resolved.push(name),
        }
    }
    resolved
}

fn resolve_under_root(root: &Path, lexical: &Path) -> Result<PathBuf, FsScopeError> {
    let abs_lexical = if lexical.is_absolute() {
        lexical_normalize(lexical)
    } else {
        lexical_normalize(&root.join(lexical))
    };

    let relative = match relative_under_root(root, &abs_lexical)? {
        Some(rel) => rel,
        None => return Err(FsScopeError::OutsideRoot),
    };

    // Walk only the suffix under the authorised root; reject symlinks there.
    // Use symlink_metadata (not Path::exists) so symlink loops are visible.
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        cursor.push(name);
        if let Ok(meta) = fs::symlink_metadata(&cursor) {
            if meta.file_type().is_symlink() {
                detect_symlink_loop(&cursor)?;
                return Err(FsScopeError::SymlinkRejected(cursor.display().to_string()));
            }
        }
    }

    finalise_existing_or_parent(&cursor).and_then(|final_path| {
        if path_within_root(&final_path, root) {
            Ok(final_path)
        } else {
            Err(FsScopeError::OutsideRoot)
        }
    })
}

/// Map an absolute path into a root-relative path, rebasing through canonical
/// ancestors so `/var/...` matches a `/private/var/...` root on macOS.
/// Returns `None` if the path is outside the root. Symlinks under the root are
/// reported as `relative` still (caller rejects them while walking).
fn relative_under_root(root: &Path, abs_path: &Path) -> Result<Option<PathBuf>, FsScopeError> {
    if let Ok(rel) = abs_path.strip_prefix(root) {
        return Ok(Some(rel.to_path_buf()));
    }

    // Walk up to an existing ancestor; never canonicalize a symlink leaf (that
    // would follow an escape link). Instead canonicalize only non-symlink dirs.
    let mut probe = abs_path.to_path_buf();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();

    loop {
        if probe.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = fs::symlink_metadata(&probe) {
            if meta.file_type().is_symlink() {
                // Rebase via parent; keep the symlink name in the suffix so the
                // root walk observes and rejects it.
                if let Some(parent) = probe.parent() {
                    if let Ok(parent_meta) = fs::symlink_metadata(parent) {
                        if parent_meta.file_type().is_symlink() {
                            detect_symlink_loop(parent)?;
                        } else {
                            let parent_canon = fs::canonicalize(parent)?;
                            if path_within_root(&parent_canon, root) || parent_canon == root {
                                let mut rel = parent_canon
                                    .strip_prefix(root)
                                    .unwrap_or(Path::new(""))
                                    .to_path_buf();
                                if let Some(name) = probe.file_name() {
                                    rel.push(name);
                                }
                                for part in suffix.iter().rev() {
                                    rel.push(part);
                                }
                                return Ok(Some(rel));
                            }
                        }
                    }
                }
                return Ok(None);
            }

            let canon = fs::canonicalize(&probe)?;
            let mut full = canon;
            for part in suffix.iter().rev() {
                full.push(part);
            }
            if path_within_root(&full, root) {
                return Ok(Some(
                    full.strip_prefix(root)
                        .unwrap_or(Path::new(""))
                        .to_path_buf(),
                ));
            }
            return Ok(None);
        }

        if let Some(name) = probe.file_name() {
            suffix.push(name.to_os_string());
        }
        match probe.parent() {
            Some(p) if p != probe.as_path() => probe = p.to_path_buf(),
            _ => break,
        }
    }

    Ok(None)
}

fn detect_symlink_loop(start: &Path) -> Result<(), FsScopeError> {
    let mut seen = 0u32;
    let mut current = start.to_path_buf();
    while fs::symlink_metadata(&current)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        seen += 1;
        if seen > MAX_SYMLINK_ITERATIONS {
            return Err(FsScopeError::SymlinkLoop);
        }
        let target = fs::read_link(&current)?;
        current = if target.is_relative() {
            current.parent().unwrap_or(Path::new("/")).join(target)
        } else {
            target
        };
    }
    Ok(())
}

fn finalise_existing_or_parent(path: &Path) -> Result<PathBuf, FsScopeError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            detect_symlink_loop(path)?;
            return Err(FsScopeError::SymlinkRejected(path.display().to_string()));
        }
        return Ok(fs::canonicalize(path)?);
    }

    let mut parent = path.parent().unwrap_or(Path::new("/")).to_path_buf();
    let mut remainder = vec![path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default()];

    while !parent.as_os_str().is_empty() && !parent.exists() {
        if let Some(name) = parent.file_name() {
            remainder.push(name.to_os_string());
        }
        let next = parent
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"));
        if next == parent {
            break;
        }
        parent = next;
    }

    if parent.exists() {
        // Parent may sit outside the root (system dirs); canonicalize is OK here
        // because membership is re-checked by the caller for scoped resolves.
        let mut canon = fs::canonicalize(&parent)?;
        for part in remainder.into_iter().rev() {
            if !part.is_empty() {
                canon.push(part);
            }
        }
        return Ok(canon);
    }

    Ok(path.to_path_buf())
}

/// True if `path` is equal to `root` or a proper descendant (component-wise).
/// Rejects prefix collisions such as `/tmp/root` vs `/tmp/root-evil`.
pub fn path_within_root(path: &Path, root: &Path) -> bool {
    let path_comps: Vec<_> = path.components().collect();
    let root_comps: Vec<_> = root.components().collect();
    if path_comps.len() < root_comps.len() {
        return false;
    }
    path_comps
        .iter()
        .zip(root_comps.iter())
        .all(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vest-fs-scope-{ts}-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn temp_root() -> (PathBuf, ApprovedFilesystemScope) {
        let dir = unique_temp_dir();
        let scope = ApprovedFilesystemScope::new([dir.clone()]).unwrap();
        (dir, scope)
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn in_root_ok() {
        let (dir, scope) = temp_root();
        let file = dir.join("hello.txt");
        File::create(&file).unwrap();
        let resolved = resolve_read_path(&scope, &file).unwrap();
        assert_eq!(resolved, fs::canonicalize(&file).unwrap());
        cleanup(&dir);
    }

    #[test]
    fn parent_escape_fails() {
        let (dir, scope) = temp_root();
        let outside = dir.join("..").join("escape-target");
        let result = resolve_read_path(&scope, &outside);
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[test]
    fn absolute_outside_fails() {
        let (dir, scope) = temp_root();
        let result = resolve_read_path(&scope, "/etc/passwd");
        assert!(matches!(
            result,
            Err(FsScopeError::OutsideRoot) | Err(FsScopeError::Escape)
        ));
        cleanup(&dir);
    }

    #[test]
    fn prefix_collision_fails() {
        let base = unique_temp_dir();
        let root = base.join("root");
        let evil = base.join("root-evil");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&evil).unwrap();
        File::create(evil.join("secret.txt")).unwrap();

        let scope = ApprovedFilesystemScope::new([root]).unwrap();
        let result = resolve_read_path(&scope, evil.join("secret.txt"));
        assert!(result.is_err());
        cleanup(&base);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_outside_fails() {
        let (dir, scope) = temp_root();
        let outside = unique_temp_dir();
        let outside_file = outside.join("secret.txt");
        File::create(&outside_file).unwrap();
        let link = dir.join("link.txt");
        symlink(&outside_file, &link).unwrap();
        let result = resolve_read_path(&scope, &link);
        assert!(matches!(result, Err(FsScopeError::SymlinkRejected(_))));
        cleanup(&dir);
        cleanup(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_dir_outside_fails() {
        let (dir, scope) = temp_root();
        let outside = unique_temp_dir();
        File::create(outside.join("a.txt")).unwrap();
        let link_dir = dir.join("outdir");
        symlink(&outside, &link_dir).unwrap();
        let result = resolve_read_path(&scope, link_dir.join("a.txt"));
        assert!(result.is_err());
        cleanup(&dir);
        cleanup(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loop_no_hang() {
        let (dir, scope) = temp_root();
        let a = dir.join("a");
        let b = dir.join("b");
        symlink(&b, &a).unwrap();
        symlink(&a, &b).unwrap();
        let result = resolve_read_path(&scope, &a);
        assert!(
            matches!(
                result,
                Err(FsScopeError::SymlinkRejected(_)) | Err(FsScopeError::SymlinkLoop)
            ),
            "got {result:?}"
        );
        cleanup(&dir);
    }

    #[test]
    fn nested_in_root_ok() {
        let (dir, scope) = temp_root();
        let nested = dir.join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("c.txt");
        File::create(&file).unwrap();
        assert!(resolve_read_path(&scope, &file).is_ok());
        cleanup(&dir);
    }

    #[test]
    fn unicode_ok() {
        let (dir, scope) = temp_root();
        let file = dir.join("файл.txt");
        File::create(&file).unwrap();
        assert!(resolve_read_path(&scope, &file).is_ok());
        cleanup(&dir);
    }

    #[test]
    fn redundant_dot_components_ok() {
        let (dir, scope) = temp_root();
        let file = dir.join("x.txt");
        File::create(&file).unwrap();
        let dotted = dir.join(".").join("x.txt");
        assert!(resolve_read_path(&scope, &dotted).is_ok());
        cleanup(&dir);
    }
}
