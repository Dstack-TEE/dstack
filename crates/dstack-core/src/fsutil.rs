// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! small filesystem helpers: atomic file replace + advisory locking.
//!
//! The allowlist and the install state file are read-modify-written from more
//! than one process (`dstack run` adds an app while the webhook reads; a second
//! `dstack run` can race the first). A torn write there is not cosmetic: the
//! auth webhook fails *closed* on invalid JSON, so a half-written allowlist
//! denies keys to every app on the host. These helpers make the write atomic
//! and serialize concurrent writers.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// `path` with `suffix` appended to its full name (not replacing the extension,
/// so `a/b.json` + `.tmp` → `a/b.json.tmp`, a sibling in the same directory).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// atomically replace `path`'s contents: write a sibling temp file, fsync it,
/// rename it over the target, then fsync the directory. A reader (or a crash)
/// sees either the old file or the new one, never a fragment, and the rename is
/// durable across a power loss. `tmp` and `path` are in the same directory so
/// the rename is atomic.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let tmp = sibling(path, ".tmp");
    let mut f =
        File::create(&tmp).with_context(|| format!("creating temp file {}", tmp.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all()
        .with_context(|| format!("syncing {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    // fsync the containing directory so the rename itself survives a crash.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// acquire an exclusive advisory lock tied to `path` (held on a sibling
/// `.lock` file). The lock releases when the returned guard is dropped —
/// including on process exit, so a crash never leaves a stale lock. Hold it
/// around a read-modify-write of `path` to serialize concurrent processes.
#[must_use = "the lock is released when the returned guard is dropped"]
pub fn lock_exclusive(path: &Path) -> Result<File> {
    let lock_path = sibling(path, ".lock");
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening lock {}", lock_path.display()))?;
    rustix::fs::flock(&f, rustix::fs::FlockOperation::LockExclusive)
        .with_context(|| format!("locking {}", lock_path.display()))?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_contents() {
        let dir = std::env::temp_dir().join(format!("dstack-fsutil-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.json");
        write_atomic(&p, "one").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one");
        write_atomic(&p, "two").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
        // no temp file left behind.
        assert!(!sibling(&p, ".tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_is_reentrant_within_process_after_drop() {
        let dir = std::env::temp_dir().join(format!("dstack-fslock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("y.json");
        std::fs::write(&p, "{}").unwrap();
        {
            let _g = lock_exclusive(&p).unwrap();
        }
        // re-acquire after the first guard dropped.
        let _g2 = lock_exclusive(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
