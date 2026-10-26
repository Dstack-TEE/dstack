// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
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
//!
//! The atomic replace itself is delegated to the `safe-write` crate, which the
//! rest of the workspace already uses. The two concerns stay separate:
//! `safe-write` makes a single write atomic and durable, while
//! [`lock_exclusive`] is what serializes a *read*-modify-write so two processes
//! cannot each publish a complete file built from the same stale read.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// `path` with `suffix` appended to its full name (not replacing the extension,
/// so `a/b.json` + `.lock` → `a/b.json.lock`, a sibling in the same directory).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// atomically replace `path`'s contents: write a uniquely named temp file in
/// the same directory, fsync it, rename it over the target, then fsync the
/// directory. A reader (or a crash) sees either the old file or the new one,
/// never a fragment, and the rename is durable across a power loss.
///
/// Concurrent writers to the same path all succeed and each publishes its
/// complete content; the winner is whoever renames last. That is *not* a
/// substitute for [`lock_exclusive`] when the write is part of a
/// read-modify-write — see the module docs.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    safe_write::safe_write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// like [`write_atomic`], but the file is created with `mode` (Unix permission
/// bits) *before* any content is written, so a secret never exists on disk with
/// broader-than-intended permissions — not even transiently between the rename
/// and a follow-up `chmod`. Use for credential files (`0o600`).
///
/// `mode` is subject to the process umask, matching
/// [`std::os::unix::fs::OpenOptionsExt::mode`], so the result is never wider
/// than requested. On non-Unix platforms `mode` is ignored, as before.
pub fn write_atomic_mode(path: &Path, contents: &str, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        safe_write::safe_write_with_mode(path, contents, mode)
            .with_context(|| format!("writing {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        write_atomic(path, contents)
    }
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

    /// every entry in `dir`, so "no temp file left behind" can be asserted
    /// without knowing the temp file's name.
    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn atomic_write_replaces_contents() {
        let dir = std::env::temp_dir().join(format!("dstack-fsutil-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.json");
        write_atomic(&p, "one").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one");
        write_atomic(&p, "two").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
        // no temp file left behind, whatever it was called.
        assert_eq!(entries(&dir), vec!["x.json".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two writers racing on one path must both succeed, and the result must be
    /// exactly one of them — not a mixture, and not a spurious failure. The
    /// previous hand-rolled implementation used a fixed `<path>.tmp`, so
    /// writers truncated each other's temp file and 3 in 4 writes failed.
    #[test]
    fn concurrent_writers_do_not_clobber_each_other() {
        const LEN: usize = 256 * 1024;
        let dir = std::env::temp_dir().join(format!("dstack-fsrace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state.json");

        for _ in 0..10 {
            std::thread::scope(|s| {
                for c in ['a', 'b', 'c', 'd'] {
                    let p = &p;
                    s.spawn(move || {
                        let body: String = std::iter::repeat_n(c, LEN).collect();
                        write_atomic(p, &body).expect("concurrent write must not fail");
                    });
                }
            });
            let got = std::fs::read_to_string(&p).unwrap();
            assert_eq!(got.len(), LEN, "torn write: wrong length");
            let distinct: std::collections::BTreeSet<char> = got.chars().collect();
            assert_eq!(distinct.len(), 1, "torn write: mixed two writers' content");
        }
        assert_eq!(entries(&dir), vec!["state.json".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rewriting a credential file through the plain helper must not widen its
    /// permissions. The previous implementation reset them to `0o666 & !umask`.
    #[cfg(unix)]
    #[test]
    fn rewrite_preserves_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dstack-fsperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("token");
        write_atomic_mode(&p, "secret", 0o600).unwrap();
        write_atomic(&p, "rotated").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewrite widened a credential file to {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_mode_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dstack-fsmode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("token");
        write_atomic_mode(&p, "secret", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "secret");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credential file must be 0600, got {mode:o}");
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
