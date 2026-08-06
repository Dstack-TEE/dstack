// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Logrotate-style rotation for files a live process holds open.
//!
//! Like the logrotate(8) this is modelled on, rotation works on a path and does
//! not care what the log contains or who writes it: `<path>.N-1` becomes
//! `<path>.N`, `<path>` is archived as `<path>.1`, and the oldest segment is
//! discarded.
//!
//! # The one requirement on callers
//!
//! The writer must hold the file open with `O_APPEND`.
//!
//! Rotation truncates the live file in place rather than renaming it. Renaming
//! would leave the writer appending into an unlinked inode, so its output would
//! vanish silently. Truncating keeps the writer's fd valid — but only under
//! `O_APPEND`, which forces every write to the current end of file. A writer
//! without it keeps writing at its stale offset, so the truncation punches a
//! sparse hole and the file springs straight back to its previous size. The cap
//! then never holds and every later check rotates again.
//!
//! For QEMU chardev logs that means `logappend=on`; for a process's stdout or
//! stderr, an `OpenOptions::append(true)` sink.

use std::path::{Path, PathBuf};

use fs_err as fs;
use tracing::warn;

/// Outcome of a rotation.
pub struct Rotated {
    /// Bytes removed from the live log.
    pub bytes: u64,
    /// Where those bytes were kept, or `None` if they were discarded because
    /// no backups are retained.
    pub archived: Option<PathBuf>,
}

/// Path of rotated segment `index`, `1` being the most recent.
pub fn segment_path(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

/// Empty `path` in place, keeping the writer's open fd valid.
///
/// Missing files are not an error: callers use this to guarantee a log starts
/// empty without having to care whether it exists yet.
pub fn truncate(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Err(err) = fs::write(path, b"") {
        warn!("failed to truncate {}: {err}", path.display());
    }
}

/// Rotate `path`, discarding the oldest of `max_backups` segments.
///
/// Returns `None` when there was nothing to rotate, which includes an empty or
/// missing log — rotating those would spend a segment slot on an empty file and
/// push a segment that still has content off the end.
pub fn rotate(path: &Path, max_backups: usize) -> Option<Rotated> {
    let bytes = match fs::metadata(path) {
        Ok(meta) if meta.len() > 0 => meta.len(),
        _ => return None,
    };
    if max_backups == 0 {
        truncate(path);
        return Some(Rotated {
            bytes,
            archived: None,
        });
    }

    let oldest = segment_path(path, max_backups);
    if oldest.exists() {
        if let Err(err) = fs::remove_file(&oldest) {
            warn!(
                "failed to remove oldest segment {}: {err}",
                oldest.display()
            );
            return None;
        }
    }
    for index in (1..max_backups).rev() {
        let from = segment_path(path, index);
        if !from.exists() {
            continue;
        }
        if let Err(err) = fs::rename(&from, segment_path(path, index + 1)) {
            warn!("failed to shift segment {}: {err}", from.display());
            return None;
        }
    }

    // Copy rather than rename: the writer holds an open fd on the live log.
    let archived = segment_path(path, 1);
    if let Err(err) = fs::copy(path, &archived) {
        warn!("failed to archive {}: {err}", path.display());
        return None;
    }
    truncate(path);
    Some(Rotated {
        bytes,
        archived: Some(archived),
    })
}

/// Rotate `path` if it has grown past `max_bytes`. `max_bytes == 0` disables
/// rotation entirely.
pub fn rotate_if_oversized(path: &Path, max_bytes: u64, max_backups: usize) -> Option<Rotated> {
    if max_bytes == 0 {
        return None;
    }
    match fs::metadata(path) {
        Ok(meta) if meta.len() > max_bytes => {}
        _ => return None,
    }
    rotate(path, max_backups)
}

/// Record in the freshly emptied log where its previous content went.
///
/// A reader that only ever sees the live file — as the VMM log API does — would
/// otherwise find it empty with no explanation. This does not make the segments
/// readable; it makes their absence self-explanatory.
pub fn append_rotation_note(path: &Path, rotated: &Rotated) {
    use std::io::Write;

    let Ok(mut file) = fs::OpenOptions::new().append(true).open(path) else {
        return;
    };
    let timestamp = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    let bytes = rotated.bytes;
    let _ = match &rotated.archived {
        Some(archived) => {
            let name = archived
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| archived.display().to_string());
            writeln!(
                file,
                "\n===== rotated {bytes} bytes to {name} @ {timestamp} =====\n"
            )
        }
        None => writeln!(
            file,
            "\n===== discarded {bytes} bytes @ {timestamp} =====\n"
        ),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_path_appends_the_index_to_the_whole_name() {
        // Suffixing the full name rather than replacing an extension keeps
        // `serial.log.1` readable and works for files with no extension.
        assert_eq!(
            segment_path(Path::new("/run/serial.log"), 1).to_str(),
            Some("/run/serial.log.1")
        );
        assert_eq!(
            segment_path(Path::new("/run/stdout"), 12).to_str(),
            Some("/run/stdout.12")
        );
    }

    #[test]
    fn rotate_shifts_and_drops_the_oldest() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("app.log");

        for marker in ["first", "second", "third", "fourth"] {
            fs::write(&log, format!("{marker}\n"))?;
            assert!(rotate(&log, 3).is_some());
        }

        assert_eq!(fs::read(segment_path(&log, 1))?, b"fourth\n");
        assert_eq!(fs::read(segment_path(&log, 2))?, b"third\n");
        assert_eq!(fs::read(segment_path(&log, 3))?, b"second\n");
        assert!(!segment_path(&log, 4).exists());
        Ok(())
    }

    #[test]
    fn rotate_keeps_the_live_file_inode() -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("app.log");

        fs::write(&log, b"before\n")?;
        let before = fs::metadata(&log)?.ino();
        rotate(&log, 3);

        // Renaming the live file would leave the writer appending into an
        // unlinked inode, losing every later line without an error.
        assert_eq!(fs::metadata(&log)?.ino(), before);
        assert_eq!(fs::read(&log)?.len(), 0);
        Ok(())
    }

    #[test]
    fn rotate_skips_an_empty_or_missing_log() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("app.log");

        // Missing: must not create anything.
        assert!(rotate(&log, 3).is_none());
        assert!(!segment_path(&log, 1).exists());

        // Empty: spending a slot here would push a segment that still has
        // content off the end.
        fs::write(&log, b"")?;
        assert!(rotate(&log, 3).is_none());
        assert!(!segment_path(&log, 1).exists());
        Ok(())
    }

    #[test]
    fn rotate_without_backups_discards_instead_of_archiving() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("app.log");

        fs::write(&log, b"discarded\n")?;
        let rotated = rotate(&log, 0).expect("rotated");

        assert_eq!(rotated.bytes, 10);
        assert!(rotated.archived.is_none());
        assert_eq!(fs::read(&log)?.len(), 0);
        assert!(!segment_path(&log, 1).exists());
        Ok(())
    }

    #[test]
    fn rotate_if_oversized_respects_the_cap() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("app.log");

        fs::write(&log, vec![b'x'; 100])?;
        assert!(rotate_if_oversized(&log, 4096, 3).is_none());
        assert_eq!(fs::read(&log)?.len(), 100);

        fs::write(&log, vec![b'x'; 8192])?;
        assert!(rotate_if_oversized(&log, 4096, 3).is_some());
        assert_eq!(fs::read(&log)?.len(), 0);
        assert_eq!(fs::read(segment_path(&log, 1))?.len(), 8192);

        // A zero cap disables rotation entirely.
        fs::write(&log, vec![b'x'; 8192])?;
        assert!(rotate_if_oversized(&log, 0, 3).is_none());
        assert_eq!(fs::read(&log)?.len(), 8192);
        Ok(())
    }

    #[test]
    fn truncate_is_unconditional_and_tolerates_a_missing_file() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("app.log");

        truncate(&log);
        assert!(!log.exists(), "truncate must not create the file");

        fs::write(&log, b"stale output\n")?;
        truncate(&log);
        assert_eq!(fs::read(&log)?.len(), 0);
        Ok(())
    }

    #[test]
    fn rotation_note_says_where_the_output_went() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("serial.log");

        fs::write(&log, vec![b'x'; 8192])?;
        let rotated = rotate(&log, 3).expect("rotated");
        append_rotation_note(&log, &rotated);

        let note = String::from_utf8_lossy(&fs::read(&log)?).into_owned();
        assert!(
            note.contains("rotated 8192 bytes to serial.log.1"),
            "{note:?}"
        );
        Ok(())
    }

    #[test]
    fn rotation_note_does_not_claim_an_archive_that_was_discarded() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("serial.log");

        fs::write(&log, vec![b'x'; 8192])?;
        let rotated = rotate(&log, 0).expect("rotated");
        append_rotation_note(&log, &rotated);

        let note = String::from_utf8_lossy(&fs::read(&log)?).into_owned();
        assert!(note.contains("discarded 8192 bytes"), "{note:?}");
        assert!(!note.contains("serial.log.1"), "{note:?}");
        Ok(())
    }
}
