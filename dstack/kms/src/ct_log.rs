// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::OpenOptions,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use fs_err as fs;

const MAX_COLLISION_INDEX: usize = 4096;

#[allow(dead_code)]
pub(crate) fn iter_ct_log_files(log_dir: &Path) -> Result<impl Iterator<Item = PathBuf>> {
    let day_dirs = fs::read_dir(log_dir)?.filter_map(|entry| {
        let path = entry.ok()?.path();
        let day = path.file_name()?.to_str()?;
        (path.is_dir() && is_eight_digits(day)).then_some(path)
    });

    Ok(day_dirs.flat_map(|dir| {
        fs::read_dir(dir).into_iter().flatten().filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.is_file() && is_ct_log_filename(&path)).then_some(path)
        })
    }))
}

pub(crate) fn ct_log_write_cert(app_id: &str, cert: &str, log_dir: &str) -> Result<()> {
    let log_dir = Path::new(log_dir);
    let now = Utc::now();
    let day = now.format("%Y%d%m").to_string();
    let base_filename = format!("{}-{app_id}", now.format("%Y%d%m-%H%M%S"));
    let day_dir = log_dir.join(day);
    fs::create_dir_all(&day_dir).context("failed to create ct log dir")?;
    write_new_cert(&day_dir, &base_filename, cert.as_bytes())
}

fn write_new_cert(dir: &Path, base_filename: &str, cert: &[u8]) -> Result<()> {
    for index in 0..=MAX_COLLISION_INDEX {
        let path = dir.join(format!("{base_filename}.{index}.cert"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(cert)
                    .with_context(|| format!("failed to write ct log cert: {}", path.display()))?;
                return Ok(());
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create ct log cert: {}", path.display()));
            }
        }
    }
    bail!("ct log filename collision range exhausted for {base_filename}")
}

fn is_eight_digits(value: &str) -> bool {
    value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_ct_log_filename(path: &Path) -> bool {
    let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(stem) = filename.strip_suffix(".cert") else {
        return false;
    };
    let Some((source, index)) = stem.rsplit_once('.') else {
        return false;
    };
    let Some((timestamp, app_id)) = source.split_once('-') else {
        return false;
    };
    timestamp.len() == 15
        && timestamp.as_bytes().get(8) == Some(&b'-')
        && timestamp
            .bytes()
            .enumerate()
            .all(|(position, byte)| position == 8 || byte.is_ascii_digit())
        && !app_id.is_empty()
        && !app_id.contains('.')
        && index
            .parse::<usize>()
            .is_ok_and(|value| value <= MAX_COLLISION_INDEX)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, thread};

    use super::*;

    #[test]
    fn concurrent_writes_are_unique_and_never_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let dir = Arc::new(temp.path().to_path_buf());
        let base = "20262907-120000-app";
        let workers: Vec<_> = (0..64)
            .map(|index| {
                let dir = Arc::clone(&dir);
                thread::spawn(move || {
                    write_new_cert(&dir, base, format!("cert-{index}").as_bytes()).unwrap();
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let contents: HashSet<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect();
        assert_eq!(contents.len(), 64);
        assert!((0..64).all(|index| contents.contains(&format!("cert-{index}"))));
    }

    #[test]
    fn collision_allocation_preserves_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let base = "20262907-120000-app";
        fs::write(temp.path().join(format!("{base}.0.cert")), "original").unwrap();
        write_new_cert(temp.path(), base, b"new").unwrap();
        assert_eq!(
            fs::read_to_string(temp.path().join(format!("{base}.0.cert"))).unwrap(),
            "original"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join(format!("{base}.1.cert"))).unwrap(),
            "new"
        );
    }

    #[test]
    fn iterator_excludes_malformed_and_unrelated_entries() {
        let temp = tempfile::tempdir().unwrap();
        let valid_day = temp.path().join("20262907");
        let invalid_day = temp.path().join("not-a-day");
        fs::create_dir_all(&valid_day).unwrap();
        fs::create_dir_all(&invalid_day).unwrap();
        let valid = valid_day.join("20262907-120000-app.7.cert");
        fs::write(&valid, "valid").unwrap();
        for name in [
            "20262907-120000-app.cert",
            "20262907-120000-app.bad.cert",
            "20262907-120000-app.4097.cert",
            "bad-app.0.cert",
            "20262907-120000-app.0.txt",
        ] {
            fs::write(valid_day.join(name), "invalid").unwrap();
        }
        fs::write(invalid_day.join("20262907-120000-app.0.cert"), "invalid").unwrap();

        let files: Vec<_> = iter_ct_log_files(temp.path()).unwrap().collect();
        assert_eq!(files, vec![valid]);
    }

    #[test]
    fn exhausted_collision_range_fails_without_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let base = "20262907-120000-app";
        for index in 0..=MAX_COLLISION_INDEX {
            fs::write(temp.path().join(format!("{base}.{index}.cert")), "existing").unwrap();
        }
        let error = write_new_cert(temp.path(), base, b"new").unwrap_err();
        assert!(error.to_string().contains("collision range exhausted"));
        assert_eq!(
            fs::read_to_string(temp.path().join(format!("{base}.0.cert"))).unwrap(),
            "existing"
        );
    }

    #[test]
    fn iteration_survives_writer_restart() {
        let temp = tempfile::tempdir().unwrap();
        let day = temp.path().join("20262907");
        fs::create_dir_all(&day).unwrap();
        write_new_cert(&day, "20262907-120000-app", b"first").unwrap();
        write_new_cert(&day, "20262907-120000-app", b"second").unwrap();

        let mut contents: Vec<_> = iter_ct_log_files(temp.path())
            .unwrap()
            .map(|path| fs::read_to_string(path).unwrap())
            .collect();
        contents.sort();
        assert_eq!(contents, ["first", "second"]);
    }
}
