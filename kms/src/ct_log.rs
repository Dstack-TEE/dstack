// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use fs_err as fs;

#[allow(dead_code)]
pub(crate) fn iter_ct_log_files(log_dir: &Path) -> Result<impl Iterator<Item = PathBuf>> {
    // Certs files at log_dir/YYYYMMDD/xxx.cert
    let day_dirs = fs::read_dir(log_dir)?.filter_map(|entry| {
        let path = entry.ok()?.path();
        if path.is_dir() {
            Some(path)
        } else {
            None
        }
    });

    Ok(day_dirs
        .flat_map(|dir| {
            let iter = fs::read_dir(dir).ok()?.filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.is_file() && path.ends_with(".cert") {
                    Some(path)
                } else {
                    None
                }
            });
            Some(iter)
        })
        .flatten())
}

pub(crate) fn ct_log_write_cert(app_id: &str, cert: &str, log_dir: &str) -> Result<()> {
    // filename: %Y%d%m-%H%M%S.%sn.%app_id.cert
    let log_dir = Path::new(log_dir);
    let now = Utc::now();
    let day = now.format("%Y%d%m").to_string();
    let base_filename = format!("{}-{app_id}", now.format("%Y%d%m-%H%M%S"));
    let day_dir = log_dir.join(day);
    fs::create_dir_all(&day_dir).context("failed to create ct log dir")?;
    let cert_log_path = find_available_filename(&day_dir, &base_filename)
        .context("failed to find available filename")?;
    fs::write(cert_log_path, cert).context("faile to write ct log cert")?;
    Ok(())
}

fn binary_search(mut upper: usize, is_ok: impl Fn(usize) -> bool) -> Option<usize> {
    let mut lower = 0;
    if is_ok(0) {
        return Some(0);
    }
    if !is_ok(upper) {
        return None;
    }
    while lower < upper {
        let mid = lower + (upper - lower) / 2;
        if is_ok(mid) {
            upper = mid;
        } else {
            lower = mid + 1;
        }
    }
    Some(upper)
}

fn find_available_filename(dir: &Path, base_filename: &str) -> Option<PathBuf> {
    fn mk_filename(dir: &Path, base_filename: &str, index: usize) -> PathBuf {
        dir.join(format!("{base_filename}.{index}.cert"))
    }
    let available_index = binary_search(4096, |i| {
        !std::path::Path::new(&mk_filename(dir, base_filename, i)).exists()
    })?;
    Some(mk_filename(dir, base_filename, available_index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_search_simple() {
        for i in 0..=4096 {
            let result = binary_search(4096, |x| x >= i);
            assert_eq!(result, Some(i));
        }
    }
}
