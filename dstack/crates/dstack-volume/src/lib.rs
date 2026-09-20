// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Build, describe, and activate dstack volumes.
//!
//! The output is a reproducible, dm-verity-protected raw disk image containing
//! a filesystem that the guest mounts read-only at a measured path.
//!
//! The build needs no docker daemon and no TEE, and it's reproducible: the same
//! inputs always give the same `verity_root`. The first partition contains a
//! generic `DSTACK_VOLUME` envelope, followed by data and verity partitions.
//! So anyone can recompute the root
//! and check it against `app-compose.json`, without trusting the builder. See
//! docs/verity-volumes.md.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

mod volume;
pub mod volume_format;

pub use volume::Compression;

/// Read the root hash out of `veritysetup` output.
///
/// One grammar for both commands this project reads. `veritysetup format`
/// prints `Root hash:\t<hex>` flush left; `veritysetup status` prints
/// `  root hash:\t<hex>` indented and lower-cased. Two parsers, one per
/// command, is how a later cryptsetup release gets to break one of them
/// silently -- so accept both spellings in one place and require what follows
/// to actually be a hash.
pub fn parse_verity_root_hash(output: &str) -> Option<String> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("Root hash:")
                .or_else(|| line.strip_prefix("root hash:"))
        })
        .map(str::trim)
        .find(|root| !root.is_empty() && root.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_string)
}

#[cfg(test)]
mod root_hash_tests {
    use super::parse_verity_root_hash;

    /// Captured from `veritysetup 2.7.0`: `format` writes the summary flush
    /// left with a capital R, `status` writes it indented and lower-cased.
    #[test]
    fn both_veritysetup_spellings_parse() {
        const ROOT: &str = "e85f5e7498a2b6f3ef05d0f612cfbec7f7bff7c2cbd64ffdebb972ab54606f89";
        let format_output = format!(
            "VERITY header information for hash.img\n\
             UUID:            \taa7082ce-3622-4ce5-a875-9cc88edf35a7\n\
             Hash algorithm:  \tsha256\n\
             Salt:            \t00\n\
             Root hash:      \t{ROOT}\n\
             Hash device size: \t8192 [bytes]\n"
        );
        let status_output = format!(
            "/dev/mapper/dstack-verity0 is active.\n\
             \ttype:        VERITY\n\
             \tstatus:      verified\n\
             \thash name:   sha256\n\
             \troot hash:   {ROOT}\n"
        );
        assert_eq!(
            parse_verity_root_hash(&format_output).as_deref(),
            Some(ROOT)
        );
        assert_eq!(
            parse_verity_root_hash(&status_output).as_deref(),
            Some(ROOT)
        );
    }

    /// A line that announces a root hash and then does not carry one is not a
    /// root hash. Returning it would feed `veritysetup open` a bad argument
    /// and blame the volume for it.
    #[test]
    fn a_label_without_a_hash_is_not_a_root_hash() {
        assert_eq!(parse_verity_root_hash("Root hash:\n"), None);
        assert_eq!(parse_verity_root_hash("root hash:   (none)\n"), None);
        assert_eq!(parse_verity_root_hash("no root hash here\n"), None);
    }
}

/// A fixed dm-verity salt.
///
/// The root is a function of the squashfs bytes and this salt, so keeping the
/// salt constant is what lets anyone recompute the root. It isn't a secret:
/// veritysetup writes it into the on-disk verity superblock anyway.
const VERITY_SALT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct VerityOptions {
    /// Build a volume from this directory.
    pub dir: Option<PathBuf>,
    /// wrap an existing filesystem image as the verity data partition. This is
    /// for hand-built ext4/xfs/etc. images; `dstack verity --dir` still produces
    /// squashfs by default.
    pub fs_image: Option<PathBuf>,
    pub output: PathBuf,
    /// squashfs compression (default: none — zero decompression at read time).
    pub compress: Compression,
}

pub struct VerityResult {
    pub verity_root: String,
    pub data_size: u64,
    pub output: PathBuf,
}

pub async fn verity(opts: VerityOptions) -> Result<VerityResult> {
    match (opts.dir, opts.fs_image) {
        (Some(dir), None) => verity_dir(dir, opts.output, opts.compress).await,
        (None, Some(fs_image)) => verity_fs_image(fs_image, opts.output).await,
        _ => bail!("give exactly one source: --dir <path> or --fs-image <path>"),
    }
}

/// Bake a directory tree into a reproducible squashfs data volume.
async fn verity_dir(dir: PathBuf, output: PathBuf, compress: Compression) -> Result<VerityResult> {
    if !dir.is_dir() {
        bail!("--dir '{}' is not a directory", dir.display());
    }
    let out = output.clone();
    let built = tokio::task::spawn_blocking(move || {
        volume::build_volume(&dir, &out, VERITY_SALT, compress)
    })
    .await
    .context("the build task failed")??;

    Ok(VerityResult {
        verity_root: built.verity_root,
        data_size: built.data_size,
        output,
    })
}

/// Wrap an already-built filesystem image. The guest discovers and mounts the
/// filesystem only after dm-verity is active.
async fn verity_fs_image(fs_image: PathBuf, output: PathBuf) -> Result<VerityResult> {
    if !fs_image.is_file() {
        bail!("--fs-image '{}' is not a file", fs_image.display());
    }
    let out = output.clone();
    let built =
        tokio::task::spawn_blocking(move || volume::build_fs_image(&fs_image, &out, VERITY_SALT))
            .await
            .context("the build task failed")??;

    Ok(VerityResult {
        verity_root: built.verity_root,
        data_size: built.data_size,
        output,
    })
}
