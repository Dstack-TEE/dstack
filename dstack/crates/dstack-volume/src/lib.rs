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
