// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Build a verity volume from docker images or a directory.
//!
//! The output is a reproducible, dm-verity-protected raw disk image: partition 1
//! is the squashfs data filesystem, and partition 2 is the dm-verity superblock
//! plus hash tree. A `docker` volume seeds the overlay2 store; a data volume just
//! mounts at a path.
//!
//! The build needs no docker daemon and no TEE, and it's reproducible: the same
//! inputs always give the same `verity_root`. The first partition contains a
//! generic `DSTACK_VOLUME` envelope, followed by data and verity partitions.
//! So anyone can recompute the root
//! and check it against `app-compose.json`, without trusting the builder. See
//! docs/verity-volumes.md.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use fs_err as fs;

pub mod oci;
mod store;
mod volume;

pub use volume::Compression;

/// A fixed dm-verity salt.
///
/// The root is a function of the squashfs bytes and this salt, so keeping the
/// salt constant is what lets anyone recompute the root. It isn't a secret:
/// veritysetup writes it into the on-disk verity superblock anyway.
const VERITY_SALT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct VerityOptions {
    /// image references to bake in, e.g. `nvidia/cuda:12.4.1-runtime-ubuntu22.04`.
    /// Empty when building a data volume from `dir`.
    pub images: Vec<String>,
    /// build a data volume from this directory instead of docker images. The
    /// resulting volume is mounted at a `target: "/path"` in the compose.
    pub dir: Option<PathBuf>,
    /// wrap an existing filesystem image as the verity data partition. This is
    /// for hand-built ext4/xfs/etc. images; `dstack verity --dir` still produces
    /// squashfs by default.
    pub fs_image: Option<PathBuf>,
    pub output: PathBuf,
    /// squashfs compression (default: none — zero decompression at read time).
    pub compress: Compression,
    /// allow plain-HTTP registries (loopback registries default to HTTP anyway).
    pub plain_http: bool,
    /// target platform `os/arch` for image pulls (e.g. `linux/amd64`). Explicit
    /// so the build is reproducible and matches the guest's arch.
    pub platform: String,
}

pub struct VerityResult {
    pub verity_root: String,
    pub data_size: u64,
    pub output: PathBuf,
    pub images: Vec<ResolvedImage>,
}

pub struct ResolvedImage {
    pub reference: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub top_chain_id: String,
}

pub async fn verity(opts: VerityOptions) -> Result<VerityResult> {
    let source_count =
        (!opts.images.is_empty()) as u8 + opts.dir.is_some() as u8 + opts.fs_image.is_some() as u8;
    if source_count != 1 {
        bail!("give exactly one source: images, --dir <path>, or --fs-image <path>");
    }
    if let Some(dir) = &opts.dir {
        verity_dir(dir.clone(), opts.output, opts.compress).await
    } else if let Some(fs_image) = &opts.fs_image {
        verity_fs_image(fs_image.clone(), opts.output).await
    } else {
        verity_docker(opts).await
    }
}

/// Bake docker images into a `docker`-target volume.
async fn verity_docker(opts: VerityOptions) -> Result<VerityResult> {
    // 1. pull every image (daemonless, verified against its digests). Dedup
    // repeated references so `verity alpine alpine` doesn't pull twice.
    let mut seen = std::collections::HashSet::new();
    let refs: Vec<&String> = opts.images.iter().filter(|r| seen.insert(*r)).collect();
    let mut pulled = Vec::with_capacity(refs.len());
    for r in refs {
        tracing::info!("resolving {r}");
        pulled.push(oci::pull(r, opts.plain_http, &opts.platform).await?);
    }

    // 2. lay out a deterministic overlay2 store, then pack + verity it. Both are
    // synchronous and privileged (mknod / trusted xattr); do them off the async
    // reactor.
    let output = opts.output.clone();
    let compress = opts.compress;
    let (built, resolved) = tokio::task::spawn_blocking(move || -> Result<_> {
        let tmp = tempfile::tempdir().context("creating scratch dir")?;
        let store_dir = tmp.path().join("store");
        fs::create_dir_all(&store_dir)?;
        let tops = store::build_store(&pulled, &store_dir)?;
        let built = volume::build_volume(&store_dir, &output, VERITY_SALT, compress)?;
        let resolved = pulled
            .iter()
            .zip(&tops)
            .map(|(img, top)| ResolvedImage {
                reference: img.reference.clone(),
                manifest_digest: img.manifest_digest.clone(),
                config_digest: img.config_digest.clone(),
                top_chain_id: top.clone(),
            })
            .collect::<Vec<_>>();
        Ok((built, resolved))
    })
    .await
    .context("the build task failed")??;

    Ok(VerityResult {
        verity_root: built.verity_root,
        data_size: built.data_size,
        output: opts.output,
        images: resolved,
    })
}

/// Bake a directory tree into a data volume (mounted at a `target: "/path"`).
/// No docker, no overlay2 layout — just a reproducible squashfs of the tree.
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
        images: vec![],
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
        images: vec![],
    })
}
