// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Build a verity volume from docker images or a directory.
//!
//! The output is a reproducible, dm-verity-protected squashfs volume that a CVM
//! mounts instead of pulling and unpacking. A `docker` volume seeds the overlay2
//! store; a data volume just mounts at a path.
//!
//! The build needs no docker daemon and no TEE, and it's reproducible: the same
//! inputs always give the same `verity_root`. So anyone can recompute the root
//! and check it against `app-compose.json`, without trusting the builder. See
//! docs/verity-volumes.md.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

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
    match (&opts.dir, opts.images.is_empty()) {
        (Some(_), false) => bail!("give either images or --dir, not both"),
        (None, true) => {
            bail!("nothing to build: pass an image, or --dir <path> to pack a directory")
        }
        (Some(dir), true) => verity_dir(dir.clone(), opts.output, opts.compress).await,
        (None, false) => verity_docker(opts).await,
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
        std::fs::create_dir_all(&store_dir)?;
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
