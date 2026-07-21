// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Fetch an image from a registry, using the `oci-client` crate.
//!
//! Given a reference, this returns the image's config and per-layer blobs, byte
//! for byte, so the caller can lay out a deterministic overlay2 store. oci-client
//! does the fiddly parts: auth, Docker-Hub name normalization, picking the right
//! platform out of an image index, and verifying digests (including a `@sha256:`
//! pin).

use anyhow::{bail, Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// How many layer blobs to download at once (order-preserving, see `pull`).
const MAX_CONCURRENT_LAYERS: usize = 4;

/// A fully-resolved image: everything needed to build an overlay2 store.
pub struct PulledImage {
    /// the reference as given by the user (for display).
    pub reference: String,
    /// docker's canonical repository name, e.g. `docker.io/library/alpine`
    /// (the repositories.json map key).
    pub repo_name: String,
    /// the repositories.json key for this reference: `repo_name:tag`, or
    /// `repo_name@sha256:...` for a digest pin. `docker run` of the same
    /// reference looks this key up, so it's what makes the image a cache hit.
    pub ref_key: String,
    /// `sha256:...` digest of the manifest actually used (the resolved image).
    pub manifest_digest: String,
    /// `sha256:...` digest of the config blob — this is the docker image id.
    pub config_digest: String,
    /// the exact config blob bytes (stored verbatim in imagedb).
    pub config_bytes: Vec<u8>,
    /// `sha256:...` uncompressed digest per layer, bottom to top.
    pub diff_ids: Vec<String>,
    /// layer blobs, bottom to top, aligned with `diff_ids`.
    pub layers: Vec<PulledLayer>,
}

pub struct PulledLayer {
    pub media_type: String,
    pub data: Vec<u8>,
}

/// Pull `reference` for `platform`, returning its config and layers.
///
/// Layers are fetched in parallel but returned in manifest order, which keeps the
/// store layout deterministic. A loopback registry (or `plain_http`) is fetched
/// over HTTP instead of HTTPS.
pub async fn pull(reference: &str, plain_http: bool, platform: &str) -> Result<PulledImage> {
    let r: Reference = reference
        .parse()
        .with_context(|| format!("invalid image reference '{reference}'"))?;

    let insecure = plain_http || is_loopback(r.resolve_registry());
    let protocol = if insecure {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    };
    let client = Client::new(ClientConfig {
        protocol,
        // Pin the platform explicitly, not the build host's, so the build is
        // reproducible and targets the guest's arch. Not always amd64: arm64
        // confidential hosts are coming (NVIDIA Vera, AWS Graviton/Nitro).
        platform_resolver: Some(platform_resolver(platform)?),
        ..Default::default()
    });
    let auth = RegistryAuth::Anonymous;

    // oci-client verifies the manifest/config digests here (including a
    // `@sha256:` pin), and returns the config as its exact raw bytes.
    let (manifest, manifest_digest, config_json) = client
        .pull_manifest_and_config(&r, &auth)
        .await
        .with_context(|| format!("resolving {reference}"))?;
    let config_bytes = config_json.into_bytes();
    let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));
    let config: Config = serde_json::from_slice(&config_bytes).context("parsing image config")?;

    // the index resolver only runs for a multi-arch image; a single-arch manifest
    // is baked as-is, so check its config arch matches --platform (else we'd bake
    // a wrong-arch volume with a right-looking label).
    let (want_os, want_arch) = parse_platform(platform)?;
    if !config.architecture.is_empty() && config.architecture != want_arch {
        bail!(
            "image is {}/{}, but --platform is {want_os}/{want_arch} (pass --platform to match)",
            if config.os.is_empty() {
                "?"
            } else {
                &config.os
            },
            config.architecture
        );
    }

    for d in &manifest.layers {
        if !accepted_layer_types().contains(&d.media_type.as_str()) {
            bail!(
                "unsupported layer media type '{}' (only gzip/plain tar; zstd is not supported yet)",
                d.media_type
            );
        }
    }
    if config.rootfs.diff_ids.len() != manifest.layers.len() {
        bail!(
            "manifest/config mismatch: {} layers vs {} diff_ids",
            manifest.layers.len(),
            config.rootfs.diff_ids.len()
        );
    }

    // Download each layer blob (digest-verified by oci-client) concurrently but
    // yielded in manifest order — `buffered` preserves input order, so the store
    // layout is deterministic without giving up parallel download.
    tracing::info!("pulling {} layer(s) of {reference}", manifest.layers.len());
    use futures::stream::{StreamExt, TryStreamExt};
    let layers: Vec<PulledLayer> = futures::stream::iter(manifest.layers.iter())
        .map(|d| {
            let client = &client;
            let r = &r;
            async move {
                // cap the speculative reservation: `d.size` is from the manifest
                // and only digest-checked after download. pull_blob grows it as
                // needed, so an inflated size can't force a huge up-front alloc.
                let hint = (d.size.max(0) as usize).min(64 << 20);
                let mut data = Vec::with_capacity(hint);
                client
                    .pull_blob(r, d, &mut data)
                    .await
                    .with_context(|| format!("fetching layer {}", d.digest))?;
                Ok::<_, anyhow::Error>(PulledLayer {
                    media_type: d.media_type.clone(),
                    data,
                })
            }
        })
        .buffered(MAX_CONCURRENT_LAYERS)
        .try_collect()
        .await?;

    let (repo_name, ref_key) = repo_and_key(&r);
    Ok(PulledImage {
        reference: reference.to_string(),
        repo_name,
        ref_key,
        manifest_digest,
        config_digest,
        config_bytes,
        diff_ids: config.rootfs.diff_ids,
        layers,
    })
}

type PlatformResolverFn =
    dyn Fn(&[oci_client::manifest::ImageIndexEntry]) -> Option<String> + Send + Sync;

/// Split `os/arch` (default os `linux`), normalizing the common non-OCI arch
/// spellings (`x86_64` -> `amd64`, `aarch64` -> `arm64`).
fn parse_platform(platform: &str) -> Result<(String, String)> {
    let (os, arch) = platform
        .split_once('/')
        .map(|(o, a)| (o.to_string(), a.to_string()))
        .unwrap_or_else(|| ("linux".to_string(), platform.to_string()));
    let arch = match arch.as_str() {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        _ => arch,
    };
    if os.is_empty() || arch.is_empty() {
        bail!("invalid --platform '{platform}' (expected e.g. linux/amd64)");
    }
    Ok((os, arch))
}

/// Build a resolver that picks the `os/arch` entry out of an image index.
fn platform_resolver(platform: &str) -> Result<Box<PlatformResolverFn>> {
    let (os, arch) = parse_platform(platform)?;
    Ok(Box::new(
        move |manifests: &[oci_client::manifest::ImageIndexEntry]| {
            manifests
                .iter()
                .find(|e| {
                    e.platform.as_ref().is_some_and(|p| {
                        p.os.to_string() == os && p.architecture.to_string() == arch
                    })
                })
                .map(|e| e.digest.clone())
        },
    ))
}

/// The layer media types we can extract: gzip and plain tar.
///
/// Checking against these lets us reject an unsupported layer (e.g. zstd) up
/// front, instead of failing later during extraction.
fn accepted_layer_types() -> [&'static str; 4] {
    [
        manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
        manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        manifest::IMAGE_LAYER_MEDIA_TYPE,
        manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    ]
}

/// Return `(repo_name, ref_key)` for a reference.
///
/// `repo_name` is docker's canonical name (the repositories.json map key);
/// `ref_key` is the entry within it — `repo@digest` for a pin, `repo:tag`
/// otherwise. `Reference` already normalizes Docker-Hub names to
/// `docker.io/library/<name>`.
fn repo_and_key(r: &Reference) -> (String, String) {
    let repo = format!("{}/{}", r.registry(), r.repository());
    let key = match r.digest() {
        Some(d) => format!("{repo}@{d}"),
        None => format!("{repo}:{}", r.tag().unwrap_or("latest")),
    };
    (repo, key)
}

/// A loopback registry we default to plain HTTP for. Any other insecure
/// registry uses `--plain-http`.
fn is_loopback(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    h == "localhost" || h.starts_with("127.")
}

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
    rootfs: RootFs,
}
#[derive(Deserialize)]
struct RootFs {
    #[serde(rename = "diff_ids", default)]
    diff_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> (String, String) {
        repo_and_key(&s.parse::<Reference>().unwrap())
    }

    #[test]
    fn hub_short_name_canonicalizes() {
        let (repo, k) = key("alpine:3.20");
        assert_eq!(repo, "docker.io/library/alpine");
        assert_eq!(k, "docker.io/library/alpine:3.20");
    }

    #[test]
    fn fully_qualified_hub_matches_short() {
        // the doc tells users to fully-qualify; it must resolve identically.
        assert_eq!(key("docker.io/library/alpine:3.20"), key("alpine:3.20"));
    }

    #[test]
    fn digest_pin_uses_at_key() {
        let d = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let (repo, k) = key(&format!("ghcr.io/foo/bar@{d}"));
        assert_eq!(repo, "ghcr.io/foo/bar");
        assert_eq!(k, format!("ghcr.io/foo/bar@{d}"));
    }

    #[test]
    fn private_registry_with_port() {
        let (repo, k) = key("10.0.2.2:5000/bench/alpine:3.20");
        assert_eq!(repo, "10.0.2.2:5000/bench/alpine");
        assert_eq!(k, "10.0.2.2:5000/bench/alpine:3.20");
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("localhost:5000"));
        assert!(is_loopback("127.0.0.1:5000"));
        assert!(!is_loopback("10.0.2.2:5000")); // qemu-guest alias, not the host
        assert!(!is_loopback("ghcr.io"));
        assert!(!is_loopback("index.docker.io"));
    }

    #[test]
    fn platform_resolver_picks_requested_arch() {
        let entries: Vec<oci_client::manifest::ImageIndexEntry> =
            serde_json::from_value(serde_json::json!([
                {"mediaType":"m","digest":"sha256:amd","size":1,
                 "platform":{"architecture":"amd64","os":"linux"}},
                {"mediaType":"m","digest":"sha256:arm","size":1,
                 "platform":{"architecture":"arm64","os":"linux"}}
            ]))
            .unwrap();
        assert_eq!(
            platform_resolver("linux/amd64").unwrap()(&entries).as_deref(),
            Some("sha256:amd")
        );
        assert_eq!(
            platform_resolver("linux/arm64").unwrap()(&entries).as_deref(),
            Some("sha256:arm")
        );
        // aarch64 alias normalizes to arm64.
        assert_eq!(
            platform_resolver("linux/aarch64").unwrap()(&entries).as_deref(),
            Some("sha256:arm")
        );
        // a platform with no matching entry resolves to nothing.
        assert_eq!(platform_resolver("windows/amd64").unwrap()(&entries), None);
    }
}
