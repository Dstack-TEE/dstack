// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! OCI Distribution API client for pulling dstack guest images directly from
//! a container registry without requiring a local Docker daemon.

use std::path::Path;

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use reqwest::Client;
use serde::Deserialize;
use tracing::info;

fn build_client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()?)
}

// ─── Tag listing ────────────────────────────────────────────────────────────

/// List tags from a Docker Registry HTTP API v2 endpoint.
///
/// `image_ref` is in the form `registry.example.com/repo/name`.
pub async fn list_registry_tags(image_ref: &str) -> Result<Vec<String>> {
    let (registry, repo) = parse_image_ref(image_ref)?;
    let client = build_client()?;

    let url = format!("https://{registry}/v2/{repo}/tags/list");
    info!("fetching registry tags from {url}");

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to fetch registry tags")?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return list_tags_with_token(&client, &registry, &repo).await;
    }

    if !response.status().is_success() {
        bail!(
            "registry returned HTTP {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let tag_list: TagList = response
        .json()
        .await
        .context("failed to parse registry tag list")?;

    Ok(tag_list.tags.unwrap_or_default())
}

/// Handle token-based auth (Docker Hub / registries requiring Bearer token).
async fn list_tags_with_token(client: &Client, registry: &str, repo: &str) -> Result<Vec<String>> {
    let token = fetch_token(client, registry, repo).await?;
    let url = format!("https://{registry}/v2/{repo}/tags/list");
    let response = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .context("failed to fetch registry tags with token")?;

    if !response.status().is_success() {
        bail!(
            "registry returned HTTP {} after auth: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let tag_list: TagList = response
        .json()
        .await
        .context("failed to parse registry tag list")?;

    Ok(tag_list.tags.unwrap_or_default())
}

// ─── Image pulling ──────────────────────────────────────────────────────────

/// Pull an image from registry and extract to the local image directory.
///
/// Fetches the OCI manifest, downloads each layer blob, and extracts
/// the tar (gzipped) contents into a flat directory.
pub async fn pull_and_extract(image_ref: &str, tag: &str, image_path: &Path) -> Result<()> {
    let (registry, repo) = parse_image_ref(image_ref)?;
    let client = build_client()?;

    info!("pulling image {image_ref}:{tag}");

    // Resolve authentication
    let token = try_fetch_token(&client, &registry, &repo).await;

    // Fetch manifest
    let manifest = fetch_manifest(&client, &registry, &repo, tag, token.as_deref()).await?;

    // Determine output directory
    let output_dir = determine_output_dir(tag, image_path);
    if output_dir.exists() {
        bail!("image directory already exists: {}", output_dir.display());
    }

    // Extract into temp dir first, then rename atomically
    let tmp_dir = image_path.join(format!(".tmp-pull-{tag}"));
    if tmp_dir.exists() {
        fs_err::remove_dir_all(&tmp_dir).context("failed to clean up stale temp dir")?;
    }
    fs_err::create_dir_all(&tmp_dir)?;

    let result = download_and_extract_layers(
        &client,
        &registry,
        &repo,
        &manifest,
        token.as_deref(),
        &tmp_dir,
    )
    .await;

    if let Err(e) = &result {
        tracing::error!("pull failed, cleaning up temp dir: {e:#}");
        let _ = fs_err::remove_dir_all(&tmp_dir);
        return result;
    }

    // Verify metadata.json exists
    if !tmp_dir.join("metadata.json").exists() {
        let _ = fs_err::remove_dir_all(&tmp_dir);
        bail!("pulled image does not contain metadata.json - not a valid dstack guest image");
    }

    // Move to final location
    fs_err::rename(&tmp_dir, &output_dir).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_dir.display(),
            output_dir.display()
        )
    })?;

    info!("image extracted to {}", output_dir.display());
    Ok(())
}

/// Fetch OCI image manifest.
fn fetch_manifest<'a>(
    client: &'a Client,
    registry: &'a str,
    repo: &'a str,
    tag: &'a str,
    token: Option<&'a str>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<OciManifest>> + Send + 'a>> {
    Box::pin(async move { fetch_manifest_inner(client, registry, repo, tag, token).await })
}

async fn fetch_manifest_inner(
    client: &Client,
    registry: &str,
    repo: &str,
    tag: &str,
    token: Option<&str>,
) -> Result<OciManifest> {
    let url = format!("https://{registry}/v2/{repo}/manifests/{tag}");

    let mut req = client.get(&url).header(
        "Accept",
        "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json",
    );
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }

    let response = req.send().await.context("failed to fetch manifest")?;

    if !response.status().is_success() {
        bail!(
            "failed to fetch manifest: HTTP {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    // Try to parse as a single manifest first
    let body = response.text().await?;
    if let Ok(manifest) = serde_json::from_str::<OciManifest>(&body) {
        if !manifest.layers.is_empty() {
            return Ok(manifest);
        }
    }

    // Might be an index/manifest list — pick the first manifest
    if let Ok(index) = serde_json::from_str::<OciIndex>(&body) {
        if let Some(first) = index.manifests.into_iter().find(|m| {
            // Prefer the non-attestation manifest
            !m.media_type
                .as_deref()
                .is_some_and(|mt| mt.contains("attestation"))
        }) {
            return fetch_manifest(client, registry, repo, &first.digest, token).await;
        }
    }

    bail!("unsupported manifest format");
}

/// Download and extract all layer blobs into `dest`.
async fn download_and_extract_layers(
    client: &Client,
    registry: &str,
    repo: &str,
    manifest: &OciManifest,
    token: Option<&str>,
    dest: &Path,
) -> Result<()> {
    for (i, layer) in manifest.layers.iter().enumerate() {
        let size_mb = layer.size as f64 / 1_048_576.0;
        info!(
            "downloading layer {}/{}: {} ({:.1} MB)",
            i + 1,
            manifest.layers.len(),
            &layer.digest[..19.min(layer.digest.len())],
            size_mb,
        );

        let url = format!("https://{registry}/v2/{repo}/blobs/{}", layer.digest);
        let mut req = client.get(&url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }

        let response = req
            .send()
            .await
            .with_context(|| format!("failed to download layer {}", layer.digest))?;

        if !response.status().is_success() {
            bail!(
                "failed to download blob {}: HTTP {}",
                layer.digest,
                response.status()
            );
        }

        let bytes = response.bytes().await.context("failed to read blob body")?;
        extract_layer(&bytes, &layer.media_type, dest)?;
    }

    Ok(())
}

/// Extract a single layer (tar+gzip or tar) into `dest`.
fn extract_layer(data: &[u8], media_type: &str, dest: &Path) -> Result<()> {
    let is_gzip = media_type.contains("gzip")
        || media_type.contains("tar+gzip")
        || (data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b);

    if is_gzip {
        let decoder = GzDecoder::new(data);
        let mut archive = tar::Archive::new(decoder);
        archive
            .unpack(dest)
            .context("failed to extract gzipped tar layer")?;
    } else {
        let mut archive = tar::Archive::new(data);
        archive
            .unpack(dest)
            .context("failed to extract tar layer")?;
    }

    // Remove docker/OCI artifact directories that may appear in layers
    for dir in &["dev", "etc", "proc", "sys"] {
        let d = dest.join(dir);
        if d.is_dir() {
            let _ = fs_err::remove_dir(&d);
        }
    }

    Ok(())
}

// ─── Token auth ─────────────────────────────────────────────────────────────

/// Try to fetch a Bearer token. Returns None if the registry doesn't need one.
async fn try_fetch_token(client: &Client, registry: &str, repo: &str) -> Option<String> {
    // Probe the /v2/ endpoint to check if auth is needed
    let probe = client
        .get(format!("https://{registry}/v2/"))
        .send()
        .await
        .ok()?;

    if probe.status() != reqwest::StatusCode::UNAUTHORIZED {
        return None;
    }

    // Parse WWW-Authenticate header for realm and service
    let www_auth = probe
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let (realm, service) = parse_www_authenticate(www_auth);

    let token_url = if !realm.is_empty() {
        format!("{realm}?service={service}&scope=repository:{repo}:pull")
    } else {
        format!("https://{registry}/v2/token?service={registry}&scope=repository:{repo}:pull")
    };

    let resp = client.get(&token_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let token_data: TokenResponse = resp.json().await.ok()?;
    Some(token_data.token)
}

async fn fetch_token(client: &Client, registry: &str, repo: &str) -> Result<String> {
    try_fetch_token(client, registry, repo)
        .await
        .context("registry requires authentication but token exchange failed")
}

/// Extract realm and service from a WWW-Authenticate: Bearer header.
fn parse_www_authenticate(header: &str) -> (String, String) {
    let mut realm = String::new();
    let mut service = String::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some(v) = part
            .strip_prefix("Bearer realm=\"")
            .or_else(|| part.strip_prefix("realm=\""))
        {
            realm = v.trim_end_matches('"').to_string();
        } else if let Some(v) = part.strip_prefix("service=\"") {
            service = v.trim_end_matches('"').to_string();
        }
    }

    (realm, service)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn determine_output_dir(tag: &str, image_path: &Path) -> std::path::PathBuf {
    let dir_name = if tag.starts_with("dstack-") {
        tag.to_string()
    } else {
        format!("dstack-{tag}")
    };
    image_path.join(dir_name)
}

/// Parse "registry.example.com/repo/name" into ("registry.example.com", "repo/name").
///
/// For Docker Hub short names like "dstacktee/guest-image" (no dots in the
/// first component), automatically expands to "registry-1.docker.io/dstacktee/guest-image".
fn parse_image_ref(image_ref: &str) -> Result<(String, String)> {
    let trimmed = image_ref
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let first_slash = trimmed
        .find('/')
        .context("invalid image reference: no repository path")?;

    let first_component = &trimmed[..first_slash];
    let repo = &trimmed[first_slash + 1..];

    if repo.is_empty() {
        bail!("invalid image reference: empty repository");
    }

    // Docker Hub short names don't contain dots or colons
    let registry = if first_component.contains('.') || first_component.contains(':') {
        first_component.to_string()
    } else {
        // Docker Hub: "user/repo" → "registry-1.docker.io"
        // and the repo needs "library/" prefix for official images
        return Ok((
            "registry-1.docker.io".to_string(),
            format!("{first_component}/{repo}"),
        ));
    };

    Ok((registry, repo.to_string()))
}

// ─── OCI types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TagList {
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Deserialize, Debug)]
struct OciManifest {
    #[serde(default)]
    layers: Vec<OciLayer>,
}

#[derive(Deserialize, Debug)]
struct OciLayer {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Deserialize, Debug)]
struct OciIndex {
    manifests: Vec<OciIndexEntry>,
}

#[derive(Deserialize, Debug)]
struct OciIndexEntry {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_ref_private_registry() {
        let (reg, repo) = parse_image_ref("cr.kvin.wang/dstack/guest-image").unwrap();
        assert_eq!(reg, "cr.kvin.wang");
        assert_eq!(repo, "dstack/guest-image");
    }

    #[test]
    fn test_parse_image_ref_docker_hub() {
        let (reg, repo) = parse_image_ref("dstacktee/guest-image").unwrap();
        assert_eq!(reg, "registry-1.docker.io");
        assert_eq!(repo, "dstacktee/guest-image");
    }

    #[test]
    fn test_parse_image_ref_with_scheme() {
        let (reg, repo) = parse_image_ref("https://ghcr.io/dstack-tee/guest-image").unwrap();
        assert_eq!(reg, "ghcr.io");
        assert_eq!(repo, "dstack-tee/guest-image");
    }

    #[test]
    fn test_parse_www_authenticate() {
        let (realm, service) = parse_www_authenticate(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#,
        );
        assert_eq!(realm, "https://auth.docker.io/token");
        assert_eq!(service, "registry.docker.io");
    }
}
