// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup image` — fetch, list, and remove guest OS images.
//!
//! Images are published as `guest-os-v*` release tarballs in the dstack
//! monorepo. Current releases use one hardware-adaptive `dstack-<ver>` image;
//! legacy releases may also contain `dstack-nvidia-<ver>` variants.
//! `install` validates the selected image against `digest.txt`, the OS image
//! hash used on all platforms. HTTP + checksum are native (reqwest is
//! already linked via the prpc client; sha2 verifies inline); only `tar` is
//! shelled out, since GNU tar is ubiquitous and battle-tested on archive edges.

use crate::cli::ImageCmd;
use crate::systemd::tool;
use anyhow::{bail, Context, Result};
use dstack_cli_core::layout::{path_string, validate_owned_path, InstallLayout};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

const REPO: &str = "Dstack-TEE/dstack";
const LEGACY_REPO: &str = "Dstack-TEE/meta-dstack";
const RELEASE_TAG_PREFIX: &str = "guest-os-v";
pub(crate) const RELEASES_URL: &str = "https://github.com/Dstack-TEE/dstack/releases?q=guest-os-v";
const LEGACY_RELEASES_URL: &str = "https://github.com/Dstack-TEE/meta-dstack/releases";
const MONOREPO_GUEST_OS_MIN_VERSION: (u64, u64, u64) = (0, 6, 0);

/// the single rule for where images live: `--image-path` if given, else the
/// image directory from the install layout. `install` and every image subcommand resolve through
/// here, so they can't drift.
pub(crate) fn resolve_image_dir(image_path: Option<&str>, prefix: Option<&str>) -> String {
    image_path
        .map(str::to_string)
        .unwrap_or_else(|| path_string(&InstallLayout::image_dir_for_prefix(prefix)))
}

pub(crate) fn validate_image_dir(image_dir: &str) -> Result<()> {
    validate_owned_path("image directory", Path::new(image_dir))
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    /// `"sha256:<hex>"` when the release publishes one (newer releases do); we
    /// verify the download against it. absent on older releases.
    #[serde(default)]
    digest: Option<String>,
}

struct PullSpec {
    version: String,
    gpu: bool,
}

pub(crate) async fn cmd_image(cmd: ImageCmd, release_api_base_url: &str) -> Result<()> {
    match cmd {
        ImageCmd::Pull {
            version,
            gpu,
            loc,
            force,
            insecure,
        } => {
            let image_dir = loc.dir();
            validate_image_dir(&image_dir)?;
            pull(
                version.as_deref(),
                gpu,
                &image_dir,
                force,
                insecure,
                release_api_base_url,
            )
            .await?;
            Ok(())
        }
        ImageCmd::List { loc } => {
            let image_dir = loc.dir();
            validate_image_dir(&image_dir)?;
            list(&image_dir)
        }
        ImageCmd::Rm { names, loc } => {
            let image_dir = loc.dir();
            validate_image_dir(&image_dir)?;
            remove(&names, &image_dir)
        }
    }
}

/// Download a guest image from the latest (or a specific) guest-OS release.
pub(crate) async fn pull(
    version: Option<&str>,
    gpu: bool,
    image_dir: &str,
    force: bool,
    insecure: bool,
    release_api_base_url: &str,
) -> Result<String> {
    println!(
        "dstackup image pull — {} image",
        if gpu {
            "gpu-capable (legacy nvidia variant preferred)"
        } else {
            "unified"
        }
    );
    let release = fetch_release(version, release_api_base_url).await?;

    let asset = pick_asset(&release.assets, gpu).with_context(|| {
        format!(
            "no suitable {} image tarball in guest-OS release {} (assets: {})",
            if gpu { "GPU-capable" } else { "unified" },
            release.tag_name,
            release
                .assets
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    // never trust the asset name into a filesystem path (github forbids `/` in
    // asset names, but don't rely on that structurally).
    if !valid_image_name(&asset.name) {
        bail!(
            "refusing release asset with an unsafe name {:?}",
            asset.name
        );
    }

    // Release archives use their filename stem as the top-level image
    // directory. Select the asset before this check because --gpu may resolve
    // to a legacy dstack-nvidia archive or to the current unified image.
    let expected = asset
        .name
        .strip_suffix(".tar.gz")
        .context("guest image asset must end in .tar.gz")?;
    if !force
        && Path::new(image_dir)
            .join(expected)
            .join("metadata.json")
            .exists()
    {
        println!("  [ok] {expected} already present (use --force to re-download)");
        return Ok(expected.to_string());
    }
    println!("  [..] release {} -> {}", release.tag_name, asset.name);

    fs::create_dir_all(image_dir).with_context(|| format!("creating {image_dir}"))?;

    // download → verify checksum → unpack into a dot-prefixed staging dir →
    // adopt (atomic rename) only once metadata.json is present. so a truncated
    // download or a tar that dies mid-unpack can never masquerade as a valid
    // image. temp artifacts are dot-prefixed (skipped by listings) and cleaned
    // up regardless of outcome. (the `valid_image_name` check above is
    // load-bearing for these two joins — keep it before any path use.)
    let tmp = Path::new(image_dir).join(format!(".{}.partial", asset.name));
    let staging = Path::new(image_dir).join(format!(".{}.staging", asset.name));
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_dir_all(&staging);
    let adopted = stage_image(asset, image_dir, &tmp, &staging, insecure).await;
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_dir_all(&staging);
    let name = adopted?;

    println!("  [ok] image ready: {name}");
    println!("  deploy with: dstackup install --image {name}   (or: dstack deploy -c <compose> --image {name})");
    Ok(name)
}

/// download, verify, unpack into `staging`, and atomically move the unpacked
/// image dir into `image_dir`. returns the image's (unpacked) directory name.
async fn stage_image(
    asset: &Asset,
    image_dir: &str,
    tmp: &Path,
    staging: &Path,
    insecure: bool,
) -> Result<String> {
    download_verified(
        &asset.browser_download_url,
        tmp,
        asset.digest.as_deref(),
        insecure,
    )
    .await?;
    fs::create_dir_all(staging).with_context(|| format!("creating {}", staging.display()))?;
    extract(&tmp.to_string_lossy(), &staging.to_string_lossy())?;
    // Do not assume the unpacked directory name matches the release asset;
    // adopt the directory that actually contains metadata.json.
    let inner = image_subdirs(&staging.to_string_lossy())
        .into_iter()
        .find(|d| staging.join(d).join("metadata.json").exists())
        .context("unpacked tarball has no image dir with a metadata.json")?;
    let dest = Path::new(image_dir).join(&inner);
    let _ = fs::remove_dir_all(&dest);
    fs::rename(staging.join(&inner), &dest)
        .with_context(|| format!("moving image into {}", dest.display()))?;
    Ok(inner)
}

/// stream the download to `dest`, hashing as it goes, and verify against the
/// release's `"sha256:<hex>"` digest in the same pass — fail closed on mismatch,
/// and fail closed when no digest is published unless `insecure`. github
/// 302-redirects to its object store; reqwest follows that by default.
///
/// the `std::fs` writes here are synchronous inside an async fn; that's fine for
/// this single-task CLI (nothing else runs on the executor), and not worth a
/// `spawn_blocking` dance.
async fn download_verified(
    url: &str,
    dest: &Path,
    expected: Option<&str>,
    insecure: bool,
) -> Result<()> {
    // fail closed BEFORE downloading hundreds of MB if we can't verify it.
    if expected.is_none() && !insecure {
        bail!("this release publishes no sha256 digest to verify the download against — pass --insecure to proceed unverified (not recommended)");
    }
    let mut resp = reqwest::get(url)
        .await
        .with_context(|| format!("requesting {url}"))?
        .error_for_status()
        .with_context(|| format!("download failed from {url}"))?;
    let total = resp.content_length();
    println!(
        "  [..] downloading{}...",
        total
            .map(|n| format!(" {} MB", n / 1_048_576))
            .unwrap_or_default()
    );
    let mut file =
        fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut done: u64 = 0;
    let mut next_pct = 25u64;
    let mut next_bytes = 50 * 1_048_576u64;
    while let Some(chunk) = resp.chunk().await.context("reading download stream")? {
        hasher.update(&chunk);
        file.write_all(&chunk)
            .with_context(|| format!("writing {}", dest.display()))?;
        done += chunk.len() as u64;
        match total.filter(|t| *t > 0) {
            // known size: percentage milestones.
            Some(total) => {
                let pct = done * 100 / total;
                if pct >= next_pct {
                    println!("  [..] {pct}%");
                    next_pct = (pct / 25 + 1) * 25;
                }
            }
            // chunked / unknown size: byte milestones, so it's never silent.
            None => {
                if done >= next_bytes {
                    println!("  [..] {} MB", done / 1_048_576);
                    next_bytes += 50 * 1_048_576;
                }
            }
        }
    }
    let _ = file.sync_all();

    let Some(expected) = expected else {
        println!("  [!]  no sha256 digest published - integrity not verified (--insecure)");
        return Ok(());
    };
    let want = expected
        .strip_prefix("sha256:")
        .unwrap_or(expected)
        .to_lowercase();
    let got = hex::encode(hasher.finalize());
    if got != want {
        bail!("image checksum mismatch (expected {want}, got {got}) — refusing a tampered or corrupt download");
    }
    println!("  [ok] sha256 verified");
    Ok(())
}

fn list(image_dir: &str) -> Result<()> {
    let imgs = installed_images(image_dir);
    if imgs.is_empty() {
        println!("{}", no_image_message(image_dir));
        return Ok(());
    }
    println!("images in {image_dir} (newest last):");
    for name in &imgs {
        println!("  {name}");
    }
    Ok(())
}

/// delete one or more local images by name (the `<image_dir>/<name>` dir).
fn remove(names: &[String], image_dir: &str) -> Result<()> {
    let mut removed = 0;
    for name in names {
        // a name must be a plain dir component — never a path that could escape
        // image_dir (`..`, `/foo`) and delete something we don't own.
        if !valid_image_name(name) {
            bail!("invalid image name {name:?} (expected a plain image name, see `dstackup image list`)");
        }
        let dir = Path::new(image_dir).join(name);
        if !dir.is_dir() {
            println!("  [!]  {name}: not found in {image_dir}");
            continue;
        }
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        println!("  [ok] removed {name}");
        removed += 1;
    }
    if removed == 0 {
        bail!("removed nothing (see `dstackup image list`)");
    }
    Ok(())
}

/// a removable image name is a single path component, never `.`/`..` or a path
/// (so `rm` can't be tricked into deleting outside the image dir).
fn valid_image_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
}

/// resolve which guest image `install` should use: an explicit `--image` if
/// given, else the newest image present locally. `require` (KMS mode, which
/// boots a CVM at install time) makes "none" a hard error with download
/// guidance; otherwise it returns `None` and prints a gentle note.
pub(crate) fn resolve_image(
    image_dir: &str,
    requested: Option<&str>,
    require: bool,
) -> Result<Option<String>> {
    if let Some(name) = requested {
        if !valid_image_name(name) {
            bail!("invalid image name {name:?} (expected a plain image name, see `dstackup image list`)");
        }
        if Path::new(image_dir)
            .join(name)
            .join("metadata.json")
            .exists()
        {
            return Ok(Some(name.to_string()));
        }
        bail!("{}", missing_named_image_message(image_dir, name));
    }
    let mut imgs = installed_images(image_dir);
    if let Some(newest) = imgs.pop() {
        if imgs.is_empty() {
            println!("  [ok] using image {newest}");
        } else {
            println!(
                "  [ok] using image {newest} (newest by fetch time; also present: {} — pass --image to choose)",
                imgs.join(", ")
            );
        }
        return Ok(Some(newest));
    }
    if require {
        bail!("{}", no_image_message(image_dir));
    }
    println!("  [!]  no guest image in {image_dir} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)");
    Ok(None)
}

/// resolve the image for install. If KMS mode needs an image and there is no
/// local image yet, fetch the latest CPU image through the same verified pull
/// path as `dstackup image pull`, then resolve from disk again.
pub(crate) async fn resolve_or_pull_image(
    image_dir: &str,
    requested: Option<&str>,
    require: bool,
    required_files: &[&str],
    release_api_base_url: &str,
) -> Result<Option<String>> {
    if let Some(name) = requested {
        if !valid_image_name(name) {
            bail!("invalid image name {name:?} (expected a plain image name, see `dstackup image list`)");
        }
        if Path::new(image_dir)
            .join(name)
            .join("metadata.json")
            .exists()
        {
            ensure_image_has_required_files(image_dir, name, required_files)?;
            return Ok(Some(name.to_string()));
        }
        if let Some(spec) = pull_spec(name) {
            println!("  [..] image {name} not found locally; downloading it");
            let pulled = pull(
                Some(&spec.version),
                spec.gpu,
                image_dir,
                false,
                false,
                release_api_base_url,
            )
            .await?;
            ensure_image_has_required_files(image_dir, &pulled, required_files)?;
            return Ok(Some(pulled));
        }
        let resolved = resolve_image(image_dir, Some(name), require)?;
        if let Some(resolved) = &resolved {
            ensure_image_has_required_files(image_dir, resolved, required_files)?;
        }
        return Ok(resolved);
    }

    let mut imgs = installed_images(image_dir);
    let skipped = retain_images_with_required_files(&mut imgs, image_dir, required_files);
    if let Some(newest) = imgs.pop() {
        if !skipped.is_empty() {
            println!(
                "  [!]  ignoring image(s) without {}: {}",
                required_files_label(required_files),
                skipped.join(", ")
            );
        }
        if imgs.is_empty() {
            println!("  [ok] using image {newest}");
        } else {
            println!(
                "  [ok] using image {newest} (newest by fetch time; also present: {} - pass --image to choose)",
                imgs.join(", ")
            );
        }
        return Ok(Some(newest));
    }

    if !require {
        if !required_files.is_empty() {
            if skipped.is_empty() {
                println!(
                    "  [!]  no guest image in {image_dir} with {} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)",
                    required_files_label(required_files)
                );
            } else {
                println!(
                    "  [!]  no guest image in {image_dir} with {}; ignored {} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)",
                    required_files_label(required_files),
                    skipped.join(", ")
                );
            }
        } else {
            println!("  [!]  no guest image in {image_dir} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)");
        }
        return Ok(None);
    }

    if !required_files.is_empty() {
        if skipped.is_empty() {
            println!(
                "  [..] no local guest image with {} found; downloading the latest cpu image",
                required_files_label(required_files)
            );
        } else {
            println!(
                "  [..] no local guest image with {} found (ignored {}); downloading the latest cpu image",
                required_files_label(required_files),
                skipped.join(", ")
            );
        }
    } else {
        println!("  [..] no local guest image found; downloading the latest cpu image");
    }
    let pulled = pull(None, false, image_dir, false, false, release_api_base_url).await?;

    if Path::new(image_dir)
        .join(&pulled)
        .join("metadata.json")
        .exists()
    {
        ensure_image_has_required_files(image_dir, &pulled, required_files)?;
        Ok(Some(pulled))
    } else {
        bail!("downloaded image {pulled}, but it is not available in {image_dir}")
    }
}

fn retain_images_with_required_files(
    imgs: &mut Vec<String>,
    image_dir: &str,
    required_files: &[&str],
) -> Vec<String> {
    if required_files.is_empty() {
        return Vec::new();
    }
    let mut skipped = Vec::new();
    imgs.retain(|name| {
        let has_required_files = image_has_required_files(image_dir, name, required_files);
        if !has_required_files {
            skipped.push(name.clone());
        }
        has_required_files
    });
    skipped
}

fn image_has_required_files(image_dir: &str, image: &str, required_files: &[&str]) -> bool {
    required_files
        .iter()
        .all(|file| Path::new(image_dir).join(image).join(file).is_file())
}

fn ensure_image_has_required_files(
    image_dir: &str,
    image: &str,
    required_files: &[&str],
) -> Result<()> {
    let missing = missing_required_files(image_dir, image, required_files);
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "image {image:?} under {image_dir} is missing required file(s): {}",
        missing.join(", ")
    )
}

fn missing_required_files(image_dir: &str, image: &str, required_files: &[&str]) -> Vec<String> {
    required_files
        .iter()
        .filter(|file| !Path::new(image_dir).join(image).join(file).is_file())
        .map(|file| (*file).to_string())
        .collect()
}

fn required_files_label(required_files: &[&str]) -> String {
    if required_files.is_empty() {
        "required file(s)".to_string()
    } else {
        required_files.join(", ")
    }
}

fn pull_spec(name: &str) -> Option<PullSpec> {
    if !valid_image_name(name) {
        return None;
    }
    if let Some(version) = name.strip_prefix("dstack-nvidia-") {
        return release_version(version).map(|version| PullSpec { version, gpu: true });
    }
    if let Some(version) = name.strip_prefix("dstack-") {
        return release_version(version).map(|version| PullSpec {
            version,
            gpu: false,
        });
    }
    release_version(name).map(|version| PullSpec {
        version,
        gpu: false,
    })
}

fn release_version(version: &str) -> Option<String> {
    let version = version.trim_start_matches('v');
    let mut chars = version.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return None;
    }
    Some(version.to_string())
}

/// the `dstackup image pull` invocation that targets `image_dir` — bare for the
/// default dir, else with the explicit `--image-path` so it's copy-paste correct.
fn pull_cmd(image_dir: &str) -> String {
    if image_dir == resolve_image_dir(None, None) {
        "dstackup image pull".to_string()
    } else {
        format!("dstackup image pull --image-path {image_dir}")
    }
}

/// the friendly "no image — here's how to get one" message.
pub(crate) fn no_image_message(image_dir: &str) -> String {
    let pull = pull_cmd(image_dir);
    format!(
        "no guest image found in {image_dir}\n\n\
         download the latest with:\n    \
         {pull}            # current unified CPU/GPU image\n    \
         {pull} --gpu      # prefer a legacy nvidia-specific asset\n\n\
         images are published at {RELEASES_URL}"
    )
}

fn missing_named_image_message(image_dir: &str, name: &str) -> String {
    let pull = pull_cmd(image_dir);
    format!(
        "image '{name}' not found in {image_dir}\n\n\
         download it with:\n    \
         {pull} --version <version>\n\n\
         or see what's available locally:\n    \
         dstackup image list"
    )
}

/// Get the latest (or a tagged) guest-OS release from the GitHub API.
///
/// Versions before 0.6.0 were released from `meta-dstack`; 0.6.0 and later are
/// released from this monorepo. Do not probe the new repository first for old
/// versions: the version boundary is authoritative and avoids redundant or
/// misleading requests.
async fn fetch_release(version: Option<&str>, release_api_base_url: &str) -> Result<Release> {
    let client = reqwest::Client::new();
    if let Some(version) = version {
        let (version, url, releases_url) = tagged_release_location(version, release_api_base_url)?;
        return fetch_tagged_release(&client, &url, releases_url)
            .await?
            .with_context(|| {
                format!("guest-OS version {version} was not found; check {releases_url}")
            });
    }

    let api_base = release_api_base_url.trim().trim_end_matches('/');
    let list_url = format!("{api_base}/{REPO}/releases?per_page=100");
    let releases: Vec<Release> = client
        .get(&list_url)
        .header("user-agent", "dstackup")
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .context("requesting dstack releases")?
        .error_for_status()
        .with_context(|| format!("github release lookup failed; check {RELEASES_URL}"))?
        .json()
        .await
        .context("parsing dstack release list")?;
    if let Some(release) = releases
        .into_iter()
        .find(|release| release.tag_name.starts_with(RELEASE_TAG_PREFIX))
    {
        return Ok(release);
    }

    let legacy_url = format!("{api_base}/{LEGACY_REPO}/releases/latest");
    fetch_tagged_release(&client, &legacy_url, LEGACY_RELEASES_URL)
        .await?
        .with_context(|| format!("no guest-OS release found; check {RELEASES_URL}"))
}

fn tagged_release_location(
    version: &str,
    release_api_base_url: &str,
) -> Result<(String, String, &'static str)> {
    let version = version
        .trim_start_matches(RELEASE_TAG_PREFIX)
        .trim_start_matches('v');
    let core = numeric_version_core(version)?;
    let (repo, tag_prefix, releases_url) = if core < MONOREPO_GUEST_OS_MIN_VERSION {
        (LEGACY_REPO, "v", LEGACY_RELEASES_URL)
    } else {
        (REPO, RELEASE_TAG_PREFIX, RELEASES_URL)
    };
    Ok((
        version.to_string(),
        format!(
            "{}/{repo}/releases/tags/{tag_prefix}{version}",
            release_api_base_url.trim().trim_end_matches('/')
        ),
        releases_url,
    ))
}

fn numeric_version_core(version: &str) -> Result<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    let minor = parts.next().unwrap_or_default();
    let patch = parts.next().unwrap_or_default();
    let patch = patch.split_once('-').map_or(patch, |(numeric, _)| numeric);
    if major.is_empty()
        || minor.is_empty()
        || patch.is_empty()
        || !major.chars().all(|c| c.is_ascii_digit())
        || !minor.chars().all(|c| c.is_ascii_digit())
        || !patch.chars().all(|c| c.is_ascii_digit())
    {
        bail!("invalid guest-OS version {version:?}; expected MAJOR.MINOR.PATCH");
    }
    Ok((major.parse()?, minor.parse()?, patch.parse()?))
}

async fn fetch_tagged_release(
    client: &reqwest::Client,
    url: &str,
    releases_url: &str,
) -> Result<Option<Release>> {
    let response = client
        .get(url)
        .header("user-agent", "dstackup")
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .context("requesting the github release")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(
        response
            .error_for_status()
            .with_context(|| format!("github release lookup failed; check {releases_url}"))?
            .json()
            .await
            .context("parsing github release json")?,
    ))
}

/// Pick a full bare-metal image tarball, never the `-uki` archive. For a GPU
/// request, prefer a legacy `dstack-nvidia-*` asset when present and otherwise
/// use the current unified image (which already contains conditional NVIDIA
/// support).
fn pick_asset(assets: &[Asset], gpu: bool) -> Option<&Asset> {
    // `-dev` marks the dev *flavour*, which only ever appears as a name prefix
    // (`dstack-dev-*`, `dstack-nvidia-dev-*`). Matching it as a bare substring
    // would also reject release names whose version carries a `-dev` prerelease
    // tag, e.g. `dstack-0.6.1-dev1.tar.gz`.
    let is_dev_flavour =
        |n: &str| n.starts_with("dstack-dev-") || n.starts_with("dstack-nvidia-dev-");
    let matches = |a: &&Asset, want_legacy_gpu: bool| {
        let n = a.name.as_str();
        if !n.ends_with(".tar.gz") || n.ends_with("-uki.tar.gz") || is_dev_flavour(n) {
            return false;
        }
        let is_gpu = n.starts_with("dstack-nvidia-");
        if want_legacy_gpu {
            is_gpu
        } else {
            n.starts_with("dstack-") && !is_gpu
        }
    };

    if gpu {
        assets
            .iter()
            .find(|asset| matches(asset, true))
            .or_else(|| assets.iter().find(|asset| matches(asset, false)))
    } else {
        assets.iter().find(|asset| matches(asset, false))
    }
}

fn extract(tarball: &str, into: &str) -> Result<()> {
    println!("  [..] unpacking...");
    // `tar` already refuses absolute/`..` members; drop owner/perms from the
    // (root-run) extraction so a hostile member set can't carry setuid/ownership.
    let ok = tool("tar")
        .args([
            "-xzf",
            tarball,
            "-C",
            into,
            "--no-same-owner",
            "--no-same-permissions",
        ])
        .status()
        .context("running tar")?
        .success();
    if !ok {
        bail!("failed to unpack {tarball}");
    }
    Ok(())
}

/// subdirectory names directly under `dir`, excluding dot-prefixed entries (our
/// `.partial`/`.staging` scratch, and never a real image name).
fn image_subdirs(dir: &str) -> Vec<String> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect()
}

/// valid local images (a subdir with a `metadata.json`), oldest first so the
/// caller can `.pop()` the newest. "newest" = most recently fetched (mtime),
/// which is the right default after a `pull`.
fn installed_images(image_dir: &str) -> Vec<String> {
    let mut v: Vec<(SystemTime, String)> = image_subdirs(image_dir)
        .into_iter()
        .filter(|d| Path::new(image_dir).join(d).join("metadata.json").exists())
        .map(|d| {
            let mtime = fs::metadata(Path::new(image_dir).join(&d))
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            (mtime, d)
        })
        .collect();
    v.sort_by_key(|(t, _)| *t);
    v.into_iter().map(|(_, n)| n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> Asset {
        Asset {
            name: name.to_string(),
            browser_download_url: format!("https://x/{name}"),
            digest: None,
        }
    }

    #[test]
    fn picks_cpu_and_gpu_skipping_dev() {
        let assets = vec![
            asset("dstack-dev-0.5.11.tar.gz"),
            asset("dstack-0.5.11.tar.gz"),
            asset("dstack-nvidia-dev-0.5.11.tar.gz"),
            asset("dstack-nvidia-0.5.11.tar.gz"),
            asset("checksums.txt"),
        ];
        assert_eq!(
            pick_asset(&assets, false).unwrap().name,
            "dstack-0.5.11.tar.gz"
        );
        assert_eq!(
            pick_asset(&assets, true).unwrap().name,
            "dstack-nvidia-0.5.11.tar.gz"
        );
    }

    #[test]
    fn gpu_pull_falls_back_to_unified_image() {
        let assets = vec![
            asset("dstack-0.6.0-uki.tar.gz"),
            asset("dstack-0.6.0.tar.gz"),
        ];
        assert_eq!(
            pick_asset(&assets, true).unwrap().name,
            "dstack-0.6.0.tar.gz"
        );
    }

    #[test]
    fn dev_flavour_is_matched_by_prefix_not_substring() {
        // `-dev` as a *prerelease tag* is part of the version, not the flavour,
        // so these releases must still be selectable.
        let assets = vec![
            asset("dstack-dev-0.6.1-dev1.tar.gz"),
            asset("dstack-0.6.1-dev1.tar.gz"),
            asset("dstack-nvidia-dev-0.6.1-dev1.tar.gz"),
            asset("dstack-nvidia-0.6.1-dev1.tar.gz"),
        ];
        assert_eq!(
            pick_asset(&assets, false).unwrap().name,
            "dstack-0.6.1-dev1.tar.gz"
        );
        assert_eq!(
            pick_asset(&assets, true).unwrap().name,
            "dstack-nvidia-0.6.1-dev1.tar.gz"
        );
    }

    #[test]
    fn prerelease_versions_are_selectable() {
        for version in ["0.6.1-rc1", "0.6.1.rc1", "0.6.1-beta.2", "0.6.1.a1"] {
            let assets = vec![
                asset(&format!("dstack-{version}-uki.tar.gz")),
                asset(&format!("dstack-{version}.tar.gz")),
            ];
            assert_eq!(
                pick_asset(&assets, false).unwrap().name,
                format!("dstack-{version}.tar.gz"),
                "{version}"
            );
        }
    }

    #[test]
    fn uki_archive_is_never_selected_as_a_host_image() {
        let assets = vec![asset("dstack-nvidia-0.6.0.a2-uki.tar.gz")];
        assert!(pick_asset(&assets, false).is_none());
        assert!(pick_asset(&assets, true).is_none());
    }

    #[test]
    fn routes_pinned_releases_at_the_monorepo_boundary() {
        for version in ["0.5.11", "v0.5.11", "guest-os-v0.5.11"] {
            let (normalized, url, releases_url) =
                tagged_release_location(version, crate::cli::DEFAULT_RELEASE_API_BASE_URL).unwrap();
            assert_eq!(normalized, "0.5.11");
            assert_eq!(
                url,
                "https://api.github.com/repos/Dstack-TEE/meta-dstack/releases/tags/v0.5.11"
            );
            assert_eq!(releases_url, LEGACY_RELEASES_URL);
        }

        for version in ["0.6.0", "0.6.0.a2", "1.0.0"] {
            let (normalized, url, releases_url) =
                tagged_release_location(version, crate::cli::DEFAULT_RELEASE_API_BASE_URL).unwrap();
            assert_eq!(normalized, version);
            assert_eq!(
                url,
                format!("https://api.github.com/repos/Dstack-TEE/dstack/releases/tags/guest-os-v{version}")
            );
            assert_eq!(releases_url, RELEASES_URL);
        }
    }

    #[test]
    fn rejects_versions_without_a_numeric_core() {
        for version in ["0.6", "latest", "0.x.0", "0.6.x"] {
            assert!(
                tagged_release_location(version, crate::cli::DEFAULT_RELEASE_API_BASE_URL).is_err(),
                "{version}"
            );
        }
    }

    #[test]
    fn release_api_base_url_is_configurable_and_trailing_slash_safe() {
        let (_, url, _) =
            tagged_release_location("0.6.0", "  http://127.0.0.1:1234/api/  ").unwrap();
        assert_eq!(
            url,
            "http://127.0.0.1:1234/api/Dstack-TEE/dstack/releases/tags/guest-os-v0.6.0"
        );
    }

    #[test]
    fn messages_mention_the_pull_command() {
        assert!(no_image_message("/d").contains("dstackup image pull"));
        assert!(missing_named_image_message("/d", "x").contains("dstackup image pull"));
    }

    #[test]
    fn rm_rejects_path_escapes() {
        assert!(valid_image_name("dstack-0.5.11"));
        for bad in ["", ".", "..", ".partial", "/etc", "a/b", "..\\x"] {
            assert!(!valid_image_name(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn image_dir_rejects_root_and_relative_paths() {
        for bad in ["/", "images", "/var/lib/../dstack/images"] {
            assert!(
                validate_image_dir(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        validate_image_dir("/var/lib/dstack/images").unwrap();
    }

    #[test]
    fn parses_requested_image_for_pull() {
        let cpu = pull_spec("dstack-0.5.11").unwrap();
        assert_eq!(cpu.version, "0.5.11");
        assert!(!cpu.gpu);

        let gpu = pull_spec("dstack-nvidia-0.5.11").unwrap();
        assert_eq!(gpu.version, "0.5.11");
        assert!(gpu.gpu);

        let bare = pull_spec("v0.5.11").unwrap();
        assert_eq!(bare.version, "0.5.11");
        assert!(!bare.gpu);

        assert!(pull_spec("").is_none());
        assert!(pull_spec("custom-local-image").is_none());
        assert!(pull_spec("dstack-dev-0.5.11").is_none());
        assert!(pull_spec("a/b").is_none());
    }
}
