// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup image` — fetch, list, and remove guest OS images.
//!
//! Images are published as release tarballs at `Dstack-TEE/meta-dstack`. There
//! are two variants — cpu (`dstack-<ver>`) and gpu (`dstack-nvidia-<ver>`).
//! `install` validates the selected image against the platform-specific digest
//! it needs before starting the host stack: TDX uses `digest.txt`, and
//! SEV-SNP uses `digest.sev.txt`. HTTP + checksum are native (reqwest is
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

const REPO: &str = "Dstack-TEE/meta-dstack";
pub(crate) const RELEASES_URL: &str = "https://github.com/Dstack-TEE/meta-dstack/releases";

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

pub(crate) async fn cmd_image(cmd: ImageCmd) -> Result<()> {
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
            pull(version.as_deref(), gpu, &image_dir, force, insecure).await?;
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

/// download a guest image from the latest (or a specific) meta-dstack release.
pub(crate) async fn pull(
    version: Option<&str>,
    gpu: bool,
    image_dir: &str,
    force: bool,
    insecure: bool,
) -> Result<String> {
    println!(
        "dstackup image pull — {} image",
        if gpu { "gpu (nvidia)" } else { "cpu" }
    );
    let release = fetch_release(version).await?;
    let ver = release.tag_name.trim_start_matches('v');

    // the unpacked dir is usually `dstack[-nvidia]-<ver>`; check that first so a
    // repeat pull is a cheap no-op instead of re-fetching a few hundred MB.
    let expected = format!("dstack-{}{ver}", if gpu { "nvidia-" } else { "" });
    if !force
        && Path::new(image_dir)
            .join(&expected)
            .join("metadata.json")
            .exists()
    {
        println!("  [ok] {expected} already present (use --force to re-download)");
        return Ok(expected);
    }

    let asset = pick_asset(&release.assets, gpu).with_context(|| {
        format!(
            "no {} image tarball in meta-dstack release {} (assets: {})",
            if gpu { "gpu" } else { "cpu" },
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
    // the unpacked dir name needn't match the asset name (e.g. a `-uki` asset),
    // so find the dir that actually holds a metadata.json.
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
    required_digest: Option<&str>,
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
        if let Some(spec) = pull_spec(name) {
            println!("  [..] image {name} not found locally; downloading it");
            let pulled = pull(Some(&spec.version), spec.gpu, image_dir, false, false).await?;
            return Ok(Some(pulled));
        }
        return resolve_image(image_dir, Some(name), require);
    }

    let mut imgs = installed_images(image_dir);
    let skipped = retain_images_with_digest(&mut imgs, image_dir, required_digest);
    if let Some(newest) = imgs.pop() {
        if !skipped.is_empty() {
            println!(
                "  [!]  ignoring image(s) without {}: {}",
                required_digest.unwrap_or("required digest"),
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
        if let Some(digest) = required_digest {
            if skipped.is_empty() {
                println!("  [!]  no guest image in {image_dir} with {digest} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)");
            } else {
                println!(
                    "  [!]  no guest image in {image_dir} with {digest}; ignored {} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)",
                    skipped.join(", ")
                );
            }
        } else {
            println!("  [!]  no guest image in {image_dir} - `dstack deploy -c <compose>` will need one (`dstackup image pull`)");
        }
        return Ok(None);
    }

    if let Some(digest) = required_digest {
        if skipped.is_empty() {
            println!(
                "  [..] no local guest image with {digest} found; downloading the latest cpu image"
            );
        } else {
            println!(
                "  [..] no local guest image with {digest} found (ignored {}); downloading the latest cpu image",
                skipped.join(", ")
            );
        }
    } else {
        println!("  [..] no local guest image found; downloading the latest cpu image");
    }
    let pulled = pull(None, false, image_dir, false, false).await?;

    if Path::new(image_dir)
        .join(&pulled)
        .join("metadata.json")
        .exists()
    {
        Ok(Some(pulled))
    } else {
        bail!("downloaded image {pulled}, but it is not available in {image_dir}")
    }
}

fn retain_images_with_digest(
    imgs: &mut Vec<String>,
    image_dir: &str,
    required_digest: Option<&str>,
) -> Vec<String> {
    let Some(required_digest) = required_digest else {
        return Vec::new();
    };
    let mut skipped = Vec::new();
    imgs.retain(|name| {
        let has_digest = Path::new(image_dir)
            .join(name)
            .join(required_digest)
            .is_file();
        if !has_digest {
            skipped.push(name.clone());
        }
        has_digest
    });
    skipped
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
         {pull}            # cpu image\n    \
         {pull} --gpu      # gpu (nvidia) image\n\n\
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

/// GET the latest (or a tagged) release JSON from the github api.
async fn fetch_release(version: Option<&str>) -> Result<Release> {
    let url = match version {
        Some(v) => format!(
            "https://api.github.com/repos/{REPO}/releases/tags/v{}",
            v.trim_start_matches('v')
        ),
        None => format!("https://api.github.com/repos/{REPO}/releases/latest"),
    };
    reqwest::Client::new()
        .get(&url)
        .header("user-agent", "dstackup")
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .context("requesting the github release")?
        .error_for_status()
        .with_context(|| {
            format!("github release lookup failed; check the version exists at {RELEASES_URL}")
        })?
        .json()
        .await
        .context("parsing github release json")
}

/// pick the cpu or gpu image tarball from a release's assets, skipping `-dev`
/// builds. cpu = `dstack-<ver>...`, gpu = `dstack-nvidia-<ver>...`.
fn pick_asset(assets: &[Asset], gpu: bool) -> Option<&Asset> {
    assets.iter().find(|a| {
        let n = a.name.as_str();
        if !n.ends_with(".tar.gz") || n.contains("-dev") {
            return false;
        }
        let is_gpu = n.starts_with("dstack-nvidia-");
        if gpu {
            is_gpu
        } else {
            n.starts_with("dstack-") && !is_gpu
        }
    })
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
    fn gpu_only_release_has_no_cpu_asset() {
        let assets = vec![asset("dstack-nvidia-0.6.0.a2-uki.tar.gz")];
        assert!(pick_asset(&assets, false).is_none());
        assert_eq!(
            pick_asset(&assets, true).unwrap().name,
            "dstack-nvidia-0.6.0.a2-uki.tar.gz"
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
