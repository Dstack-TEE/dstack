// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup image` — fetch, list, and remove guest OS images.
//!
//! Images are published as release tarballs at `Dstack-TEE/meta-dstack`. There
//! are two variants — cpu (`dstack-<ver>`) and gpu (`dstack-nvidia-<ver>`); a
//! single image serves both TDX and SEV-SNP (it ships both firmwares + digests,
//! and the platform selects which at boot). We shell out to `curl`/`tar` to stay
//! dependency-light and match how the rest of the crate calls system tools.

use crate::cli::ImageCmd;
use crate::systemd::tool;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const REPO: &str = "Dstack-TEE/meta-dstack";
pub(crate) const RELEASES_URL: &str = "https://github.com/Dstack-TEE/meta-dstack/releases";

/// default image directory — matches `install`'s `<prefix>/images` default.
pub(crate) fn default_image_dir() -> String {
    "/var/lib/dstack/images".to_string()
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
}

pub(crate) fn cmd_image(cmd: ImageCmd) -> Result<()> {
    match cmd {
        ImageCmd::Pull {
            version,
            gpu,
            image_path,
            force,
        } => pull(
            version.as_deref(),
            gpu,
            &image_path.unwrap_or_else(default_image_dir),
            force,
        ),
        ImageCmd::List { image_path } => list(&image_path.unwrap_or_else(default_image_dir)),
        ImageCmd::Rm { names, image_path } => {
            remove(&names, &image_path.unwrap_or_else(default_image_dir))
        }
    }
}

/// download a guest image from the latest (or a specific) meta-dstack release.
fn pull(version: Option<&str>, gpu: bool, image_dir: &str, force: bool) -> Result<()> {
    println!(
        "dstackup image pull — {} image",
        if gpu { "gpu (nvidia)" } else { "cpu" }
    );
    let release = fetch_release(version)?;
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
        return Ok(());
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
    println!("  [..] release {} -> {}", release.tag_name, asset.name);

    fs::create_dir_all(image_dir).with_context(|| format!("creating {image_dir}"))?;

    // the asset name doesn't always match the unpacked dir (e.g. a `-uki` asset
    // unpacks to the plain version dir), so snapshot the dir set before/after and
    // diff, rather than guessing the name.
    let before = image_subdirs(image_dir);
    let tmp = Path::new(image_dir).join(format!(".{}.partial", asset.name));
    let _ = fs::remove_file(&tmp);
    let dl = download(&asset.browser_download_url, &tmp.to_string_lossy());
    let untar = dl.and_then(|()| extract(&tmp.to_string_lossy(), image_dir));
    let _ = fs::remove_file(&tmp);
    untar?;

    let name = image_subdirs(image_dir)
        .into_iter()
        .find(|d| {
            !before.contains(d) && Path::new(image_dir).join(d).join("metadata.json").exists()
        })
        .unwrap_or(expected);
    let dest = Path::new(image_dir).join(&name);
    if !dest.join("metadata.json").exists() {
        bail!(
            "unpacked {} but found no metadata.json under {} (unexpected tarball layout)",
            asset.name,
            dest.display()
        );
    }
    println!("  [ok] image ready: {name}");
    println!("  deploy with: dstackup install --image {name}   (or: dstack deploy <compose> --image {name})");
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
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\')
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
        if Path::new(image_dir)
            .join(name)
            .join("metadata.json")
            .exists()
        {
            return Ok(Some(name.to_string()));
        }
        bail!("{}", missing_named_image_message(image_dir, name));
    }
    if let Some(newest) = installed_images(image_dir).pop() {
        println!(
            "  [ok] using image {newest} (newest in {image_dir}; pass --image to pick another)"
        );
        return Ok(Some(newest));
    }
    if require {
        bail!("{}", no_image_message(image_dir));
    }
    println!("  [!]  no guest image in {image_dir} — `dstack deploy` will need one (`dstackup image pull`)");
    Ok(None)
}

/// the friendly "no image — here's how to get one" message.
pub(crate) fn no_image_message(image_dir: &str) -> String {
    format!(
        "no guest image found in {image_dir}\n\n\
         download the latest with:\n    \
         dstackup image pull            # cpu image\n    \
         dstackup image pull --gpu      # gpu (nvidia) image\n\n\
         or a specific version:\n    \
         dstackup image pull --version 0.5.11\n\n\
         images are published at {RELEASES_URL}"
    )
}

fn missing_named_image_message(image_dir: &str, name: &str) -> String {
    format!(
        "image '{name}' not found in {image_dir}\n\n\
         download it with:\n    \
         dstackup image pull --version <version>\n\n\
         or see what's available locally:\n    \
         dstackup image list"
    )
}

/// GET the latest (or a tagged) release JSON from the github api via curl.
fn fetch_release(version: Option<&str>) -> Result<Release> {
    let url = match version {
        Some(v) => format!(
            "https://api.github.com/repos/{REPO}/releases/tags/v{}",
            v.trim_start_matches('v')
        ),
        None => format!("https://api.github.com/repos/{REPO}/releases/latest"),
    };
    let out = tool("curl")
        .args([
            "-fsSL",
            "-H",
            "user-agent: dstackup",
            "-H",
            "accept: application/vnd.github+json",
            &url,
        ])
        .output()
        .context("running curl (is it installed?)")?;
    if !out.status.success() {
        bail!(
            "github release lookup failed: {}. check the version exists at {RELEASES_URL}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("parsing github release json")
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

fn download(url: &str, dest: &str) -> Result<()> {
    println!("  [..] downloading (this can take a minute)...");
    let ok = tool("curl")
        .args(["-fL", "--progress-bar", "--retry", "3", "-o", dest, url])
        .status()
        .context("running curl")?
        .success();
    if !ok {
        bail!("download failed from {url}");
    }
    Ok(())
}

fn extract(tarball: &str, into: &str) -> Result<()> {
    println!("  [..] unpacking...");
    let ok = tool("tar")
        .args(["-xzf", tarball, "-C", into])
        .status()
        .context("running tar")?
        .success();
    if !ok {
        bail!("failed to unpack {tarball}");
    }
    Ok(())
}

/// subdirectory names directly under `dir` (no validation).
fn image_subdirs(dir: &str) -> Vec<String> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
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
        for bad in ["", ".", "..", "/etc", "a/b", "..\\x"] {
            assert!(!valid_image_name(bad), "{bad:?} should be rejected");
        }
    }
}
