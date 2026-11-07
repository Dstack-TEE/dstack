// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Deliver a local Docker image through an authenticated, read-only volume.

use std::{fs, path::Path, process::Stdio};

use anyhow::{bail, Context, Result};
use dstack_cli_core::config::{KmsImage, DEV_KMS_MOUNT};
use dstack_types::VerityVolume;
use dstack_volume::{Compression, VerityOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::systemd::tool;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LocalImage {
    id: String,
    os: String,
    architecture: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SavedImage {
    config: String,
    repo_tags: Option<Vec<String>>,
    layers: Vec<String>,
}

fn archive_file(root: &Path, name: &str) -> Result<std::path::PathBuf> {
    let path = root.join(name).canonicalize()?;
    if !path.starts_with(root) || !path.is_file() {
        bail!("invalid file in Docker image archive: {name:?}");
    }
    Ok(path)
}

/// Emit the standard Docker archive files with a content-addressed local tag.
/// Docker's classic and containerd stores expose different image IDs, so a
/// config hash in the archive's RepoTags is the portable runtime reference.
fn prepare_archive(export: &Path, output: &Path) -> Result<String> {
    let export = export.canonicalize()?;
    let [mut image]: [SavedImage; 1] =
        serde_json::from_slice(&fs::read(export.join("manifest.json"))?)
            .context("dev-kms requires a single-image Docker archive")?;
    let config = fs::read(archive_file(&export, &image.config)?)?;
    let digest = format!("{:x}", Sha256::digest(&config));
    let image_ref = format!("dstack-dev-kms:{digest}");
    fs::create_dir(output)?;
    image.config = format!("{digest}.json");
    fs::write(output.join(&image.config), config)?;
    for (index, layer) in image.layers.iter_mut().enumerate() {
        let source = archive_file(&export, layer)?;
        *layer = format!("{index}/layer.tar");
        fs::create_dir(output.join(index.to_string()))?;
        fs::hard_link(source, output.join(&layer))?;
    }
    image.repo_tags = Some(vec![image_ref.clone()]);
    fs::write(output.join("manifest.json"), serde_json::to_vec(&[image])?)?;
    Ok(image_ref)
}

fn read_image(bytes: &[u8]) -> Result<LocalImage> {
    let [image]: [LocalImage; 1] =
        serde_json::from_slice(bytes).context("invalid Docker image inspection response")?;
    let digest = image
        .id
        .strip_prefix("sha256:")
        .context("invalid Docker image id")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid Docker image id");
    }
    if image.os != "linux" || image.architecture != "amd64" {
        bail!("dev-kms requires a linux/amd64 image");
    }
    Ok(image)
}

pub(crate) async fn package(tag: &str, volumes_dir: &Path) -> Result<KmsImage> {
    let inspected = tool("docker")
        .args(["image", "inspect", "--", tag])
        .output()
        .context("failed to inspect local dev-kms image")?;
    if !inspected.status.success() {
        bail!("local dev-kms image {tag:?} is unavailable; build and tag it before installing");
    }
    let image = read_image(&inspected.stdout)?;
    fs::create_dir_all(volumes_dir).context("failed to create dev-kms volume directory")?;
    let scratch = tempfile::tempdir_in(volumes_dir)?;
    let export_dir = scratch.path().join("export");
    fs::create_dir(&export_dir)?;
    // Save by immutable ID so a concurrent retag cannot change the selected image.
    let mut export = tool("docker")
        .args(["image", "save", &image.id])
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to export dev-kms image")?;
    let output = export
        .stdout
        .take()
        .context("missing Docker export output")?;
    // Store the archive's filesystem contents. Docker save generates transient
    // tar directory timestamps; the existing volume format normalizes metadata.
    let unpacked = tar::Archive::new(output).unpack(&export_dir);
    let status = export
        .wait()
        .context("failed to wait for Docker image export")?;
    unpacked.context("failed to unpack dev-kms image export")?;
    if !status.success() {
        bail!("failed to export dev-kms image: {status}");
    }
    let contents = scratch.path().join("image");
    let image_ref = prepare_archive(&export_dir, &contents)?;
    let output = scratch.path().join("volume.img");
    let built = dstack_volume::verity(VerityOptions {
        dir: Some(contents),
        fs_image: None,
        output: output.clone(),
        compress: Compression::Zstd,
    })
    .await?;
    let source = format!("dev-kms-{}.img", built.verity_root);
    fs::File::open(&output)?.sync_all()?;
    fs::rename(output, volumes_dir.join(&source)).context("failed to install dev-kms volume")?;
    fs::File::open(volumes_dir)?.sync_all()?;
    println!("  [ok] packaged dev-kms {tag} ({})", image.id);
    Ok(KmsImage::Dev {
        image_ref,
        volume: VerityVolume {
            source,
            verity_root: hex::decode(built.verity_root)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid dev-kms verity root"))?,
            target: DEV_KMS_MOUNT.into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_reference_is_bound_to_the_config_and_preserves_layers() {
        let scratch = tempfile::tempdir().unwrap();
        let export = scratch.path().join("export");
        let output = scratch.path().join("image");
        fs::create_dir(&export).unwrap();
        let config = b"{\"architecture\":\"amd64\",\"os\":\"linux\"}";
        fs::write(export.join("config.json"), config).unwrap();
        fs::write(export.join("layer.tar"), b"unchanged layer bytes").unwrap();
        fs::write(
            export.join("manifest.json"),
            serde_json::to_vec(&[SavedImage {
                config: "config.json".into(),
                repo_tags: None,
                layers: vec!["layer.tar".into()],
            }])
            .unwrap(),
        )
        .unwrap();
        let image_ref = prepare_archive(&export, &output).unwrap();
        assert_eq!(
            image_ref,
            format!("dstack-dev-kms:{:x}", Sha256::digest(config))
        );
        let [saved]: [SavedImage; 1] =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(saved.repo_tags.unwrap(), [image_ref]);
        assert_eq!(fs::read(output.join(saved.config)).unwrap(), config);
        assert_eq!(
            fs::read(output.join(&saved.layers[0])).unwrap(),
            b"unchanged layer bytes"
        );
        assert!(archive_file(&export.canonicalize().unwrap(), "../image/manifest.json").is_err());
    }

    #[test]
    fn requires_one_linux_amd64_image_with_a_content_id() {
        let image = serde_json::json!({
            "Id": format!("sha256:{}", "12".repeat(32)),
            "Os": "linux", "Architecture": "amd64"
        });
        let encode = |image| serde_json::to_vec(&serde_json::json!([image])).unwrap();
        assert!(read_image(&encode(image.clone())).is_ok());
        for (key, value) in [
            ("Id", "local-tag"),
            ("Id", "sha256:abcd"),
            ("Architecture", "arm64"),
            ("Os", "windows"),
        ] {
            let mut invalid = image.clone();
            invalid[key] = value.into();
            assert!(read_image(&encode(invalid)).is_err());
        }
        assert!(read_image(b"[]").is_err());
        assert!(read_image(&serde_json::to_vec(&[&image, &image]).unwrap()).is_err());
    }
}
