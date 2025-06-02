use fs_err as fs;
use path_absolutize::Absolutize;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub cmdline: Option<String>,
    pub kernel: String,
    pub initrd: String,
    pub hda: Option<String>,
    pub rootfs: Option<String>,
    pub bios: Option<String>,
    #[serde(default)]
    pub rootfs_hash: Option<String>,
    #[serde(default)]
    pub shared_ro: bool,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub is_dev: bool,
}

impl ImageInfo {
    pub fn version_tuple(&self) -> Option<(u16, u16, u16)> {
        let version = self
            .version
            .split('.')
            .take(3)
            .map(|v| v.parse::<u16>())
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if version.len() < 3 {
            return None;
        }
        Some((version[0], version[1], version[2]))
    }
}

impl ImageInfo {
    pub fn load(filename: impl AsRef<Path>) -> Result<Self> {
        let file = fs::File::open(filename.as_ref()).context("failed to open image info")?;
        let info: ImageInfo =
            serde_json::from_reader(file).context("failed to parse image info")?;
        Ok(info)
    }
}

#[derive(Debug)]
pub struct Image {
    pub info: ImageInfo,
    pub initrd: PathBuf,
    pub kernel: PathBuf,
    pub hda: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub bios: Option<PathBuf>,
    pub digest: Option<String>,
}

impl Image {
    pub fn load(base_path: impl AsRef<Path>) -> Result<Self> {
        let base_path = base_path.as_ref().absolutize()?;
        let mut info = ImageInfo::load(base_path.join("metadata.json"))?;
        let initrd = base_path.join(&info.initrd);
        let kernel = base_path.join(&info.kernel);
        let hda = info.hda.as_ref().map(|hda| base_path.join(hda));
        let rootfs = info.rootfs.as_ref().map(|rootfs| base_path.join(rootfs));
        let bios = info.bios.as_ref().map(|bios| base_path.join(bios));
        let digest = fs::read_to_string(base_path.join("digest.txt"))
            .ok()
            .map(|s| s.trim().to_string());
        if info.version.is_empty() {
            // Older images does not have version field. Fallback to the version of the image folder name
            info.version = guess_version(&base_path).unwrap_or_default();
        }
        Self {
            info,
            hda,
            initrd,
            kernel,
            rootfs,
            bios,
            digest,
        }
        .ensure_exists()
    }

    fn ensure_exists(self) -> Result<Self> {
        if !self.initrd.exists() {
            bail!("Initrd does not exist: {}", self.initrd.display());
        }
        if !self.kernel.exists() {
            bail!("Kernel does not exist: {}", self.kernel.display());
        }
        if let Some(hda) = &self.hda {
            if !hda.exists() {
                bail!("Hda does not exist: {}", hda.display());
            }
        }
        if let Some(rootfs) = &self.rootfs {
            if !rootfs.exists() {
                bail!("Rootfs does not exist: {}", rootfs.display());
            }
        }
        if let Some(bios) = &self.bios {
            if !bios.exists() {
                bail!("Bios does not exist: {}", bios.display());
            }
        }
        Ok(self)
    }
}

fn guess_version(base_path: &Path) -> Option<String> {
    // name pattern: dstack-dev-0.2.3 or dstack-0.2.3
    let basename = base_path.file_name()?.to_str()?.to_string();
    let version = if basename.starts_with("dstack-dev-") {
        basename.strip_prefix("dstack-dev-")?
    } else if basename.starts_with("dstack-") {
        basename.strip_prefix("dstack-")?
    } else {
        return None;
    };
    Some(version.to_string())
}
