// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Filesystem layout shared by `dstackup` and the local `dstack` client.

use anyhow::{bail, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_BIN_DIR: &str = "/usr/local/bin";
pub const DEFAULT_LIBEXEC_DIR: &str = "/usr/local/libexec/dstack";
pub const DEFAULT_SHARE_DIR: &str = "/usr/local/share/dstack";
pub const DEFAULT_CONFIG_DIR: &str = "/etc/dstack";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/dstack";
pub const DEFAULT_CACHE_DIR: &str = "/var/cache/dstack";
pub const DEFAULT_RUN_DIR: &str = "/run/dstack";
pub const STATE_FILE: &str = "dstackup-state.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallLayout {
    /// Explicit installation root supplied through `--prefix`.
    ///
    /// `None` means the default system-wide FHS layout is in use.
    pub root: Option<PathBuf>,
    pub bin_dir: PathBuf,
    pub libexec_dir: PathBuf,
    pub share_dir: PathBuf,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl InstallLayout {
    pub fn new(prefix: Option<&str>) -> Self {
        match prefix {
            Some(prefix) => {
                let root = PathBuf::from(prefix);
                Self {
                    root: Some(root.clone()),
                    bin_dir: root.join("bin"),
                    libexec_dir: root.join("libexec/dstack"),
                    share_dir: root.join("share/dstack"),
                    config_dir: root.join("etc/dstack"),
                    state_dir: root.join("var/lib/dstack"),
                    cache_dir: root.join("var/cache/dstack"),
                    run_dir: root.join("run/dstack"),
                }
            }
            None => Self {
                root: None,
                bin_dir: PathBuf::from(DEFAULT_BIN_DIR),
                libexec_dir: PathBuf::from(DEFAULT_LIBEXEC_DIR),
                share_dir: PathBuf::from(DEFAULT_SHARE_DIR),
                config_dir: PathBuf::from(DEFAULT_CONFIG_DIR),
                state_dir: PathBuf::from(DEFAULT_STATE_DIR),
                cache_dir: PathBuf::from(DEFAULT_CACHE_DIR),
                run_dir: PathBuf::from(DEFAULT_RUN_DIR),
            },
        }
    }

    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join(STATE_FILE)
    }

    pub fn image_dir(&self) -> PathBuf {
        self.state_dir.join("images")
    }

    pub fn source_dir(&self) -> PathBuf {
        self.cache_dir.join("source")
    }

    pub fn cargo_target_dir(&self) -> PathBuf {
        self.cache_dir.join("target")
    }

    pub fn key_provider_dir(&self) -> PathBuf {
        self.share_dir.join("key-provider-build")
    }

    pub fn hello_nginx_compose(&self) -> PathBuf {
        self.share_dir
            .join("examples/hello-nginx/docker-compose.yaml")
    }

    pub fn state_path_for_prefix(prefix: Option<&str>) -> PathBuf {
        Self::new(prefix).state_path()
    }

    pub fn image_dir_for_prefix(prefix: Option<&str>) -> PathBuf {
        Self::new(prefix).image_dir()
    }

    pub fn is_default(&self) -> bool {
        self.root.is_none()
    }

    pub fn all_dirs_absolute(&self) -> bool {
        [
            &self.bin_dir,
            &self.libexec_dir,
            &self.share_dir,
            &self.config_dir,
            &self.state_dir,
            &self.cache_dir,
            &self.run_dir,
        ]
        .into_iter()
        .all(|path| path.is_absolute())
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(root) = &self.root {
            validate_install_prefix(root)?;
        }
        for (name, path) in [
            ("bin dir", &self.bin_dir),
            ("libexec dir", &self.libexec_dir),
            ("share dir", &self.share_dir),
            ("config dir", &self.config_dir),
            ("state dir", &self.state_dir),
            ("cache dir", &self.cache_dir),
            ("run dir", &self.run_dir),
        ] {
            validate_owned_dir(name, path)?;
        }
        Ok(())
    }
}

pub fn path_string(path: &Path) -> String {
    path.display().to_string()
}

pub fn validate_install_prefix(prefix: &Path) -> Result<()> {
    validate_absolute_path("--prefix", prefix)?;
    validate_no_dot_segments("--prefix", prefix)?;
    Ok(())
}

pub fn validate_owned_path(name: &str, path: &Path) -> Result<()> {
    validate_owned_dir(name, path)
}

fn validate_owned_dir(name: &str, path: &Path) -> Result<()> {
    validate_absolute_path(name, path)?;
    validate_no_dot_segments(name, path)?;
    Ok(())
}

fn validate_no_dot_segments(name: &str, path: &Path) -> Result<()> {
    for segment in path.as_os_str().as_bytes().split(|byte| *byte == b'/') {
        if segment == b"." || segment == b".." {
            bail!("{name} must not contain . or .. path components");
        }
    }
    Ok(())
}

fn validate_absolute_path(name: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("{name} must be an absolute path");
    }
    if path == Path::new("/") {
        bail!("{name} must not be /");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layout_uses_system_paths() {
        let layout = InstallLayout::new(None);
        assert_eq!(layout.bin_dir, PathBuf::from("/usr/local/bin"));
        assert_eq!(
            layout.libexec_dir,
            PathBuf::from("/usr/local/libexec/dstack")
        );
        assert_eq!(layout.share_dir, PathBuf::from("/usr/local/share/dstack"));
        assert_eq!(layout.config_dir, PathBuf::from("/etc/dstack"));
        assert_eq!(layout.state_dir, PathBuf::from("/var/lib/dstack"));
        assert_eq!(layout.cache_dir, PathBuf::from("/var/cache/dstack"));
        assert_eq!(layout.run_dir, PathBuf::from("/run/dstack"));
        assert_eq!(
            layout.state_path(),
            PathBuf::from("/var/lib/dstack/dstackup-state.json")
        );
    }

    #[test]
    fn prefix_layout_is_self_contained() {
        let layout = InstallLayout::new(Some("/opt/dstack-a"));
        assert_eq!(layout.bin_dir, PathBuf::from("/opt/dstack-a/bin"));
        assert_eq!(
            layout.libexec_dir,
            PathBuf::from("/opt/dstack-a/libexec/dstack")
        );
        assert_eq!(
            layout.share_dir,
            PathBuf::from("/opt/dstack-a/share/dstack")
        );
        assert_eq!(layout.config_dir, PathBuf::from("/opt/dstack-a/etc/dstack"));
        assert_eq!(
            layout.state_dir,
            PathBuf::from("/opt/dstack-a/var/lib/dstack")
        );
        assert_eq!(
            layout.cache_dir,
            PathBuf::from("/opt/dstack-a/var/cache/dstack")
        );
        assert_eq!(layout.run_dir, PathBuf::from("/opt/dstack-a/run/dstack"));
    }

    #[test]
    fn prefix_validation_rejects_root_and_parent_components() {
        for bad in ["relative", "/", "/opt/../dstack", "/opt/./dstack"] {
            assert!(
                validate_install_prefix(Path::new(bad)).is_err(),
                "{bad:?} should be rejected"
            );
        }
        validate_install_prefix(Path::new("/opt/dstack-a")).unwrap();
    }

    #[test]
    fn layout_validation_rejects_root_owned_dirs() {
        let mut layout = InstallLayout::new(Some("/opt/dstack-a"));
        layout.share_dir = PathBuf::from("/");
        assert!(layout.validate().is_err());
    }
}
