// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use fs_err as fs;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::acme_client::Credentials;

#[derive(Debug, Clone)]
pub struct WorkDir {
    workdir: PathBuf,
}

impl WorkDir {
    pub fn new(workdir: impl AsRef<Path>) -> Self {
        Self {
            workdir: workdir.as_ref().to_path_buf(),
        }
    }

    pub fn workdir(&self) -> &PathBuf {
        &self.workdir
    }

    pub fn account_credentials_path(&self) -> PathBuf {
        self.workdir.join("credentials.json")
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.workdir.join("backup")
    }

    pub fn live_dir(&self) -> PathBuf {
        self.workdir.join("live")
    }

    pub fn cert_path(&self) -> PathBuf {
        self.live_dir().join("cert.pem")
    }

    pub fn key_path(&self) -> PathBuf {
        self.live_dir().join("key.pem")
    }

    pub fn list_certs(&self) -> Result<Vec<PathBuf>> {
        crate::bot::list_certs(self.backup_dir())
    }

    pub fn acme_account_uri(&self) -> Result<String> {
        let encoded_credentials = fs::read_to_string(self.account_credentials_path())?;
        let credentials: Credentials = serde_json::from_str(&encoded_credentials)?;
        Ok(credentials.account_id)
    }

    pub fn acme_account_quote_path(&self) -> PathBuf {
        self.workdir.join("acme-account.quote")
    }

    pub fn list_cert_public_keys(&self) -> Result<BTreeSet<Vec<u8>>> {
        crate::bot::list_cert_public_keys(self.backup_dir())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_workdir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dstack-certbot-workdir-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn paths_and_archive_listing_are_stable() -> Result<()> {
        let root = temp_workdir();
        let workdir = WorkDir::new(&root);
        fs::create_dir_all(workdir.backup_dir().join("2026-07-29T11:00:02Z"))?;
        fs::create_dir_all(workdir.backup_dir().join("2026-07-29T11:00:01Z"))?;
        fs::write(
            workdir.backup_dir().join("2026-07-29T11:00:02Z/cert.pem"),
            "new",
        )?;
        fs::write(
            workdir.backup_dir().join("2026-07-29T11:00:01Z/cert.pem"),
            "old",
        )?;
        fs::create_dir_all(workdir.backup_dir().join("incomplete"))?;
        fs::write(workdir.backup_dir().join("not-a-generation"), "ignored")?;

        assert_eq!(
            workdir.account_credentials_path(),
            root.join("credentials.json")
        );
        assert_eq!(
            workdir.acme_account_quote_path(),
            root.join("acme-account.quote")
        );
        assert_eq!(workdir.cert_path(), root.join("live/cert.pem"));
        assert_eq!(workdir.key_path(), root.join("live/key.pem"));
        assert_eq!(
            workdir.list_certs()?,
            vec![
                root.join("backup/2026-07-29T11:00:01Z/cert.pem"),
                root.join("backup/2026-07-29T11:00:02Z/cert.pem"),
            ]
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn live_links_can_roll_back_to_a_complete_generation() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = temp_workdir();
        let workdir = WorkDir::new(&root);
        let old = workdir.backup_dir().join("2026-07-29T11:00:01Z");
        let new = workdir.backup_dir().join("2026-07-29T11:00:02Z");
        for (generation, marker) in [(&old, "old"), (&new, "new")] {
            fs::create_dir_all(generation)?;
            fs::write(generation.join("cert.pem"), format!("{marker}-cert"))?;
            fs::write(generation.join("key.pem"), format!("{marker}-key"))?;
        }
        fs::create_dir_all(workdir.live_dir())?;
        symlink(new.join("cert.pem"), workdir.cert_path())?;
        symlink(new.join("key.pem"), workdir.key_path())?;
        assert_eq!(fs::read_to_string(workdir.cert_path())?, "new-cert");
        fs::remove_file(workdir.cert_path())?;
        fs::remove_file(workdir.key_path())?;
        symlink(old.join("cert.pem"), workdir.cert_path())?;
        symlink(old.join("key.pem"), workdir.key_path())?;
        assert_eq!(fs::read_to_string(workdir.cert_path())?, "old-cert");
        assert_eq!(fs::read_to_string(workdir.key_path())?, "old-key");
        assert_eq!(workdir.list_certs()?.len(), 2);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn malformed_credentials_fail_without_mutating_the_archive() -> Result<()> {
        let root = temp_workdir();
        let workdir = WorkDir::new(&root);
        fs::create_dir_all(workdir.backup_dir().join("generation"))?;
        fs::write(workdir.backup_dir().join("generation/cert.pem"), "sentinel")?;
        fs::write(workdir.account_credentials_path(), "{not-json")?;
        assert!(workdir.acme_account_uri().is_err());
        assert_eq!(
            fs::read_to_string(workdir.backup_dir().join("generation/cert.pem"))?,
            "sentinel"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
