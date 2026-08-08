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
    use std::os::unix::fs::symlink;

    #[test]
    fn paths_and_archive_listing_are_stable() {
        let root = tempfile::tempdir().unwrap();
        let workdir = WorkDir::new(root.path());
        assert_eq!(
            workdir.account_credentials_path(),
            root.path().join("credentials.json")
        );
        assert_eq!(workdir.backup_dir(), root.path().join("backup"));
        assert_eq!(workdir.cert_path(), root.path().join("live/cert.pem"));
        assert_eq!(workdir.key_path(), root.path().join("live/key.pem"));
        fs::create_dir_all(workdir.backup_dir().join("0002")).unwrap();
        fs::create_dir_all(workdir.backup_dir().join("0001")).unwrap();
        fs::write(workdir.backup_dir().join("0002/cert.pem"), "second").unwrap();
        fs::write(workdir.backup_dir().join("0001/cert.pem"), "first").unwrap();
        assert_eq!(
            workdir.list_certs().unwrap(),
            vec![
                workdir.backup_dir().join("0001/cert.pem"),
                workdir.backup_dir().join("0002/cert.pem"),
            ]
        );
    }

    #[test]
    fn live_links_can_roll_back_to_a_complete_generation() {
        let root = tempfile::tempdir().unwrap();
        let workdir = WorkDir::new(root.path());
        let first = workdir.backup_dir().join("0001");
        let second = workdir.backup_dir().join("0002");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("cert.pem"), "first-cert").unwrap();
        fs::write(first.join("key.pem"), "first-key").unwrap();
        fs::write(second.join("cert.pem"), "second-cert").unwrap();
        fs::write(second.join("key.pem"), "second-key").unwrap();
        fs::create_dir_all(workdir.live_dir()).unwrap();
        symlink(second.join("cert.pem"), workdir.cert_path()).unwrap();
        symlink(second.join("key.pem"), workdir.key_path()).unwrap();
        fs::remove_file(workdir.cert_path()).unwrap();
        fs::remove_file(workdir.key_path()).unwrap();
        symlink(first.join("cert.pem"), workdir.cert_path()).unwrap();
        symlink(first.join("key.pem"), workdir.key_path()).unwrap();
        assert_eq!(
            fs::read_to_string(workdir.cert_path()).unwrap(),
            "first-cert"
        );
        assert_eq!(fs::read_to_string(workdir.key_path()).unwrap(), "first-key");
    }

    #[test]
    fn malformed_credentials_fail_without_mutating_the_archive() {
        let root = tempfile::tempdir().unwrap();
        let workdir = WorkDir::new(root.path());
        let archive = workdir.backup_dir().join("0001");
        fs::create_dir_all(&archive).unwrap();
        fs::write(archive.join("cert.pem"), "stable").unwrap();
        fs::write(workdir.account_credentials_path(), "not-json").unwrap();
        assert!(workdir.acme_account_uri().is_err());
        assert_eq!(
            fs::read_to_string(archive.join("cert.pem")).unwrap(),
            "stable"
        );
    }
}
