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
