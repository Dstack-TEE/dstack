// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Traits for the crate

use anyhow::{Context, Result};
use dstack_attest::attestation::AppInfo;

use crate::oids::{PHALA_RATLS_APP_ID, PHALA_RATLS_APP_INFO, PHALA_RATLS_CERT_USAGE};

/// Types that can get custom cert extensions from.
pub trait CertExt {
    /// Get a cert extension from the type.
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>>;

    /// Get externtion bytes
    #[errify::errify("Failed to get extension for {oid:?}")]
    fn get_extension_bytes(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let Some(der) = self.get_extension_der(oid)? else {
            return Ok(None);
        };
        let ext = yasna::parse_der(&der, |reader| reader.read_bytes())?;
        Ok(Some(ext))
    }

    /// Get Certificate Special Usage from the type.
    fn get_special_usage(&self) -> Result<Option<String>> {
        let Some(found) = self.get_extension_bytes(PHALA_RATLS_CERT_USAGE)? else {
            return Ok(None);
        };
        let found = String::from_utf8(found).context("Failed to decode special usage as utf8")?;
        Ok(Some(found))
    }

    /// Get the app id from the certificate
    fn get_app_id(&self) -> Result<Option<Vec<u8>>> {
        self.get_extension_bytes(PHALA_RATLS_APP_ID)
    }

    /// Get app info
    fn get_app_info(&self) -> Result<Option<AppInfo>> {
        let Some(app_info_bytes) = self.get_extension_bytes(PHALA_RATLS_APP_INFO)? else {
            return Ok(None);
        };
        let app_info =
            rmp_serde::from_slice(&app_info_bytes).context("Failed to decode app info as json")?;
        Ok(app_info)
    }
}
