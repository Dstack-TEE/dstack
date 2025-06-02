//! Traits for the crate

use anyhow::{Context, Result};

use crate::oids::{PHALA_RATLS_APP_ID, PHALA_RATLS_CERT_USAGE};

/// Types that can get custom cert extensions from.
pub trait CertExt {
    /// Get a cert extension from the type.
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>>;
    /// Get externtion bytes
    fn get_extension_bytes(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let Some(der) = self.get_extension_der(oid)? else {
            return Ok(None);
        };
        let ext = yasna::parse_der(&der, |reader| reader.read_bytes())?;
        Ok(Some(ext))
    }

    /// Get Certificate Special Usage from the type.
    fn get_special_usage(&self) -> Result<Option<String>> {
        let Some(found) = self
            .get_extension_bytes(PHALA_RATLS_CERT_USAGE)
            .context("Failed to get extension")?
        else {
            return Ok(None);
        };
        let found = String::from_utf8(found).context("Failed to decode special usage as utf8")?;
        Ok(Some(found))
    }

    /// Get the app id from the certificate
    fn get_app_id(&self) -> Result<Option<Vec<u8>>> {
        let app_id = self
            .get_extension_bytes(PHALA_RATLS_APP_ID)
            .context("Failed to get extension")?;
        Ok(app_id)
    }
}
