// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Compatibility helpers for build-time OS-image measurement documents.

use anyhow::{Context, Result};
use dstack_types::{
    OsImageMeasurementDocument, SevOsImageMeasurementDocument, TdxOsImageMeasurementDocument,
    SNP_MEASUREMENT_FILENAME, TDX_MEASUREMENT_FILENAME,
};
use fs_err as fs;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ImageMetadata {
    #[serde(default, rename = "bios-sev")]
    bios_sev: Option<String>,
}

/// Generate a compatibility `measurement.json` for an image directory that has
/// already produced `sha256sum.txt` plus split measurement CBOR files.
///
/// New image builds should ship `measurement.tdx.cbor` / `measurement.snp.cbor`
/// directly instead of this combined JSON document.
pub fn os_image_measurement_document_for_image_dir(
    image_dir: &Path,
) -> Result<OsImageMeasurementDocument> {
    let meta_path = image_dir.join("metadata.json");
    let meta_str = fs::read_to_string(&meta_path)
        .with_context(|| format!("cannot read {}", meta_path.display()))?;
    let meta: ImageMetadata =
        serde_json::from_str(&meta_str).context("failed to parse image metadata.json")?;
    let sha256sum_path = image_dir.join("sha256sum.txt");
    let sha256sum = fs::read(&sha256sum_path)
        .with_context(|| format!("cannot read {}", sha256sum_path.display()))?;

    let tdx_path = image_dir.join(TDX_MEASUREMENT_FILENAME);
    let tdx = if tdx_path.exists() {
        Some(TdxOsImageMeasurementDocument::new(
            sha256sum.clone(),
            fs::read(&tdx_path).with_context(|| format!("cannot read {}", tdx_path.display()))?,
        ))
    } else {
        None
    };

    let snp = if meta.bios_sev.is_some() {
        let snp_path = image_dir.join(SNP_MEASUREMENT_FILENAME);
        Some(SevOsImageMeasurementDocument::new(
            sha256sum,
            fs::read(&snp_path).with_context(|| format!("cannot read {}", snp_path.display()))?,
        ))
    } else {
        None
    };

    Ok(OsImageMeasurementDocument::new(tdx, snp))
}
