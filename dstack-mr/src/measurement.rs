// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Unified build-time OS-image measurement document.

use anyhow::{Context, Result};
use dstack_types::{
    OsImageMeasurementDocument, SevOsImageMeasurementDocument, TdxOsImageMeasurementDocument,
};
use fs_err as fs;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ImageMetadata {
    #[serde(default, rename = "bios-sev")]
    bios_sev: Option<String>,
}

/// Generate `measurement.json` for an image directory.
///
/// TDX material is mandatory for the normal dstack image. SNP material is
/// included when metadata declares a dedicated `bios-sev` firmware.
pub fn os_image_measurement_document_for_image_dir(
    image_dir: &Path,
) -> Result<OsImageMeasurementDocument> {
    let meta_path = image_dir.join("metadata.json");
    let meta_str = fs::read_to_string(&meta_path)
        .with_context(|| format!("cannot read {}", meta_path.display()))?;
    let meta: ImageMetadata =
        serde_json::from_str(&meta_str).context("failed to parse image metadata.json")?;

    let tdx = TdxOsImageMeasurementDocument::new(
        crate::tdx::tdx_os_image_measurement_for_image_dir(image_dir)
            .context("failed to build TDX measurement document")?,
    );

    let snp = if meta.bios_sev.is_some() {
        Some(SevOsImageMeasurementDocument::new(
            crate::sev::sev_os_image_measurement_for_image_dir(image_dir)
                .context("failed to build SNP measurement document")?,
        ))
    } else {
        None
    };

    Ok(OsImageMeasurementDocument::new(Some(tdx), snp))
}
