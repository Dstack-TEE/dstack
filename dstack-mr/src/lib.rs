// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

pub use dstack_types::OvmfVariant;
pub use machine::{Machine, TdxMeasurementDetails};

use util::{measure_log, measure_sha384, utf16_encode};

pub type RtmrLog = Vec<Vec<u8>>;
pub type RtmrLogs = [RtmrLog; 3];

mod acpi;
mod kernel;
mod machine;
mod num;
mod tdvf;
mod util;

/// Pick the OVMF variant for a given dstack OS version string ("MAJOR.MINOR.PATCH").
///
/// Treats `0.5.10 <= v < 0.6.0` and `v >= 0.6.1` as `Stable202505`, everything else as
/// `Pre202505`. Used as a fallback when `VmConfig::ovmf_variant` is absent.
pub fn ovmf_variant_for_version(version: &str) -> Result<OvmfVariant> {
    let parts: Vec<u32> = version
        .split('.')
        .map(|p| {
            p.parse::<u32>()
                .with_context(|| format!("invalid version component: {p}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() != 3 {
        bail!("expected MAJOR.MINOR.PATCH, got {version}");
    }
    let v = (parts[0], parts[1], parts[2]);
    let stable = ((0, 5, 10)..(0, 6, 0)).contains(&v) || v >= (0, 6, 1);
    Ok(if stable {
        OvmfVariant::Stable202505
    } else {
        OvmfVariant::Pre202505
    })
}

/// Extract the `MAJOR.MINOR.PATCH` version suffix from a dstack image name.
///
/// Recognises any `<prefix>-MAJOR.MINOR.PATCH[.SUFFIX]` shape, e.g.
/// `dstack-0.5.10`, `dstack-dev-0.5.10`, `dstack-nvidia-0.5.10`,
/// `dstack-nvidia-dev-0.5.10`, `dstack-0.5.10.rc1`, `dstack-dev-0.6.1.dev`.
///
/// The optional `.SUFFIX` is permitted to be non-numeric (pre-release tag,
/// build label, etc.) and is dropped from the returned slice — only the
/// numeric `X.Y.Z` is needed to pick the OVMF variant.
///
/// Returns `None` when the segment after the last `-` is not at least a valid
/// `X.Y.Z` triple of non-empty numeric components.
pub fn extract_version_from_image_name(image: &str) -> Option<&str> {
    let tail = image.rsplit('-').next()?;
    let parts: Vec<&str> = tail.split('.').collect();
    if !(3..=4).contains(&parts.len()) {
        return None;
    }
    let core_numeric = parts[..3]
        .iter()
        .all(|p| !p.is_empty() && p.parse::<u32>().is_ok());
    let suffix_ok = parts.len() == 3 || !parts[3].is_empty();
    if !(core_numeric && suffix_ok) {
        return None;
    }
    // Slice off the optional `.SUFFIX` so callers get just `X.Y.Z`.
    let core_len = parts[0].len() + 1 + parts[1].len() + 1 + parts[2].len();
    Some(&tail[..core_len])
}

/// Pick the OVMF variant from an image name like `dstack-0.5.10`.
///
/// Falls back to `OvmfVariant::default()` (= `Pre202505`) when the image name is
/// missing or doesn't carry a parseable version suffix. Use this only as a
/// fallback for images that pre-date `VmConfig::ovmf_variant`.
pub fn ovmf_variant_for_image(image: Option<&str>) -> OvmfVariant {
    image
        .and_then(extract_version_from_image_name)
        .and_then(|v| ovmf_variant_for_version(v).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod ovmf_variant_tests {
    use super::*;

    #[test]
    fn pre_202505_for_old_versions() {
        for v in ["0.4.99", "0.5.7", "0.5.8", "0.5.9", "0.6.0"] {
            assert_eq!(
                ovmf_variant_for_version(v).unwrap(),
                OvmfVariant::Pre202505,
                "{v}"
            );
        }
    }

    #[test]
    fn stable_202505_for_new_versions() {
        for v in ["0.5.10", "0.5.99", "0.6.1", "0.6.2", "0.7.0", "1.0.0"] {
            assert_eq!(
                ovmf_variant_for_version(v).unwrap(),
                OvmfVariant::Stable202505,
                "{v}"
            );
        }
    }

    #[test]
    fn rejects_malformed_version() {
        assert!(ovmf_variant_for_version("0.5").is_err());
        assert!(ovmf_variant_for_version("0.5.10-dev").is_err());
        assert!(ovmf_variant_for_version("v0.5.10").is_err());
    }

    #[test]
    fn parses_version_from_image_name() {
        // Three-segment plain versions across the known prefix shapes.
        assert_eq!(
            extract_version_from_image_name("dstack-0.5.10"),
            Some("0.5.10")
        );
        assert_eq!(
            extract_version_from_image_name("dstack-dev-0.5.10"),
            Some("0.5.10")
        );
        assert_eq!(
            extract_version_from_image_name("dstack-nvidia-0.5.10"),
            Some("0.5.10")
        );
        assert_eq!(
            extract_version_from_image_name("dstack-nvidia-dev-0.6.1"),
            Some("0.6.1")
        );
        // Optional .SUFFIX is allowed and dropped; suffix may be non-numeric.
        assert_eq!(
            extract_version_from_image_name("dstack-0.5.10.rc1"),
            Some("0.5.10")
        );
        assert_eq!(
            extract_version_from_image_name("dstack-dev-0.6.1.dev"),
            Some("0.6.1")
        );
        assert_eq!(
            extract_version_from_image_name("dstack-nvidia-dev-0.5.10.1"),
            Some("0.5.10")
        );
        // Rejections.
        assert_eq!(extract_version_from_image_name("dstack"), None);
        assert_eq!(extract_version_from_image_name("dstack-rc1"), None);
        assert_eq!(extract_version_from_image_name("dstack-0.5"), None);
        assert_eq!(extract_version_from_image_name("dstack-0.5.10."), None);
        assert_eq!(extract_version_from_image_name("dstack-0.5.10.1.2"), None);
        assert_eq!(extract_version_from_image_name("dstack-0..10"), None);
        assert_eq!(extract_version_from_image_name("dstack-a.b.c"), None);
    }

    #[test]
    fn ovmf_variant_for_image_handles_missing_and_unknown() {
        assert_eq!(ovmf_variant_for_image(None), OvmfVariant::Pre202505);
        assert_eq!(
            ovmf_variant_for_image(Some("dstack")),
            OvmfVariant::Pre202505
        );
        assert_eq!(
            ovmf_variant_for_image(Some("dstack-0.5.9")),
            OvmfVariant::Pre202505
        );
        assert_eq!(
            ovmf_variant_for_image(Some("dstack-0.5.10")),
            OvmfVariant::Stable202505
        );
        assert_eq!(
            ovmf_variant_for_image(Some("dstack-nvidia-dev-0.6.1")),
            OvmfVariant::Stable202505
        );
    }

    #[test]
    fn serializes_with_snake_case() {
        assert_eq!(
            serde_json::to_string(&OvmfVariant::Pre202505).unwrap(),
            "\"pre202505\""
        );
        assert_eq!(
            serde_json::to_string(&OvmfVariant::Stable202505).unwrap(),
            "\"stable202505\""
        );
        assert_eq!(
            serde_json::from_str::<OvmfVariant>("\"stable202505\"").unwrap(),
            OvmfVariant::Stable202505
        );
    }
}

/// Contains all the measurement values for TDX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxMeasurements {
    #[serde(with = "hex_bytes")]
    pub mrtd: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr2: Vec<u8>,
}
