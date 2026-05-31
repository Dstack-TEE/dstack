// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Integration test to verify TDVF firmware parsing correctness
//!
//! This test ensures that the scale codec-based parsing produces
//! identical measurements to the original implementation.
//!
//! The test downloads a real dstack release from GitHub and verifies
//! that the measurements remain consistent with the baseline.

use anyhow::{Context, Result};
use dstack_mr::Machine;
use std::path::PathBuf;

// dstack release to download for testing
const DSTACK_VERSION: &str = "v0.5.5";
const DSTACK_RELEASE_URL: &str =
    "https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.5/dstack-0.5.5.tar.gz";

// Expected measurements from baseline (verified with original implementation)
// These are the measurements for dstack v0.5.5 with default configuration
// Generated with: dstack-mr measure /path/to/dstack-0.5.5/metadata.json --json
const EXPECTED_MRTD: &str = "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077";
const EXPECTED_RTMR0: &str = "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96";
const EXPECTED_RTMR1: &str = "daa9380dc33b14728a9adb222437cf14db2d40ffc4d7061d8f3c329f6c6b339f71486d33521287e8faeae22301f4d815";
const EXPECTED_RTMR2: &str = "1c41080c9c74be158e55b92f2958129fc1265647324c4a0dc403292cfa41d4c529f39093900347a11c8c1b82ed8c5edf";

/// Download and extract dstack release tarball if not already cached
fn get_test_image_dir() -> Result<PathBuf> {
    let cache_dir = std::env::temp_dir().join("dstack-mr-test-cache");
    let version_dir = cache_dir.join(DSTACK_VERSION);
    let image_dir = version_dir.join("dstack-0.5.5");
    let metadata_path = image_dir.join("metadata.json");

    // Return cached version if it exists
    if metadata_path.exists() {
        return Ok(image_dir);
    }

    eprintln!("Downloading dstack {DSTACK_VERSION} release for testing...",);
    std::fs::create_dir_all(&version_dir)?;

    // Download tarball
    let tarball_path = version_dir.join("dstack.tar.gz");
    let response =
        reqwest::blocking::get(DSTACK_RELEASE_URL).context("failed to download dstack release")?;

    if !response.status().is_success() {
        anyhow::bail!("failed to download: HTTP {}", response.status());
    }

    let bytes = response.bytes().context("failed to read response")?;
    std::fs::write(&tarball_path, bytes).context("failed to write tarball")?;

    eprintln!("Extracting tarball...");

    // Extract tarball
    let tarball = std::fs::File::open(&tarball_path)?;
    let decoder = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(&version_dir)
        .context("failed to extract tarball")?;

    // Verify extraction
    if !metadata_path.exists() {
        anyhow::bail!("metadata.json not found after extraction");
    }

    eprintln!("Test image ready at: {}", image_dir.display());

    Ok(image_dir)
}

#[test]
#[ignore] // Run with: cargo test --release -- --ignored
fn test_tdvf_parse_produces_correct_measurements() -> Result<()> {
    // Get or download test image
    let image_dir = get_test_image_dir()?;
    let metadata_path = image_dir.join("metadata.json");

    let metadata = std::fs::read_to_string(&metadata_path)
        .with_context(|| format!("failed to read {}", metadata_path.display()))?;
    let image_info: dstack_types::ImageInfo = serde_json::from_str(&metadata)?;

    let firmware_path = image_dir.join(&image_info.bios).display().to_string();
    let kernel_path = image_dir.join(&image_info.kernel).display().to_string();
    let initrd_path = image_dir.join(&image_info.initrd).display().to_string();
    let cmdline = image_info.cmdline + " initrd=initrd";

    eprintln!("Building machine configuration...");
    let machine = Machine::builder()
        .cpu_count(1)
        .memory_size(2 * 1024 * 1024 * 1024) // 2GB
        .firmware(&firmware_path)
        .kernel(&kernel_path)
        .initrd(&initrd_path)
        .kernel_cmdline(&cmdline)
        .two_pass_add_pages(true)
        .pic(true)
        .smm(false)
        .hugepages(false)
        .num_gpus(0)
        .num_nvswitches(0)
        .hotplug_off(false)
        .root_verity(true)
        .build();

    eprintln!("Computing measurements (this parses TDVF firmware)...");
    let measurements = machine.measure()?;

    eprintln!("Verifying measurements against baseline...");

    // Verify measurements match expected values
    assert_eq!(
        hex::encode(&measurements.mrtd),
        EXPECTED_MRTD,
        "MRTD mismatch - TDVF parsing may have regressed"
    );
    assert_eq!(
        hex::encode(&measurements.rtmr0),
        EXPECTED_RTMR0,
        "RTMR0 mismatch - TDVF parsing may have regressed"
    );
    assert_eq!(
        hex::encode(&measurements.rtmr1),
        EXPECTED_RTMR1,
        "RTMR1 mismatch - TDVF parsing may have regressed"
    );
    assert_eq!(
        hex::encode(&measurements.rtmr2),
        EXPECTED_RTMR2,
        "RTMR2 mismatch - TDVF parsing may have regressed"
    );

    eprintln!("✅ All measurements match baseline - TDVF parsing is correct!");

    Ok(())
}
