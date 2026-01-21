// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::TdxEvent;
use dstack_mr::{RtmrLog, TdxMeasurementDetails, TdxMeasurements};
use dstack_types::VmConfig;
use ra_tls::attestation::{
    Attestation, AttestationQuote, VerifiedAttestation, VersionedAttestation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::{debug, info, warn};

use crate::types::{
    AcpiTables, RtmrEventEntry, RtmrEventStatus, RtmrMismatch, VerificationDetails,
    VerificationRequest, VerificationResponse,
};

fn collect_rtmr_mismatch(
    rtmr_label: &str,
    expected: &[u8],
    actual: &[u8],
    expected_sequence: &RtmrLog,
    actual_indices: &[usize],
    event_log: &[TdxEvent],
) -> RtmrMismatch {
    let expected_hex = hex::encode(expected);
    let actual_hex = hex::encode(actual);

    let mut events = Vec::new();

    for (&idx, expected_digest) in actual_indices.iter().zip(expected_sequence.iter()) {
        match event_log.get(idx) {
            Some(event) => {
                let event_name = if event.event.is_empty() {
                    "(unnamed)".to_string()
                } else {
                    event.event.clone()
                };
                let status = if event.digest() == expected_digest.as_slice() {
                    RtmrEventStatus::Match
                } else {
                    RtmrEventStatus::Mismatch
                };
                events.push(RtmrEventEntry {
                    index: idx,
                    event_type: event.event_type,
                    event_name,
                    actual_digest: hex::encode(event.digest()),
                    expected_digest: Some(hex::encode(expected_digest)),
                    payload_len: event.event_payload.len(),
                    status,
                });
            }
            None => {
                events.push(RtmrEventEntry {
                    index: idx,
                    event_type: 0,
                    event_name: "(missing)".to_string(),
                    actual_digest: String::new(),
                    expected_digest: Some(hex::encode(expected_digest)),
                    payload_len: 0,
                    status: RtmrEventStatus::Missing,
                });
            }
        }
    }

    for &idx in actual_indices.iter().skip(expected_sequence.len()) {
        let (event_type, event_name, actual_digest, payload_len) = match event_log.get(idx) {
            Some(event) => (
                event.event_type,
                if event.event.is_empty() {
                    "(unnamed)".to_string()
                } else {
                    event.event.clone()
                },
                hex::encode(event.digest()),
                event.event_payload.len(),
            ),
            None => (0, "(missing)".to_string(), String::new(), 0),
        };
        events.push(RtmrEventEntry {
            index: idx,
            event_type,
            event_name,
            actual_digest,
            expected_digest: None,
            payload_len,
            status: RtmrEventStatus::Extra,
        });
    }

    let missing_expected_digests = if expected_sequence.len() > actual_indices.len() {
        expected_sequence[actual_indices.len()..]
            .iter()
            .map(hex::encode)
            .collect()
    } else {
        Vec::new()
    };

    RtmrMismatch {
        rtmr: rtmr_label.to_string(),
        expected: expected_hex.to_string(),
        actual: actual_hex.to_string(),
        events,
        missing_expected_digests,
    }
}

const MEASUREMENT_CACHE_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
struct CachedMeasurement {
    version: u32,
    measurements: TdxMeasurements,
}

struct ImagePaths {
    fw_path: PathBuf,
    kernel_path: PathBuf,
    initrd_path: PathBuf,
    kernel_cmdline: String,
}

pub struct CvmVerifier {
    pub image_cache_dir: String,
    pub download_url: String,
    pub download_timeout: Duration,
    pub pccs_url: Option<String>,
}

impl CvmVerifier {
    pub fn new(
        image_cache_dir: String,
        download_url: String,
        download_timeout: Duration,
        pccs_url: Option<String>,
    ) -> Self {
        Self {
            image_cache_dir,
            download_url,
            download_timeout,
            pccs_url,
        }
    }

    fn measurement_cache_dir(&self) -> PathBuf {
        Path::new(&self.image_cache_dir).join("measurements")
    }

    fn measurement_cache_path(&self, cache_key: &str) -> PathBuf {
        self.measurement_cache_dir()
            .join(format!("{cache_key}.json"))
    }

    fn vm_config_cache_key(vm_config: &VmConfig) -> Result<String> {
        let serialized = serde_json::to_vec(vm_config)
            .context("Failed to serialize VM config for cache key computation")?;
        Ok(hex::encode(Sha256::digest(&serialized)))
    }

    fn load_measurements_from_cache(&self, cache_key: &str) -> Result<Option<TdxMeasurements>> {
        let path = self.measurement_cache_path(cache_key);
        if !path.exists() {
            return Ok(None);
        }

        let path_display = path.display().to_string();
        let contents = match fs_err::read(&path) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to read measurement cache {}: {e:?}", path_display);
                return Ok(None);
            }
        };

        let cached: CachedMeasurement = match serde_json::from_slice(&contents) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Failed to parse measurement cache {}: {e:?}", path_display);
                return Ok(None);
            }
        };

        if cached.version != MEASUREMENT_CACHE_VERSION {
            debug!(
                "Ignoring measurement cache {} due to version mismatch (found {}, expected {})",
                path_display, cached.version, MEASUREMENT_CACHE_VERSION
            );
            return Ok(None);
        }

        debug!("Loaded measurement cache entry {}", cache_key);
        Ok(Some(cached.measurements))
    }

    fn store_measurements_in_cache(
        &self,
        cache_key: &str,
        measurements: &TdxMeasurements,
    ) -> Result<()> {
        let cache_dir = self.measurement_cache_dir();
        fs_err::create_dir_all(&cache_dir)
            .context("Failed to create measurement cache directory")?;

        let path = self.measurement_cache_path(cache_key);
        let mut tmp = tempfile::NamedTempFile::new_in(&cache_dir)
            .context("Failed to create temporary cache file")?;

        let entry = CachedMeasurement {
            version: MEASUREMENT_CACHE_VERSION,
            measurements: measurements.clone(),
        };
        serde_json::to_writer(tmp.as_file_mut(), &entry)
            .context("Failed to serialize measurement cache entry")?;
        tmp.as_file_mut()
            .sync_all()
            .context("Failed to flush measurement cache entry to disk")?;

        tmp.persist(&path).map_err(|e| {
            anyhow!(
                "Failed to persist measurement cache to {}: {e}",
                path.display()
            )
        })?;
        debug!("Stored measurement cache entry {}", cache_key);
        Ok(())
    }

    fn compute_measurement_details(
        &self,
        vm_config: &VmConfig,
        fw_path: &Path,
        kernel_path: &Path,
        initrd_path: &Path,
        kernel_cmdline: &str,
    ) -> Result<TdxMeasurementDetails> {
        let firmware = fw_path.display().to_string();
        let kernel = kernel_path.display().to_string();
        let initrd = initrd_path.display().to_string();

        let details = dstack_mr::Machine::builder()
            .cpu_count(vm_config.cpu_count)
            .memory_size(vm_config.memory_size)
            .firmware(&firmware)
            .kernel(&kernel)
            .initrd(&initrd)
            .kernel_cmdline(kernel_cmdline)
            .root_verity(true)
            .hotplug_off(vm_config.hotplug_off)
            .maybe_two_pass_add_pages(vm_config.qemu_single_pass_add_pages)
            .maybe_pic(vm_config.pic)
            .maybe_qemu_version(vm_config.qemu_version.clone())
            .maybe_pci_hole64_size(if vm_config.pci_hole64_size > 0 {
                Some(vm_config.pci_hole64_size)
            } else {
                None
            })
            .hugepages(vm_config.hugepages)
            .num_gpus(vm_config.num_gpus)
            .num_nvswitches(vm_config.num_nvswitches)
            .host_share_mode(vm_config.host_share_mode.clone())
            .build()
            .measure_with_logs()
            .context("Failed to compute expected MRs")?;

        Ok(details)
    }

    fn compute_measurements(
        &self,
        vm_config: &VmConfig,
        fw_path: &Path,
        kernel_path: &Path,
        initrd_path: &Path,
        kernel_cmdline: &str,
    ) -> Result<TdxMeasurements> {
        self.compute_measurement_details(
            vm_config,
            fw_path,
            kernel_path,
            initrd_path,
            kernel_cmdline,
        )
        .map(|details| details.measurements)
    }

    fn load_or_compute_measurements(
        &self,
        vm_config: &VmConfig,
        fw_path: &Path,
        kernel_path: &Path,
        initrd_path: &Path,
        kernel_cmdline: &str,
    ) -> Result<TdxMeasurements> {
        let cache_key = Self::vm_config_cache_key(vm_config)?;

        if let Some(measurements) = self.load_measurements_from_cache(&cache_key)? {
            return Ok(measurements);
        }

        let measurements = self.compute_measurements(
            vm_config,
            fw_path,
            kernel_path,
            initrd_path,
            kernel_cmdline,
        )?;

        if let Err(e) = self.store_measurements_in_cache(&cache_key, &measurements) {
            warn!(
                "Failed to write measurement cache entry for {}: {e:?}",
                cache_key
            );
        }

        Ok(measurements)
    }

    /// Helper method to ensure image is downloaded and return image paths
    async fn ensure_image_downloaded(&self, vm_config: &VmConfig) -> Result<ImagePaths> {
        let hex_os_image_hash = hex::encode(&vm_config.os_image_hash);

        // Get image directory
        let image_dir = Path::new(&self.image_cache_dir)
            .join("images")
            .join(&hex_os_image_hash);

        let metadata_path = image_dir.join("metadata.json");
        if !metadata_path.exists() {
            info!("Image {hex_os_image_hash} not found, downloading");
            tokio::time::timeout(
                self.download_timeout,
                self.download_image(&hex_os_image_hash, &image_dir),
            )
            .await
            .context("Download image timeout")?
            .with_context(|| format!("Failed to download image {hex_os_image_hash}"))?;
        }

        let image_info =
            fs_err::read_to_string(metadata_path).context("Failed to read image metadata")?;
        let image_info: dstack_types::ImageInfo =
            serde_json::from_str(&image_info).context("Failed to parse image metadata")?;

        let fw_path = image_dir.join(&image_info.bios);
        let kernel_path = image_dir.join(&image_info.kernel);
        let initrd_path = image_dir.join(&image_info.initrd);
        let kernel_cmdline = image_info.cmdline + " initrd=initrd";

        Ok(ImagePaths {
            fw_path,
            kernel_path,
            initrd_path,
            kernel_cmdline,
        })
    }

    /// Compute expected TDX measurements for a given VM configuration.
    ///
    /// This method downloads the OS image if needed (using the configured cache),
    /// then computes the expected MRTD and RTMRs based on the VM configuration.
    /// Results are cached automatically.
    pub async fn compute_measurements_for_config(
        &self,
        vm_config: &VmConfig,
    ) -> Result<TdxMeasurements> {
        let image_paths = self.ensure_image_downloaded(vm_config).await?;

        self.load_or_compute_measurements(
            vm_config,
            &image_paths.fw_path,
            &image_paths.kernel_path,
            &image_paths.initrd_path,
            &image_paths.kernel_cmdline,
        )
    }

    pub async fn verify(&self, request: VerificationRequest) -> Result<VerificationResponse> {
        let attestation = if let Some(attestation) = &request.attestation {
            VersionedAttestation::from_scale(attestation).context("Failed to decode attestaion")?
        } else if let Some(tdx_quote) = request.quote {
            let event_log = request
                .event_log
                .as_ref()
                .context("Event log is required")?;
            Attestation::from_tdx_quote(tdx_quote, event_log.as_bytes())
                .context("Failed to create attestation")?
                .into_versioned()
        } else {
            bail!("Quote is required");
        };
        let mut details = VerificationDetails {
            quote_verified: false,
            event_log_verified: false,
            os_image_hash_verified: false,
            report_data: None,
            tcb_status: None,
            advisory_ids: vec![],
            app_info: None,
            acpi_tables: None,
            rtmr_debug: None,
        };

        let attestation = attestation.into_inner();
        let debug = request.debug.unwrap_or(false);
        let verified = attestation.verify(self.pccs_url.as_deref()).await;
        let verified_attestation = match verified {
            Ok(att) => {
                details.quote_verified = true;
                details.tcb_status = att.report.tdx_report().map(|r| r.status.clone());
                details.advisory_ids = att
                    .report
                    .tdx_report()
                    .map(|r| r.advisory_ids.clone())
                    .unwrap_or_default();
                details.report_data = Some(hex::encode(att.report_data));
                att
            }
            Err(e) => {
                return Ok(VerificationResponse {
                    is_valid: false,
                    details,
                    reason: Some(format!("Quote verification failed: {e:#}")),
                });
            }
        };
        // Step 3: Verify os-image-hash matches using dstack-mr
        let verified = self
            .verify_os_image_hash(
                request.vm_config.clone().unwrap_or_default(),
                &verified_attestation,
                debug,
                &mut details,
            )
            .await;
        let vm_config = match verified {
            Ok(vm_config) => vm_config,
            Err(e) => {
                return Ok(VerificationResponse {
                    is_valid: false,
                    details,
                    reason: Some(format!("OS image hash verification failed: {e:#}")),
                });
            }
        };
        details.os_image_hash_verified = true;
        match verified_attestation.decode_app_info(false) {
            Ok(mut info) => {
                info.os_image_hash = vm_config.os_image_hash;
                details.event_log_verified = true;
                details.app_info = Some(info);
            }
            Err(e) => {
                return Ok(VerificationResponse {
                    is_valid: false,
                    details,
                    reason: Some(format!("Event log verification failed: {}", e)),
                });
            }
        };

        Ok(VerificationResponse {
            is_valid: true,
            details,
            reason: None,
        })
    }

    pub async fn verify_os_image_hash(
        &self,
        vm_config: String,
        attestation: &VerifiedAttestation,
        debug: bool,
        details: &mut VerificationDetails,
    ) -> Result<VmConfig> {
        let vm_config = attestation
            .decode_vm_config(&vm_config)
            .context("Failed to decode VM config")?;
        match &attestation.quote {
            AttestationQuote::DstackTdx(_) => {
                self.verify_os_image_hash_for_dstack_tdx(&vm_config, attestation, debug, details)
                    .await?;
            }
            AttestationQuote::DstackGcpTdx | AttestationQuote::DstackNitroEnclave => {
                bail!(
                    "Unsupported attestation quote: {:?}",
                    attestation.quote.mode()
                );
            }
        }
        Ok(vm_config)
    }

    async fn verify_os_image_hash_for_dstack_tdx(
        &self,
        vm_config: &VmConfig,
        attestation: &VerifiedAttestation,
        debug: bool,
        details: &mut VerificationDetails,
    ) -> Result<()> {
        let Some(report) = &attestation.report.tdx_report() else {
            bail!("No TDX report");
        };
        let Some(tdx_quote) = attestation.tdx_quote() else {
            bail!("No TDX quote");
        };
        let event_log = &tdx_quote.event_log;
        // Get boot info from attestation
        let report = report
            .report
            .as_td10()
            .context("Failed to decode TD report")?;

        // Extract the verified MRs from the report
        let verified_mrs = Mrs {
            mrtd: report.mr_td.to_vec(),
            rtmr0: report.rt_mr0.to_vec(),
            rtmr1: report.rt_mr1.to_vec(),
            rtmr2: report.rt_mr2.to_vec(),
        };

        // Compute expected measurements (reusing the public API)
        let (mrs, expected_logs) = if debug {
            // For debug mode, we need detailed logs and ACPI tables
            let image_paths = self.ensure_image_downloaded(vm_config).await?;

            let TdxMeasurementDetails {
                measurements,
                rtmr_logs,
                acpi_tables,
            } = self
                .compute_measurement_details(
                    vm_config,
                    &image_paths.fw_path,
                    &image_paths.kernel_path,
                    &image_paths.initrd_path,
                    &image_paths.kernel_cmdline,
                )
                .context("Failed to compute expected measurements")?;

            details.acpi_tables = Some(AcpiTables {
                tables: hex::encode(&acpi_tables.tables),
                rsdp: hex::encode(&acpi_tables.rsdp),
                loader: hex::encode(&acpi_tables.loader),
            });

            (measurements, Some(rtmr_logs))
        } else {
            // For non-debug mode, reuse the public API with caching
            (
                self.compute_measurements_for_config(vm_config)
                    .await
                    .context("Failed to compute expected measurements")?,
                None,
            )
        };

        let expected_mrs = Mrs {
            mrtd: mrs.mrtd.clone(),
            rtmr0: mrs.rtmr0.clone(),
            rtmr1: mrs.rtmr1.clone(),
            rtmr2: mrs.rtmr2.clone(),
        };

        match expected_mrs.assert_eq(&verified_mrs) {
            Ok(()) => Ok(()),
            Err(e) => {
                let result = Err(e).context("MRs do not match");
                if !debug {
                    return result;
                }
                let Some(expected_logs) = expected_logs.as_ref() else {
                    return result;
                };
                let mut rtmr_debug = Vec::new();

                if expected_mrs.rtmr0 != verified_mrs.rtmr0 {
                    rtmr_debug.push(collect_rtmr_mismatch(
                        "RTMR0",
                        &expected_mrs.rtmr0,
                        &verified_mrs.rtmr0,
                        &expected_logs[0],
                        &[],
                        event_log,
                    ));
                }

                if expected_mrs.rtmr1 != verified_mrs.rtmr1 {
                    rtmr_debug.push(collect_rtmr_mismatch(
                        "RTMR1",
                        &expected_mrs.rtmr1,
                        &verified_mrs.rtmr1,
                        &expected_logs[1],
                        &[],
                        event_log,
                    ));
                }

                if expected_mrs.rtmr2 != verified_mrs.rtmr2 {
                    rtmr_debug.push(collect_rtmr_mismatch(
                        "RTMR2",
                        &expected_mrs.rtmr2,
                        &verified_mrs.rtmr2,
                        &expected_logs[2],
                        &[],
                        event_log,
                    ));
                }

                if !rtmr_debug.is_empty() {
                    details.rtmr_debug = Some(rtmr_debug);
                }

                result
            }
        }
    }

    pub async fn download_image(&self, hex_os_image_hash: &str, dst_dir: &Path) -> Result<()> {
        let url = self
            .download_url
            .replace("{OS_IMAGE_HASH}", hex_os_image_hash);

        // Create a temporary directory for extraction within the cache directory
        let cache_dir = Path::new(&self.image_cache_dir).join("images").join("tmp");
        fs_err::create_dir_all(&cache_dir).context("Failed to create cache directory")?;
        let auto_delete_temp_dir = tempfile::Builder::new()
            .prefix("tmp-download-")
            .tempdir_in(&cache_dir)
            .context("Failed to create temporary directory")?;
        let tmp_dir = auto_delete_temp_dir.path();

        info!("Downloading image from {}", url);
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to download image")?;

        if !response.status().is_success() {
            bail!(
                "Failed to download image: HTTP status {}, url: {url}",
                response.status(),
            );
        }

        // Save the tarball to a temporary file using streaming
        let tarball_path = tmp_dir.join("image.tar.gz");
        let mut file = tokio::fs::File::create(&tarball_path)
            .await
            .context("Failed to create tarball file")?;
        let mut response = response;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk)
                .await
                .context("Failed to write chunk to file")?;
        }

        let extracted_dir = tmp_dir.join("extracted");
        fs_err::create_dir_all(&extracted_dir).context("Failed to create extraction directory")?;

        // Extract the tarball
        let output = Command::new("tar")
            .arg("xzf")
            .arg(&tarball_path)
            .current_dir(&extracted_dir)
            .output()
            .await
            .context("Failed to extract tarball")?;

        if !output.status.success() {
            bail!(
                "Failed to extract tarball: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Verify checksum
        let output = Command::new("sha256sum")
            .arg("-c")
            .arg("sha256sum.txt")
            .current_dir(&extracted_dir)
            .output()
            .await
            .context("Failed to verify checksum")?;

        if !output.status.success() {
            bail!(
                "Checksum verification failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Remove the files that are not listed in sha256sum.txt
        let sha256sum_path = extracted_dir.join("sha256sum.txt");
        let files_doc =
            fs_err::read_to_string(&sha256sum_path).context("Failed to read sha256sum.txt")?;
        let listed_files: Vec<&OsStr> = files_doc
            .lines()
            .flat_map(|line| line.split_whitespace().nth(1))
            .map(|s| s.as_ref())
            .collect();
        let files = fs_err::read_dir(&extracted_dir).context("Failed to read directory")?;
        for file in files {
            let file = file.context("Failed to read directory entry")?;
            let filename = file.file_name();
            if !listed_files.contains(&filename.as_os_str()) {
                if file.path().is_dir() {
                    fs_err::remove_dir_all(file.path()).context("Failed to remove directory")?;
                } else {
                    fs_err::remove_file(file.path()).context("Failed to remove file")?;
                }
            }
        }

        // os_image_hash should eq to sha256sum of the sha256sum.txt
        let os_image_hash = Sha256::new_with_prefix(files_doc.as_bytes()).finalize();
        if hex::encode(os_image_hash) != hex_os_image_hash {
            bail!("os_image_hash does not match sha256sum of the sha256sum.txt");
        }

        // Move the extracted files to the destination directory
        let metadata_path = extracted_dir.join("metadata.json");
        if !metadata_path.exists() {
            bail!("metadata.json not found in the extracted archive");
        }

        if dst_dir.exists() {
            fs_err::remove_dir_all(dst_dir).context("Failed to remove destination directory")?;
        }
        let dst_dir_parent = dst_dir.parent().context("Failed to get parent directory")?;
        fs_err::create_dir_all(dst_dir_parent).context("Failed to create parent directory")?;
        // Move the extracted files to the destination directory
        fs_err::rename(extracted_dir, dst_dir)
            .context("Failed to move extracted files to destination directory")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Mrs {
    mrtd: Vec<u8>,
    rtmr0: Vec<u8>,
    rtmr1: Vec<u8>,
    rtmr2: Vec<u8>,
}

impl Mrs {
    fn assert_eq(&self, other: &Self) -> Result<()> {
        if self.mrtd != other.mrtd {
            bail!(
                "MRTD mismatch: expected={}, actual={}",
                hex::encode(&self.mrtd),
                hex::encode(&other.mrtd)
            );
        }
        if self.rtmr0 != other.rtmr0 {
            bail!(
                "RTMR0 mismatch: expected={}, actual={}",
                hex::encode(&self.rtmr0),
                hex::encode(&other.rtmr0)
            );
        }
        if self.rtmr1 != other.rtmr1 {
            bail!(
                "RTMR1 mismatch: expected={}, actual={}",
                hex::encode(&self.rtmr1),
                hex::encode(&other.rtmr1)
            );
        }
        if self.rtmr2 != other.rtmr2 {
            bail!(
                "RTMR2 mismatch: expected={}, actual={}",
                hex::encode(&self.rtmr2),
                hex::encode(&other.rtmr2)
            );
        }
        Ok(())
    }
}
