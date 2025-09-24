// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::TdxEventLog as EventLog;
use dstack_mr::{RtmrLog, TdxMeasurementDetails, TdxMeasurements};
use dstack_types::VmConfig;
use ra_tls::attestation::{Attestation, VerifiedAttestation};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha384};
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::{debug, info, warn};

use crate::types::{
    AcpiTables, RtmrEventEntry, RtmrEventStatus, RtmrMismatch, VerificationDetails,
    VerificationRequest, VerificationResponse,
};

#[derive(Debug, Clone)]
struct RtmrComputationResult {
    event_indices: [Vec<usize>; 4],
    rtmrs: [[u8; 48]; 4],
}

fn replay_event_logs(eventlog: &[EventLog]) -> Result<RtmrComputationResult> {
    let mut event_indices: [Vec<usize>; 4] = Default::default();
    let mut rtmrs: [[u8; 48]; 4] = [[0u8; 48]; 4];

    for idx in 0..4 {
        for (event_idx, event) in eventlog.iter().enumerate() {
            event
                .validate()
                .context("Failed to validate event digest")?;

            if event.imr == idx {
                event_indices[idx as usize].push(event_idx);
                let mut hasher = Sha384::new();
                hasher.update(rtmrs[idx as usize]);
                hasher.update(event.digest);
                rtmrs[idx as usize] = hasher.finalize().into();
            }
        }
    }

    Ok(RtmrComputationResult {
        event_indices,
        rtmrs,
    })
}

fn collect_rtmr_mismatch(
    rtmr_label: &str,
    expected: &[u8],
    actual: &[u8],
    expected_sequence: &RtmrLog,
    actual_indices: &[usize],
    event_log: &[EventLog],
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
                let status = if event.digest == expected_digest.as_slice() {
                    RtmrEventStatus::Match
                } else {
                    RtmrEventStatus::Mismatch
                };
                events.push(RtmrEventEntry {
                    index: idx,
                    event_type: event.event_type,
                    event_name,
                    actual_digest: hex::encode(event.digest),
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
                hex::encode(event.digest),
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

pub struct CvmVerifier {
    pub image_cache_dir: String,
    pub download_url: String,
    pub download_timeout: Duration,
}

impl CvmVerifier {
    pub fn new(image_cache_dir: String, download_url: String, download_timeout: Duration) -> Self {
        Self {
            image_cache_dir,
            download_url,
            download_timeout,
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

    pub async fn verify(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
        let quote = hex::decode(&request.quote).context("Failed to decode quote hex")?;

        // Event log is always JSON string
        let event_log = request.event_log.as_bytes().to_vec();

        let attestation = Attestation::new(quote, event_log)
            .context("Failed to create attestation from quote and event log")?;

        let debug = request.debug.unwrap_or(false);

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

        let vm_config: VmConfig =
            serde_json::from_str(&request.vm_config).context("Failed to decode VM config JSON")?;

        // Step 1: Verify the TDX quote using dcap-qvl
        let verified_attestation = match self.verify_quote(attestation, &request.pccs_url).await {
            Ok(att) => {
                details.quote_verified = true;
                details.tcb_status = Some(att.report.status.clone());
                details.advisory_ids = att.report.advisory_ids.clone();
                // Extract and store report_data
                if let Ok(report_data) = att.decode_report_data() {
                    details.report_data = Some(hex::encode(report_data));
                }
                att
            }
            Err(e) => {
                return Ok(VerificationResponse {
                    is_valid: false,
                    details,
                    reason: Some(format!("Quote verification failed: {}", e)),
                });
            }
        };

        // Step 3: Verify os-image-hash matches using dstack-mr
        if let Err(e) = self
            .verify_os_image_hash(&vm_config, &verified_attestation, debug, &mut details)
            .await
        {
            return Ok(VerificationResponse {
                is_valid: false,
                details,
                reason: Some(format!("OS image hash verification failed: {e:#}")),
            });
        }
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

    async fn verify_quote(
        &self,
        attestation: Attestation,
        pccs_url: &Option<String>,
    ) -> Result<VerifiedAttestation> {
        // Extract report data from quote
        let report_data = attestation.decode_report_data()?;

        attestation
            .verify(&report_data, pccs_url.as_deref())
            .await
            .context("Quote verification failed")
    }

    async fn verify_os_image_hash(
        &self,
        vm_config: &VmConfig,
        attestation: &VerifiedAttestation,
        debug: bool,
        details: &mut VerificationDetails,
    ) -> Result<()> {
        let hex_os_image_hash = hex::encode(&vm_config.os_image_hash);

        // Get boot info from attestation
        let report = attestation
            .report
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

        // Get image directory
        let image_dir = Path::new(&self.image_cache_dir)
            .join("images")
            .join(&hex_os_image_hash);

        let metadata_path = image_dir.join("metadata.json");
        if !metadata_path.exists() {
            info!("Image {} not found, downloading", hex_os_image_hash);
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

        // Use dstack-mr to compute expected MRs
        let (mrs, expected_logs) = if debug {
            let TdxMeasurementDetails {
                measurements,
                rtmr_logs,
                acpi_tables,
            } = self
                .compute_measurement_details(
                    vm_config,
                    &fw_path,
                    &kernel_path,
                    &initrd_path,
                    &kernel_cmdline,
                )
                .context("Failed to compute expected measurements")?;

            details.acpi_tables = Some(AcpiTables {
                tables: hex::encode(&acpi_tables.tables),
                rsdp: hex::encode(&acpi_tables.rsdp),
                loader: hex::encode(&acpi_tables.loader),
            });

            (measurements, Some(rtmr_logs))
        } else {
            (
                self.load_or_compute_measurements(
                    vm_config,
                    &fw_path,
                    &kernel_path,
                    &initrd_path,
                    &kernel_cmdline,
                )
                .context("Failed to obtain expected measurements")?,
                None,
            )
        };

        let expected_mrs = Mrs {
            mrtd: mrs.mrtd.clone(),
            rtmr0: mrs.rtmr0.clone(),
            rtmr1: mrs.rtmr1.clone(),
            rtmr2: mrs.rtmr2.clone(),
        };

        let event_log: Vec<EventLog> = serde_json::from_slice(&attestation.raw_event_log)
            .context("Failed to parse event log for mismatch analysis")?;

        let computation_result = replay_event_logs(&event_log)
            .context("Failed to replay event logs for mismatch analysis")?;

        if computation_result.rtmrs[3] != report.rt_mr3 {
            bail!("RTMR3 mismatch");
        }

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
                        &computation_result.event_indices[0],
                        &event_log,
                    ));
                }

                if expected_mrs.rtmr1 != verified_mrs.rtmr1 {
                    rtmr_debug.push(collect_rtmr_mismatch(
                        "RTMR1",
                        &expected_mrs.rtmr1,
                        &verified_mrs.rtmr1,
                        &expected_logs[1],
                        &computation_result.event_indices[1],
                        &event_log,
                    ));
                }

                if expected_mrs.rtmr2 != verified_mrs.rtmr2 {
                    rtmr_debug.push(collect_rtmr_mismatch(
                        "RTMR2",
                        &expected_mrs.rtmr2,
                        &verified_mrs.rtmr2,
                        &expected_logs[2],
                        &computation_result.event_indices[2],
                        &event_log,
                    ));
                }

                if !rtmr_debug.is_empty() {
                    details.rtmr_debug = Some(rtmr_debug);
                }

                result
            }
        }
    }

    async fn download_image(&self, hex_os_image_hash: &str, dst_dir: &Path) -> Result<()> {
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

mod upgrade_authority {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
    pub struct BootInfo {
        pub mrtd: Vec<u8>,
        pub rtmr0: Vec<u8>,
        pub rtmr1: Vec<u8>,
        pub rtmr2: Vec<u8>,
        pub rtmr3: Vec<u8>,
        pub mr_aggregated: Vec<u8>,
        pub os_image_hash: Vec<u8>,
        pub mr_system: Vec<u8>,
        pub app_id: Vec<u8>,
        pub compose_hash: Vec<u8>,
        pub instance_id: Vec<u8>,
        pub device_id: Vec<u8>,
        pub key_provider_info: Vec<u8>,
        pub event_log: String,
        pub tcb_status: String,
        pub advisory_ids: Vec<String>,
    }
}
