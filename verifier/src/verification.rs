// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::TdxEvent;
use dstack_attest::amd_sev_snp::AmdKdsClient;
use dstack_mr::{RtmrLog, TdxMeasurementDetails, TdxMeasurements};
use dstack_types::VmConfig;
use hex_literal::hex;
use ra_tls::attestation::{
    Attestation, AttestationQuote, DstackVerifiedReport, NitroPcrs, PlatformEvidence, TpmQuote,
    VerifiedAttestation, VersionedAttestation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::{debug, info, warn};

use crate::types::{
    AcpiTables, RtmrEventEntry, RtmrEventStatus, RtmrMismatch, VerificationDetails,
    VerificationRequest, VerificationResponse,
};

fn tee_platform_name(quote: &AttestationQuote) -> &'static str {
    match quote {
        AttestationQuote::DstackTdx(_) => "tdx",
        AttestationQuote::DstackGcpTdx(_) => "gcp-tdx",
        AttestationQuote::DstackNitroEnclave(_) => "nitro",
        AttestationQuote::DstackAmdSevSnp(_) => "sev-snp",
    }
}

/// best-effort: None for empty/malformed blobs.
fn decode_key_provider_info(bytes: &[u8]) -> Option<dstack_types::KeyProviderInfo> {
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

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

// Bump whenever expected RTMR computation changes so stale entries get ignored.
// v2: edk2-stable202505 OVMF RTMR[0] layout (added 4 events, reshaped BootOrder
// and Boot0000); the legacy 13-event log no longer matches any in-field image.
const MEASUREMENT_CACHE_VERSION: u32 = 2;

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
    is_dev: bool,
    version: String,
}

pub struct CvmVerifier {
    pub image_cache_dir: String,
    pub download_url: String,
    pub download_timeout: Duration,
    pub pccs_url: Option<String>,
    amd_kds_client: OnceLock<Result<AmdKdsClient, String>>,
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
            amd_kds_client: OnceLock::new(),
        }
    }

    fn amd_kds_client(&self) -> Result<&AmdKdsClient> {
        match self
            .amd_kds_client
            .get_or_init(|| AmdKdsClient::new().map_err(|err| format!("{err:#}")))
        {
            Ok(client) => Ok(client),
            Err(err) => bail!("failed to create amd sev-snp KDS client: {err}"),
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

        // Prefer the explicit variant the image declared; fall back to parsing
        // the version out of the image name for pre-`ovmf_variant` deployments.
        let ovmf_variant = vm_config
            .ovmf_variant
            .unwrap_or_else(|| dstack_mr::ovmf_variant_for_image(vm_config.image.as_deref()));

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
            .ovmf_variant(ovmf_variant)
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
            is_dev: image_info.is_dev,
            version: image_info.version,
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
            VersionedAttestation::from_bytes(attestation).context("Failed to decode attestaion")?
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
        let mut details = VerificationDetails::default();

        let debug = request.debug.unwrap_or(false);
        let attestation = attestation.into_v1();
        let verified = if matches!(&attestation.platform, PlatformEvidence::SevSnp { .. }) {
            attestation
                .verify_with_amd_kds_client(self.pccs_url.as_deref(), self.amd_kds_client()?)
                .await
        } else {
            attestation.verify(self.pccs_url.as_deref()).await
        };
        let verified_attestation = match verified {
            Ok(att) => {
                details.quote_verified = true;
                details.tee_platform = Some(tee_platform_name(&att.quote).to_string());
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
                details.key_provider = decode_key_provider_info(&info.key_provider_info);
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
        // The raw config string used for platform-specific binding: the explicit
        // request `vm_config` when supplied, otherwise the one embedded in the
        // attestation (mirroring `decode_vm_config`'s own fallback).
        let raw_config = if vm_config.is_empty() {
            attestation.config.clone()
        } else {
            vm_config.clone()
        };
        let mut vm_config = attestation
            .decode_vm_config(&vm_config)
            .context("Failed to decode VM config")?;
        match &attestation.quote {
            AttestationQuote::DstackGcpTdx(quote) => {
                self.verify_os_image_hash_for_gcp_tdx(&vm_config, &quote.tpm_quote)
                    .await?;
            }
            AttestationQuote::DstackTdx(_) => {
                self.verify_os_image_hash_for_dstack_tdx(&vm_config, attestation, debug, details)
                    .await?;
            }
            AttestationQuote::DstackNitroEnclave(_) => {
                let DstackVerifiedReport::DstackNitroEnclave(report) = &attestation.report else {
                    bail!("internal error: nitro quote without a verified nitro report");
                };
                self.verify_os_image_hash_for_nitro_enclave(&vm_config, &report.pcrs)?;
            }
            AttestationQuote::DstackAmdSevSnp(_) => {
                self.verify_os_image_hash_for_dstack_sev(
                    attestation,
                    &raw_config,
                    &mut vm_config,
                    details,
                )?;
            }
        }
        Ok(vm_config)
    }

    /// Verify the AMD SEV-SNP OS image binding.
    ///
    /// Unlike TDX (which replays RTMRs against a downloaded image), the SNP boot
    /// is summarised by the launch `MEASUREMENT`. The CVM advertises the
    /// self-contained launch inputs (`sev_snp_measurement`) and the MrConfigV3
    /// document in its `vm_config`; we recompute the launch measurement from
    /// those inputs and require it to equal the hardware-signed `MEASUREMENT`
    /// (which is what makes the otherwise-untrusted inputs trustworthy), require
    /// `HOST_DATA` to bind the MrConfigV3 document, and then derive the
    /// image-invariant `os_image_hash`. The shared recomputation in
    /// `dstack_mr::sev` is the same code path the KMS uses for key release, so a
    /// quote that the KMS would release keys for verifies here too.
    fn verify_os_image_hash_for_dstack_sev(
        &self,
        attestation: &VerifiedAttestation,
        raw_config: &str,
        vm_config: &mut VmConfig,
        details: &mut VerificationDetails,
    ) -> Result<()> {
        let report = attestation
            .report
            .amd_snp_report()
            .context("internal error: sev-snp quote without a verified sev-snp report")?;
        let binding =
            dstack_mr::sev::verify_sev_launch(&report.measurement, &report.host_data, raw_config)
                .context("amd sev-snp launch verification failed")?;
        // The os_image_hash derived from the measurement-bound launch inputs is
        // the authoritative one; surface it (overriding any guest-advertised
        // value, which is not independently trusted).
        vm_config.os_image_hash = binding.os_image_hash;
        details.tcb_status = Some(report.tcb_info.tcb_status().to_string());
        details.advisory_ids = report.advisory_ids.clone();
        Ok(())
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

        // one download serves both measurement computation and the dev/version flags
        let image_paths = self.ensure_image_downloaded(vm_config).await?;
        details.os_image_is_dev = Some(image_paths.is_dev);
        if !image_paths.version.is_empty() {
            details.os_image_version = Some(image_paths.version.clone());
        }

        // Compute expected measurements
        let (mrs, expected_logs) = if debug {
            // For debug mode, we need detailed logs and ACPI tables
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
            // For non-debug mode, use the cached-measurement path.
            (
                self.load_or_compute_measurements(
                    vm_config,
                    &image_paths.fw_path,
                    &image_paths.kernel_path,
                    &image_paths.initrd_path,
                    &image_paths.kernel_cmdline,
                )
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

    /// Verify Nitro Enclave OS image hash using the signature-verified NSM PCRs.
    ///
    /// For Nitro:
    /// 1. PCR0/1/2 come from the EIF build (code + kernel + app) in production mode.
    /// 2. In debug mode AWS zeroes PCR0/1/2, so there is no measurement of the
    ///    actual code; we refuse to authorize such enclaves.
    /// 3. The computed image hash is compared against vm_config.os_image_hash.
    fn verify_os_image_hash_for_nitro_enclave(
        &self,
        vm_config: &VmConfig,
        pcrs: &NitroPcrs,
    ) -> Result<()> {
        // Reject debug-mode enclaves outright: their zeroed PCRs measure nothing,
        // so accepting them would let arbitrary code run under attestation.
        if pcrs.is_debug() {
            bail!("nitro enclave is in debug mode (PCR0/1/2 are zeroed); refusing to verify");
        }
        let os_image_hash = pcrs.image_hash();
        // Compare with expected os_image_hash from vm_config
        if os_image_hash != vm_config.os_image_hash {
            bail!(
                "os_image_hash mismatch: expected={}, computed={}",
                hex::encode(&vm_config.os_image_hash),
                hex::encode(&os_image_hash)
            );
        }
        Ok(())
    }

    async fn verify_os_image_hash_for_gcp_tdx(
        &self,
        vm_config: &VmConfig,
        tpm_quote: &TpmQuote,
    ) -> Result<()> {
        // Verify PCR 0 (GCP OVMF firmware)
        const EXPECTED_PCR0: [u8; 32] =
            hex!("0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802");

        let pcr0 = tpm_quote
            .pcr_values
            .iter()
            .find(|p| p.index == 0)
            .context("PCR 0 not found in TPM quote")?;

        // Get expected UKI hash from os_image_hash (which should be set to UKI Authenticode hash)
        let expected_uki_hash = &vm_config.os_image_hash;

        let pcr2_events: Vec<_> = tpm_quote
            .event_log
            .iter()
            .filter(|e| e.pcr_index == 2)
            .collect();
        debug!("PCR 2 Event Log contains {} events", pcr2_events.len());
        // Extract Event 28 (3rd event, 0-indexed as 2)
        // NOTE: This is GCP OVMF-specific behavior
        let event_28_digest = {
            if pcr0.value != EXPECTED_PCR0 {
                bail!(
                    "PCR 0 mismatch: expected GCP OVMF v2, got {}",
                    hex::encode(&pcr0.value)
                );
            }
            &pcr2_events.get(2).context("Event 28 not found")?.digest
        };

        if event_28_digest != expected_uki_hash {
            bail!(
                "UKI hash mismatch: expected={}, actual={}",
                hex::encode(expected_uki_hash),
                hex::encode(event_28_digest)
            );
        }
        debug!(
            "✓ UKI hash verified from PCR 2 Event Log (Event 28), digest: {}",
            hex::encode(event_28_digest)
        );
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key_provider_info_parses_json_and_tolerates_garbage() {
        let info =
            decode_key_provider_info(br#"{"name":"kms","id":"abcd"}"#).expect("should parse");
        assert_eq!(info.name, "kms");
        assert_eq!(info.id, "abcd");

        // empty/malformed must degrade to None, not fail the verify.
        assert!(decode_key_provider_info(b"").is_none());
        assert!(decode_key_provider_info(b"not json").is_none());
    }
}
