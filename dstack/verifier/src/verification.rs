// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::{
    tdx::{
        TDX_ACPI_DATA_EVENT_PAYLOAD, TDX_ACPI_DATA_EVENT_TYPE, TDX_ACPI_LOADER_EVENT,
        TDX_ACPI_RSDP_EVENT, TDX_ACPI_TABLES_EVENT,
    },
    TdxEvent,
};
use dstack_mr::{
    tdx::TdxRtmr0AcpiHashes, RtmrLog, RtmrLogs, TdxMeasurementDetails, TdxMeasurements,
};
use dstack_types::{TdxAttestationVariant, VmConfig};
use hex_literal::hex;
use ra_tls::attestation::{
    AppInfo, Attestation, AttestationQuote, AttestationVerifier, DstackVerifiedReport, NitroPcrs,
    TpmQuote, VerifiedAttestation, VersionedAttestation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::{debug, info, warn};

use crate::types::{
    AcpiTables, PolicyBootInfo, RtmrEventEntry, RtmrEventStatus, RtmrMismatch, VerificationDetails,
    VerificationRequest, VerificationResponse,
};

/// Return the canonical TCB status and advisory list used by auth policy.
///
/// Matched exhaustively on purpose: adding a `DstackVerifiedReport` variant must
/// fail the build here rather than silently inherit another platform's TCB
/// semantics through a catch-all arm.
pub fn policy_tcb_fields(attestation: &VerifiedAttestation) -> (String, Vec<String>) {
    match &attestation.report {
        DstackVerifiedReport::DstackTdx(report) => {
            (report.status.clone(), report.advisory_ids.clone())
        }
        // GCP binds a TPM quote next to the TDX quote, but only the TDX report
        // carries a TCB surface, so the TPM report contributes nothing here.
        DstackVerifiedReport::DstackGcpTdx { tdx_report, .. } => {
            (tdx_report.status.clone(), tdx_report.advisory_ids.clone())
        }
        // SNP has no upstream status string; it is derived by comparing the
        // report's TCB versions, so read it from `tcb_info` rather than a field.
        DstackVerifiedReport::DstackAmdSevSnp(report) => (
            report.tcb_info.tcb_status().to_string(),
            report.advisory_ids.clone(),
        ),
        // AWS NitroTPM has no TDX/SNP-style TCB surface; a verified attestation
        // is normalized to "UpToDate" so the verifier's policy boot info matches
        // the KMS bootAuth payload and passes the shared "UpToDate" auth gate.
        DstackVerifiedReport::DstackAwsNitroTpm(_) => ("UpToDate".to_string(), Vec::new()),
        // Other no-TCB platforms (currently Nitro Enclave) stay empty so a
        // relying party's UpToDate requirement fails closed.
        DstackVerifiedReport::DstackNitroEnclave(_) => (String::new(), Vec::new()),
    }
}

fn policy_boot_info_from_verified_app_info(
    attestation: &VerifiedAttestation,
    app_info: &AppInfo,
) -> PolicyBootInfo {
    let (tcb_status, advisory_ids) = policy_tcb_fields(attestation);
    PolicyBootInfo::from_app_info(
        attestation.quote.variant(),
        app_info,
        tcb_status,
        advisory_ids,
    )
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
// v3: all supported OVMF measurements use the Pre202505 RTMR[0] layout.
const MEASUREMENT_CACHE_VERSION: u32 = 3;

#[derive(Clone, Serialize, Deserialize)]
struct CachedMeasurement {
    version: u32,
    measurements: TdxMeasurements,
}

struct ImagePaths {
    image_dir: PathBuf,
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
    pub attestation_verifier: Arc<AttestationVerifier>,
}

impl CvmVerifier {
    pub fn new(
        image_cache_dir: String,
        download_url: String,
        download_timeout: Duration,
        attestation_verifier: Arc<AttestationVerifier>,
    ) -> Self {
        Self {
            image_cache_dir,
            download_url,
            download_timeout,
            attestation_verifier,
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

        // Prefer the explicit variant the image declared; pre-`ovmf_variant`
        // deployments fall back to the only layout that existed back then.
        let ovmf_variant = vm_config.ovmf_variant.unwrap_or_default();

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
            .num_nics(vm_config.num_nics)
            .num_verity_volumes(vm_config.num_verity_volumes)
            .swtpm(vm_config.swtpm)
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

    fn image_content_digest(image_dir: &Path) -> Result<Option<Vec<u8>>> {
        let sha256sum_path = image_dir.join("sha256sum.txt");
        if !sha256sum_path.exists() {
            return Ok(None);
        }
        let files_doc =
            fs_err::read_to_string(&sha256sum_path).context("Failed to read sha256sum.txt")?;
        Ok(Some(
            Sha256::new_with_prefix(files_doc.as_bytes())
                .finalize()
                .to_vec(),
        ))
    }

    fn image_hash_matches_legacy_digest(image_dir: &Path, expected: &[u8]) -> Result<bool> {
        Ok(Self::image_content_digest(image_dir)?
            .as_deref()
            .is_some_and(|digest| digest == expected))
    }

    /// Mirrors the confinement rule `tar::Entry::unpack_in` applies internally:
    /// `..` components, absolute paths, and Windows prefixes escape the
    /// extraction root, while `.` components are stripped and are harmless.
    ///
    /// This duplicates the library check on purpose. `Archive::unpack` discards
    /// the `unpack_in` return value, so an escaping member is silently dropped
    /// and extraction still reports success; checking here turns that into an
    /// error and keeps the boundary from widening if the library's behavior
    /// ever changes. It must not be *stricter* than the library, though:
    /// rejecting `.` components would reject the `./`-prefixed archives that
    /// `tar -czf out.tar.gz .` produces, and roughly a third of the images
    /// published on download.dstack.org are packed that way.
    fn is_confined_archive_path(path: &Path) -> bool {
        path.components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
    }

    /// A manifest name must be literally a file name, because
    /// `prune_unlisted_image_files` matches manifest entries against the
    /// `file_name()` of each top-level directory entry, and `sha256sum -c`
    /// resolves them relative to the extraction root.
    fn is_flat_manifest_name(name: &str) -> bool {
        Path::new(name)
            .file_name()
            .is_some_and(|file_name| file_name == OsStr::new(name))
    }

    fn validate_image_manifest_paths(files_doc: &str) -> Result<()> {
        for (line_index, line) in files_doc.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let _digest = fields
                .next()
                .context("image manifest entry is missing a digest")?;
            let name = fields
                .next()
                .context("image manifest entry is missing a path")?;
            if fields.next().is_some() {
                bail!("image manifest line {} has extra fields", line_index + 1);
            }
            if !Self::is_flat_manifest_name(name) {
                bail!("image manifest line {} has an unsafe path", line_index + 1);
            }
            if name == "sha256sum.txt" {
                bail!("image manifest must not recursively list sha256sum.txt");
            }
        }
        Ok(())
    }

    fn extract_image_archive(tarball_path: &Path, extracted_dir: &Path) -> Result<()> {
        let file = fs_err::File::open(tarball_path).context("Failed to open image archive")?;
        // `MultiGzDecoder`, not `GzDecoder`: the latter stops at the first gzip
        // member and reports clean EOF, so a concatenated-member archive would
        // extract partially without any error.
        let decoder = flate2::read::MultiGzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().context("Failed to read image archive")? {
            let mut entry = entry.context("Failed to read image archive entry")?;
            let path = entry
                .path()
                .context("Failed to decode image archive path")?;
            if !Self::is_confined_archive_path(&path) {
                bail!("image archive contains unsafe path {}", path.display());
            }
            let entry_type = entry.header().entry_type();
            if !(entry_type.is_file() || entry_type.is_dir()) {
                bail!(
                    "image archive contains unsupported entry {}",
                    path.display()
                );
            }
            if !entry
                .unpack_in(extracted_dir)
                .context("Failed to extract image archive entry")?
            {
                bail!("image archive entry escaped the extraction root");
            }
        }
        Ok(())
    }

    fn prune_unlisted_image_files(extracted_dir: &Path, files_doc: &str) -> Result<()> {
        let listed_files: Vec<&OsStr> = files_doc
            .lines()
            .flat_map(|line| line.split_whitespace().nth(1))
            .map(|s| s.as_ref())
            .collect();
        let files = fs_err::read_dir(extracted_dir).context("Failed to read directory")?;
        for file in files {
            let file = file.context("Failed to read directory entry")?;
            let filename = file.file_name();
            // sha256sum.txt is the content-addressed OS identity and is needed
            // again when a legacy TDX quote is verified from the cache.
            if filename != OsStr::new("sha256sum.txt")
                && !listed_files.contains(&filename.as_os_str())
            {
                if file.path().is_dir() {
                    fs_err::remove_dir_all(file.path()).context("Failed to remove directory")?;
                } else {
                    fs_err::remove_file(file.path()).context("Failed to remove file")?;
                }
            }
        }
        Ok(())
    }

    fn tdx_acpi_hashes_from_event_log(event_log: &[TdxEvent]) -> Result<TdxRtmr0AcpiHashes> {
        let rtmr0_events = event_log
            .iter()
            .filter(|event| event.imr == 0)
            .collect::<Vec<_>>();
        let acpi_events = rtmr0_events
            .iter()
            .filter(|event| {
                event.event_type == TDX_ACPI_DATA_EVENT_TYPE
                    && event.event_payload == TDX_ACPI_DATA_EVENT_PAYLOAD
            })
            .collect::<Vec<_>>();
        if acpi_events.len() != 3 {
            bail!(
                "TDX lite attestation requires exactly 3 RTMR0 ACPI DATA events; found {} candidates and {} RTMR0 events",
                acpi_events.len(),
                rtmr0_events.len()
            );
        }

        let digest_for = |name: &str| -> Result<Vec<u8>> {
            let matches = acpi_events
                .iter()
                .copied()
                .filter(|event| event.event == name)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                bail!(
                    "TDX lite attestation requires exactly one RTMR0 ACPI DATA event named {name}; found {}",
                    matches.len()
                );
            }
            let digest = matches[0].digest();
            if digest.len() != 48 {
                bail!(
                    "TDX RTMR0 ACPI DATA event {name} has invalid digest length {}, expected 48",
                    digest.len()
                );
            }
            Ok(digest)
        };

        Ok(TdxRtmr0AcpiHashes {
            loader: digest_for(TDX_ACPI_LOADER_EVENT)?,
            rsdp: digest_for(TDX_ACPI_RSDP_EVENT)?,
            tables: digest_for(TDX_ACPI_TABLES_EVENT)?,
        })
    }

    /// Compare recomputed ACPI digests against the ones the guest reported.
    ///
    /// RTMR0 alone would already fail on a mismatch, but only with an opaque
    /// "MRs do not match": name the offending table here so an operator can
    /// tell a tampered table apart from an unexpected VM shape.
    fn assert_tdx_acpi_hashes_match(
        expected: &TdxRtmr0AcpiHashes,
        reported: &TdxRtmr0AcpiHashes,
    ) -> Result<()> {
        for (name, expected, reported) in [
            (TDX_ACPI_LOADER_EVENT, &expected.loader, &reported.loader),
            (TDX_ACPI_RSDP_EVENT, &expected.rsdp, &reported.rsdp),
            (TDX_ACPI_TABLES_EVENT, &expected.tables, &reported.tables),
        ] {
            if expected != reported {
                bail!(
                    "TDX lite {name} digest mismatch: expected {}, reported {}",
                    hex::encode(expected),
                    hex::encode(reported)
                );
            }
        }
        Ok(())
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
            image_dir,
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
        // Keep the two verifier input modes disjoint:
        // - `attestation` is self-contained and its embedded config is used.
        // - raw TDX input uses top-level `quote` + `event_log` + `vm_config`.
        // Never mix top-level config with an attestation; otherwise an
        // untrusted, separately supplied config could influence verification.
        let has_attestation = request.attestation.is_some();
        if has_attestation
            && (request.quote.is_some()
                || request.event_log.is_some()
                || request.vm_config.is_some())
        {
            warn!(
                "attestation is present; ignoring top-level quote/event_log/vm_config to avoid mixed verification inputs"
            );
        }
        let request_vm_config = if has_attestation {
            String::new()
        } else {
            request.vm_config.clone().unwrap_or_default()
        };
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
        let verified = attestation.verify(&self.attestation_verifier).await;
        let verified_attestation = match verified {
            Ok(att) => {
                details.quote_verified = true;
                details.tee_variant = Some(att.quote.variant());
                // keep the top-level tcb_status consistent with the
                // boot_info.tcbStatus fed to the auth policy (notably AWS
                // NitroTPM, which is normalized to "UpToDate" there).
                let (tcb_status, advisory_ids) = policy_tcb_fields(&att);
                details.tcb_status = (!tcb_status.is_empty()).then_some(tcb_status);
                details.advisory_ids = advisory_ids;
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
                request_vm_config.clone(),
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
        match verified_attestation.decode_app_info_ex(false, &request_vm_config) {
            Ok(mut info) => {
                info.os_image_hash = vm_config.os_image_hash;
                details.boot_info = Some(policy_boot_info_from_verified_app_info(
                    &verified_attestation,
                    &info,
                ));
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
                self.verify_os_image_hash_for_gcp_tdx(&vm_config, &quote.tpm_quote)?;
            }
            // The declared scheme alone selects the path, matched exhaustively
            // so a new variant fails the build here instead of taking one.
            //
            // A `tdx_measurement` document must not pull a `Legacy` boot onto
            // the lite path. Both paths now verify the ACPI tables, but they
            // disagree on what `os_image_hash` means: legacy requires it to be
            // the image digest and recomputes every MR from the downloaded
            // image, while lite treats it as `sha256(sha256sum.txt)` and trusts
            // the attached document for the image-static material. Images
            // attach the document whenever they have it, independent of the
            // scheme, so honoring it here would silently move a boot the app
            // pinned to `Legacy` onto weaker image-identity checks.
            //
            // `Lite` without a document is rejected by the lite path itself,
            // rather than degraded to a download.
            AttestationQuote::DstackTdx(_) => match vm_config.tdx_attestation_variant {
                TdxAttestationVariant::Legacy => {
                    self.verify_os_image_hash_for_dstack_tdx(
                        &vm_config,
                        attestation,
                        debug,
                        details,
                    )
                    .await?;
                }
                TdxAttestationVariant::Lite => {
                    self.verify_os_image_hash_for_dstack_tdx_lite(
                        &vm_config,
                        attestation,
                        debug,
                        details,
                    )
                    .await?;
                }
            },
            AttestationQuote::DstackNitroEnclave(_) => {
                let DstackVerifiedReport::DstackNitroEnclave(report) = &attestation.report else {
                    bail!("internal error: nitro quote without a verified nitro report");
                };
                self.verify_os_image_hash_for_nitro_enclave(&vm_config, &report.pcrs)?;
            }
            AttestationQuote::DstackAwsNitroTpm(_) => {
                let DstackVerifiedReport::DstackAwsNitroTpm(report) = &attestation.report else {
                    bail!("internal error: NitroTPM quote without a verified NitroTPM report");
                };
                self.verify_os_image_hash_for_aws_nitro_tpm(&vm_config, &report.pcrs)?;
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
    /// `HOST_DATA` to bind the MrConfigV3 document, and then verify/return the
    /// unified `os_image_hash` (`sha256(sha256sum.txt)`). The shared recomputation in
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
        // verify_sev_launch has checked that vm_config.os_image_hash commits to
        // the supplied sha256sum.txt and measurement.snp.cbor material.
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
        let report = report
            .report
            .as_td10()
            .context("Failed to decode TD report")?;

        let verified_mrs = Mrs {
            mrtd: report.mr_td.to_vec(),
            rtmr0: report.rt_mr0.to_vec(),
            rtmr1: report.rt_mr1.to_vec(),
            rtmr2: report.rt_mr2.to_vec(),
        };

        // Legacy TDX attestation keeps the original KMS verifier semantics:
        // os_image_hash must be the image digest (digest.txt =
        // sha256(sha256sum.txt)), and expected MRs are recomputed through the
        // existing full-image path.
        let image_paths = self.ensure_image_downloaded(vm_config).await?;
        if !Self::image_hash_matches_legacy_digest(&image_paths.image_dir, &vm_config.os_image_hash)
            .context("Failed to check legacy image digest")?
        {
            bail!("legacy TDX attestation requires os_image_hash = sha256(sha256sum.txt)");
        }
        details.os_image_is_dev = Some(image_paths.is_dev);
        if !image_paths.version.is_empty() {
            details.os_image_version = Some(image_paths.version.clone());
        }

        let (mrs, expected_logs) = if debug {
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

        self.compare_tdx_mrs(
            Mrs {
                mrtd: mrs.mrtd,
                rtmr0: mrs.rtmr0,
                rtmr1: mrs.rtmr1,
                rtmr2: mrs.rtmr2,
            },
            verified_mrs,
            expected_logs.as_ref(),
            event_log,
            debug,
            details,
        )?;
        details.acpi_tables_verified = true;
        Ok(())
    }

    async fn verify_os_image_hash_for_dstack_tdx_lite(
        &self,
        vm_config: &VmConfig,
        attestation: &VerifiedAttestation,
        _debug: bool,
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

        let document = vm_config
            .tdx_measurement
            .as_ref()
            .context("tdx lite attestation requires vm_config.tdx_measurement")?;
        document
            .verify(&vm_config.os_image_hash)
            .map_err(anyhow::Error::msg)
            .context("tdx lite measurement material does not match os_image_hash")?;
        let measurement = document
            .decode_measurement()
            .map_err(anyhow::Error::msg)
            .context("failed to decode vm_config.tdx_measurement CBOR")?;
        if let Some(config_ovmf_variant) = vm_config.ovmf_variant {
            if config_ovmf_variant != measurement.tdvf.ovmf_variant {
                bail!(
                    "tdx measurement ovmf_variant mismatch: vm_config={:?}, document={:?}",
                    config_ovmf_variant,
                    measurement.tdvf.ovmf_variant
                );
            }
        }

        // Compute expected measurements. TDX lite keeps the unified image hash
        // and carries split measurement material; verify it without
        // downloading the image. The guest labels the three RTMR0 ACPI DATA
        // events as acpi-loader, acpi-rsdp, and acpi-tables before exposing the
        // event log, so the verifier does not guess based on event order.
        let reported_acpi_hashes = Self::tdx_acpi_hashes_from_event_log(event_log)
            .context("TDX lite attestation is missing named RTMR0 ACPI DATA digests")?;
        // Recompute the digests from the declared VM shape instead of trusting
        // the reported ones, and treat both failure modes as fatal: a mismatch
        // means the tables are not the ones this shape produces, and a shape
        // the generator cannot model (`swtpm`, a QEMU older than any profile)
        // leaves nothing to compare against. Downgrading either case to "pass,
        // but unverified" would make the check optional at the host's
        // discretion, because `swtpm` and `qemu_version` are host-declared
        // fields that no other measurement independently constrains.
        let acpi_hashes =
            dstack_mr::tdx::expected_rtmr0_acpi_hashes(vm_config, measurement.tdvf.ovmf_variant)
                .context("failed to recompute expected TDX lite ACPI table digests")?;
        Self::assert_tdx_acpi_hashes_match(&acpi_hashes, &reported_acpi_hashes)?;
        details.acpi_tables_verified = true;
        // RTMR0 below is rebuilt from the recomputed digests, so the expected
        // value depends on nothing the host reported about the tables.
        let mrs = dstack_mr::tdx::tdx_measurements_from_measurement_document(
            document,
            vm_config,
            &acpi_hashes,
        )
        .context("Failed to compute TDX expected measurements without image download")?;

        let expected_mrs = Mrs {
            mrtd: mrs.mrtd.clone(),
            rtmr0: mrs.rtmr0.clone(),
            rtmr1: mrs.rtmr1.clone(),
            rtmr2: mrs.rtmr2.clone(),
        };
        expected_mrs
            .assert_eq(&verified_mrs)
            .context("MRs do not match")
    }

    fn compare_tdx_mrs(
        &self,
        expected_mrs: Mrs,
        verified_mrs: Mrs,
        expected_logs: Option<&RtmrLogs>,
        event_log: &[TdxEvent],
        debug: bool,
        details: &mut VerificationDetails,
    ) -> Result<()> {
        match expected_mrs.assert_eq(&verified_mrs) {
            Ok(()) => Ok(()),
            Err(e) => {
                let result = Err(e).context("MRs do not match");
                if !debug {
                    return result;
                }
                let Some(expected_logs) = expected_logs else {
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

    /// Verify AWS EC2 NitroTPM OS image identity (unified with GCP/TDX lite):
    /// `vm_config.aws_measurement` with `os_image_hash = sha256(sha256sum.txt)`
    /// and `boot_pcr_digest = sha256(PCR4||PCR7||PCR12)` bound to the
    /// attestation document PCRs. `aws_measurement` is required.
    fn verify_os_image_hash_for_aws_nitro_tpm(
        &self,
        vm_config: &VmConfig,
        pcrs: &std::collections::BTreeMap<u16, Vec<u8>>,
    ) -> Result<()> {
        let document = vm_config
            .aws_measurement
            .as_ref()
            .context("vm_config.aws_measurement is required on AWS NitroTPM")?;
        document
            .verify(&vm_config.os_image_hash)
            .map_err(anyhow::Error::msg)
            .context("aws measurement material does not match os_image_hash")?;
        let measurement = document
            .decode_measurement()
            .map_err(anyhow::Error::msg)
            .context("failed to decode vm_config.aws_measurement")?;
        let quoted_digest = dstack_attest::attestation::aws_nitro_tpm_boot_pcr_digest(pcrs)
            .context("failed to compute NitroTPM boot_pcr_digest from attestation")?;
        if measurement.boot_pcr_digest.as_slice() != quoted_digest.as_slice() {
            bail!(
                "AWS boot_pcr_digest mismatch: expected={}, quoted={}",
                hex::encode(&measurement.boot_pcr_digest),
                hex::encode(&quoted_digest)
            );
        }
        Ok(())
    }

    fn verify_os_image_hash_for_gcp_tdx(
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

        let document = vm_config
            .gcp_measurement
            .as_ref()
            .context("gcp tdx attestation requires vm_config.gcp_measurement")?;
        document
            .verify(&vm_config.os_image_hash)
            .map_err(anyhow::Error::msg)
            .context("gcp measurement material does not match os_image_hash")?;
        let measurement = document
            .decode_measurement()
            .map_err(anyhow::Error::msg)
            .context("failed to decode vm_config.gcp_measurement CBOR")?;
        let expected_uki_hash = &measurement.uki_authenticode_sha256;

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

        file.flush()
            .await
            .context("Failed to flush image archive")?;
        drop(file);
        Self::extract_image_archive(&tarball_path, &extracted_dir)?;

        let sha256sum_path = extracted_dir.join("sha256sum.txt");
        let files_doc =
            fs_err::read_to_string(&sha256sum_path).context("Failed to read sha256sum.txt")?;
        Self::validate_image_manifest_paths(&files_doc)?;

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
        Self::prune_unlisted_image_files(&extracted_dir, &files_doc)?;

        // All image modes are addressed by sha256(sha256sum.txt). Extra
        // measurement CBOR files are ordinary sha256sum.txt entries and do not
        // define alternate image hashes.
        let legacy_os_image_hash = Sha256::new_with_prefix(files_doc.as_bytes()).finalize();
        if hex::encode(legacy_os_image_hash) != hex_os_image_hash {
            bail!("os_image_hash does not match sha256(sha256sum.txt)");
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
    use std::collections::BTreeMap;

    use super::*;

    // Kept inside `mod tests` so the non-test build stays free of unused imports.
    use dcap_qvl::{
        quote::{Report as DcapReport, TDReport10},
        tcb_info::{TcbStatus, TcbStatusWithAdvisory},
        verify::VerifiedReport as DcapVerifiedReport,
    };
    use dstack_attest::amd_sev_snp::{AmdSnpTcbInfo, VerifiedAmdSnpReport};
    use ra_tls::attestation::{
        AwsNitroTpmVerifiedReport, DstackAwsNitroTpmQuote, DstackGcpTdxQuote, DstackNitroQuote,
        NitroVerifiedReport, SnpQuote, TdxQuote,
    };
    use tpm_qvl::verify::{ClockInfo, QuoteInfo, TpmAttest, VerifiedReport as TpmVerifiedReport};

    fn aws_boot_pcrs(pcr4: u8) -> BTreeMap<u16, Vec<u8>> {
        BTreeMap::from([
            (4, vec![pcr4; 48]),
            (7, vec![0x77; 48]),
            (12, vec![0x12; 48]),
        ])
    }

    fn aws_vm_config(pcrs: &BTreeMap<u16, Vec<u8>>) -> VmConfig {
        let measurement =
            dstack_types::AwsOsImageMeasurement::from_boot_pcrs(&pcrs[&4], &pcrs[&7], &pcrs[&12])
                .expect("valid PCR lengths");
        let measurement = measurement.to_cbor_vec();
        let checksum_file = format!(
            "{}  measurement.aws.cbor\n",
            hex::encode(Sha256::digest(&measurement))
        )
        .into_bytes();
        let os_image_hash = dstack_types::image_hash_from_sha256sum(&checksum_file);
        serde_json::from_value(serde_json::json!({
            "os_image_hash": hex::encode(os_image_hash),
            "aws_measurement": dstack_types::AwsOsImageMeasurementDocument::new(
                checksum_file,
                measurement,
            ),
        }))
        .expect("valid AWS vm_config")
    }

    fn test_verifier() -> CvmVerifier {
        CvmVerifier::new(
            String::new(),
            String::new(),
            Duration::from_secs(1),
            test_attestation_verifier(),
        )
    }

    fn test_attestation_verifier() -> Arc<AttestationVerifier> {
        Arc::new(AttestationVerifier::new_prod(None).unwrap())
    }

    /// Build a TDX verified report carrying `status`/`advisory_ids`. Everything
    /// else is zeroed: `policy_tcb_fields` reads only those two fields.
    fn tdx_report(status: &str, advisory_ids: &[&str]) -> DcapVerifiedReport {
        DcapVerifiedReport {
            status: status.to_string(),
            advisory_ids: advisory_ids.iter().map(|id| id.to_string()).collect(),
            report: DcapReport::TD10(TDReport10 {
                tee_tcb_svn: [0; 16],
                mr_seam: [0; 48],
                mr_signer_seam: [0; 48],
                seam_attributes: [0; 8],
                td_attributes: [0; 8],
                xfam: [0; 8],
                mr_td: [0; 48],
                mr_config_id: [0; 48],
                mr_owner: [0; 48],
                mr_owner_config: [0; 48],
                rt_mr0: [0; 48],
                rt_mr1: [0; 48],
                rt_mr2: [0; 48],
                rt_mr3: [0; 48],
                report_data: [0; 64],
            }),
            ppid: Vec::new(),
            qe_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
            platform_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        }
    }

    fn snp_report(tcb_info: AmdSnpTcbInfo, advisory_ids: &[&str]) -> VerifiedAmdSnpReport {
        VerifiedAmdSnpReport {
            measurement: [0; 48],
            report_data: [0; 64],
            host_data: [0; 32],
            chip_id: [0; 64],
            tcb_info,
            advisory_ids: advisory_ids.iter().map(|id| id.to_string()).collect(),
        }
    }

    fn tpm_report_for_gcp() -> TpmVerifiedReport {
        TpmVerifiedReport {
            attest: TpmAttest {
                magic: 0,
                type_: 0,
                qualified_signer: Vec::new(),
                qualified_data: Vec::new(),
                clock_info: ClockInfo {
                    clock: 0,
                    reset_count: 0,
                    restart_count: 0,
                    safe: 0,
                },
                firmware_version: 0,
                attested_quote_info: QuoteInfo {
                    pcr_selections: Vec::new(),
                    pcr_digest: Vec::new(),
                },
            },
            platform: dstack_types::Platform::Gcp,
            pcr_values: Vec::new(),
        }
    }

    /// `policy_tcb_fields` ignores the quote, but pair each report with its own
    /// platform's quote so the rows stay readable as real attestations.
    fn verified_attestation(
        quote: AttestationQuote,
        report: DstackVerifiedReport,
    ) -> VerifiedAttestation {
        Attestation {
            quote,
            runtime_events: Vec::new(),
            report_data: [0; 64],
            config: String::new(),
            report,
        }
    }

    fn empty_tdx_quote() -> AttestationQuote {
        AttestationQuote::DstackTdx(TdxQuote {
            quote: Vec::new(),
            event_log: Vec::new(),
        })
    }

    /// Exercises the report-to-policy mapping itself, which is where a wrong
    /// source can silently downgrade the auth gate (e.g. reading the wrong
    /// report on GCP, or letting a no-TCB platform report "UpToDate").
    #[test]
    fn tcb_policy_fields_map_each_platform_to_its_own_tcb_source() {
        let advisories = ["INTEL-SA-00001", "INTEL-SA-00002"];
        let expected_advisories: Vec<String> = advisories.iter().map(|id| id.to_string()).collect();

        // SNP derives its status by comparing TCB versions rather than reading
        // a field, so cover both the equal (UpToDate) and unequal (OutOfDate)
        // shapes.
        let snp_up_to_date = AmdSnpTcbInfo::default();
        let mut snp_out_of_date = AmdSnpTcbInfo::default();
        snp_out_of_date.current.microcode = 1;

        let rows: [(&str, VerifiedAttestation, &str, Vec<String>); 7] = [
            (
                "tdx-up-to-date",
                verified_attestation(
                    empty_tdx_quote(),
                    DstackVerifiedReport::DstackTdx(tdx_report("UpToDate", &[])),
                ),
                "UpToDate",
                Vec::new(),
            ),
            (
                "tdx-out-of-date-carries-advisories",
                verified_attestation(
                    empty_tdx_quote(),
                    DstackVerifiedReport::DstackTdx(tdx_report("OutOfDate", &advisories)),
                ),
                "OutOfDate",
                expected_advisories.clone(),
            ),
            (
                "tdx-revoked",
                verified_attestation(
                    empty_tdx_quote(),
                    DstackVerifiedReport::DstackTdx(tdx_report("Revoked", &advisories)),
                ),
                "Revoked",
                expected_advisories.clone(),
            ),
            (
                // The bundled TPM report has no TCB surface: the TDX report must
                // still drive policy, and must not be flattened to empty.
                "gcp-tdx-reads-the-tdx-report-not-the-tpm-report",
                verified_attestation(
                    AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
                        tdx_quote: TdxQuote {
                            quote: Vec::new(),
                            event_log: Vec::new(),
                        },
                        tpm_quote: TpmQuote {
                            message: Vec::new(),
                            signature: Vec::new(),
                            pcr_values: Vec::new(),
                            ak_cert: Vec::new(),
                            platform: dstack_types::Platform::Gcp,
                            event_log: Vec::new(),
                        },
                    }),
                    DstackVerifiedReport::DstackGcpTdx {
                        tdx_report: tdx_report("OutOfDate", &advisories),
                        tpm_report: tpm_report_for_gcp(),
                    },
                ),
                "OutOfDate",
                expected_advisories.clone(),
            ),
            (
                "sev-snp-matching-tcb-versions-are-up-to-date",
                verified_attestation(
                    AttestationQuote::DstackAmdSevSnp(SnpQuote {
                        report: Vec::new(),
                        cert_chain: Vec::new(),
                        mr_config: String::new(),
                    }),
                    DstackVerifiedReport::DstackAmdSevSnp(snp_report(snp_up_to_date, &[])),
                ),
                "UpToDate",
                Vec::new(),
            ),
            (
                "sev-snp-mismatched-tcb-versions-are-out-of-date",
                verified_attestation(
                    AttestationQuote::DstackAmdSevSnp(SnpQuote {
                        report: Vec::new(),
                        cert_chain: Vec::new(),
                        mr_config: String::new(),
                    }),
                    DstackVerifiedReport::DstackAmdSevSnp(snp_report(snp_out_of_date, &advisories)),
                ),
                "OutOfDate",
                expected_advisories.clone(),
            ),
            (
                // No TCB surface, but normalized to UpToDate so the verifier's
                // policy boot info matches the KMS bootAuth payload.
                "aws-nitro-tpm-is-normalized-to-up-to-date",
                verified_attestation(
                    AttestationQuote::DstackAwsNitroTpm(DstackAwsNitroTpmQuote {
                        attestation_doc: Vec::new(),
                    }),
                    DstackVerifiedReport::DstackAwsNitroTpm(AwsNitroTpmVerifiedReport {
                        module_id: String::new(),
                        pcrs: BTreeMap::new(),
                        public_key: None,
                        user_data: Vec::new(),
                        nonce: None,
                        timestamp: 0,
                    }),
                ),
                "UpToDate",
                Vec::new(),
            ),
        ];

        for (name, attestation, expected_status, expected_advisory_ids) in rows {
            let (status, advisory_ids) = policy_tcb_fields(&attestation);
            assert_eq!(status, expected_status, "{name}");
            assert_eq!(advisory_ids, expected_advisory_ids, "{name}");
        }
    }

    /// Split out from the table above because it asserts the opposite property:
    /// Nitro Enclave must stay empty so a relying party's "UpToDate" gate fails
    /// closed rather than accepting a platform with no TCB surface.
    #[test]
    fn nitro_enclave_reports_no_tcb_status_and_fails_an_up_to_date_gate() {
        let attestation = verified_attestation(
            AttestationQuote::DstackNitroEnclave(DstackNitroQuote {
                nsm_quote: Vec::new(),
            }),
            DstackVerifiedReport::DstackNitroEnclave(NitroVerifiedReport {
                module_id: String::new(),
                pcrs: NitroPcrs {
                    pcr0: vec![0x10; 48],
                    pcr1: vec![0x11; 48],
                    pcr2: vec![0x12; 48],
                },
                user_data: Vec::new(),
                timestamp: 0,
            }),
        );

        let (status, advisory_ids) = policy_tcb_fields(&attestation);
        assert_eq!(status, "");
        assert_ne!(status, "UpToDate");
        assert!(advisory_ids.is_empty());
    }

    #[test]
    fn gcp_and_nitro_enclave_measurement_bindings_matrix() {
        let verifier = test_verifier();

        let nitro_pcrs = NitroPcrs {
            pcr0: vec![0x10; 48],
            pcr1: vec![0x11; 48],
            pcr2: vec![0x12; 48],
        };
        let nitro_config: VmConfig = serde_json::from_value(serde_json::json!({
            "os_image_hash": hex::encode(nitro_pcrs.image_hash()),
        }))
        .unwrap();
        verifier
            .verify_os_image_hash_for_nitro_enclave(&nitro_config, &nitro_pcrs)
            .unwrap();
        let mut changed_nitro = nitro_pcrs.clone();
        changed_nitro.pcr2[0] ^= 1;
        assert!(verifier
            .verify_os_image_hash_for_nitro_enclave(&nitro_config, &changed_nitro)
            .is_err());
        let debug_nitro = NitroPcrs {
            pcr0: vec![0; 48],
            pcr1: vec![0; 48],
            pcr2: vec![0; 48],
        };
        assert!(verifier
            .verify_os_image_hash_for_nitro_enclave(&nitro_config, &debug_nitro)
            .is_err());

        let uki_hash = vec![0x24; 32];
        let measurement = dstack_types::GcpOsImageMeasurement::new(uki_hash.clone()).unwrap();
        let measurement_bytes = measurement.to_cbor_vec();
        let checksum_file = format!(
            "{}  measurement.gcp.cbor\n",
            hex::encode(Sha256::digest(&measurement_bytes))
        )
        .into_bytes();
        let os_image_hash = dstack_types::image_hash_from_sha256sum(&checksum_file);
        let gcp_config: VmConfig = serde_json::from_value(serde_json::json!({
            "os_image_hash": hex::encode(os_image_hash),
            "gcp_measurement": dstack_types::GcpOsImageMeasurementDocument::new(
                checksum_file,
                measurement_bytes,
            ),
        }))
        .unwrap();
        let expected_pcr0 =
            hex!("0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802");
        let gcp_quote = |pcr0: Vec<u8>, event_28: Vec<u8>| TpmQuote {
            message: Vec::new(),
            signature: Vec::new(),
            pcr_values: vec![tpm_types::PcrValue {
                index: 0,
                algorithm: "sha256".into(),
                value: pcr0,
            }],
            ak_cert: Vec::new(),
            platform: dstack_types::Platform::Gcp,
            event_log: vec![
                tpm_types::TpmEvent {
                    pcr_index: 2,
                    digest: vec![1; 32],
                },
                tpm_types::TpmEvent {
                    pcr_index: 2,
                    digest: vec![2; 32],
                },
                tpm_types::TpmEvent {
                    pcr_index: 2,
                    digest: event_28,
                },
            ],
        };
        verifier
            .verify_os_image_hash_for_gcp_tdx(
                &gcp_config,
                &gcp_quote(expected_pcr0.to_vec(), uki_hash.clone()),
            )
            .unwrap();
        assert!(verifier
            .verify_os_image_hash_for_gcp_tdx(
                &gcp_config,
                &gcp_quote(vec![0; 32], uki_hash.clone()),
            )
            .is_err());
        assert!(verifier
            .verify_os_image_hash_for_gcp_tdx(
                &gcp_config,
                &gcp_quote(expected_pcr0.to_vec(), vec![0; 32]),
            )
            .is_err());
        let mut missing_document = gcp_config;
        missing_document.gcp_measurement = None;
        assert!(verifier
            .verify_os_image_hash_for_gcp_tdx(
                &missing_document,
                &gcp_quote(expected_pcr0.to_vec(), uki_hash),
            )
            .is_err());
    }

    #[test]
    fn aws_os_image_check_requires_measurement() {
        let pcrs = aws_boot_pcrs(0x04);
        let mut vm_config = aws_vm_config(&pcrs);
        vm_config.aws_measurement = None;

        let err = test_verifier()
            .verify_os_image_hash_for_aws_nitro_tpm(&vm_config, &pcrs)
            .expect_err("missing aws_measurement must fail");
        assert!(format!("{err:#}").contains("aws_measurement is required"));
    }

    #[test]
    fn aws_os_image_check_accepts_bound_measurement() {
        let pcrs = aws_boot_pcrs(0x04);
        test_verifier()
            .verify_os_image_hash_for_aws_nitro_tpm(&aws_vm_config(&pcrs), &pcrs)
            .expect("bound aws_measurement must verify");
    }

    #[test]
    fn aws_os_image_check_rejects_boot_pcr_digest_mismatch() {
        let quoted_pcrs = aws_boot_pcrs(0x04);
        let vm_config = aws_vm_config(&aws_boot_pcrs(0x05));

        let err = test_verifier()
            .verify_os_image_hash_for_aws_nitro_tpm(&vm_config, &quoted_pcrs)
            .expect_err("measurement for different PCRs must fail");
        assert!(format!("{err:#}").contains("boot_pcr_digest mismatch"));
    }

    fn acpi_event(name: &str, digest_byte: u8) -> TdxEvent {
        TdxEvent {
            imr: 0,
            event_type: TDX_ACPI_DATA_EVENT_TYPE,
            digest: vec![digest_byte; 48],
            event: name.to_string(),
            event_payload: TDX_ACPI_DATA_EVENT_PAYLOAD.to_vec(),
            version: Default::default(),
            preimage: None,
        }
    }

    #[test]
    fn tdx_lite_acpi_hashes_are_selected_by_event_name() {
        let event_log = vec![
            acpi_event(TDX_ACPI_RSDP_EVENT, 2),
            acpi_event(TDX_ACPI_TABLES_EVENT, 3),
            acpi_event(TDX_ACPI_LOADER_EVENT, 1),
        ];

        let hashes =
            CvmVerifier::tdx_acpi_hashes_from_event_log(&event_log).expect("named ACPI hashes");

        assert_eq!(hashes.loader, vec![1u8; 48]);
        assert_eq!(hashes.rsdp, vec![2u8; 48]);
        assert_eq!(hashes.tables, vec![3u8; 48]);
    }

    #[test]
    fn tdx_lite_acpi_hashes_reject_unlabeled_events() {
        let event_log = vec![
            acpi_event("", 1),
            acpi_event(TDX_ACPI_RSDP_EVENT, 2),
            acpi_event(TDX_ACPI_TABLES_EVENT, 3),
        ];

        assert!(CvmVerifier::tdx_acpi_hashes_from_event_log(&event_log).is_err());
    }

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

    fn sample_measurements(byte: u8) -> TdxMeasurements {
        TdxMeasurements {
            mrtd: vec![byte; 48],
            rtmr0: vec![byte.wrapping_add(1); 48],
            rtmr1: vec![byte.wrapping_add(2); 48],
            rtmr2: vec![byte.wrapping_add(3); 48],
        }
    }

    #[test]
    fn measurement_cache_version_mismatch_is_ignored_and_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier();
        verifier.image_cache_dir = directory.path().display().to_string();
        let config: VmConfig = serde_json::from_str("{}").unwrap();
        let key = CvmVerifier::vm_config_cache_key(&config).unwrap();
        let path = verifier.measurement_cache_path(&key);
        fs_err::create_dir_all(path.parent().unwrap()).unwrap();

        fs_err::write(
            &path,
            serde_json::to_vec(&CachedMeasurement {
                version: MEASUREMENT_CACHE_VERSION - 1,
                measurements: sample_measurements(0x11),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(verifier
            .load_measurements_from_cache(&key)
            .unwrap()
            .is_none());

        let current = sample_measurements(0x22);
        verifier
            .store_measurements_in_cache(&key, &current)
            .unwrap();
        let loaded = verifier
            .load_measurements_from_cache(&key)
            .unwrap()
            .expect("current cache entry");
        assert_eq!(
            serde_json::to_vec(&loaded).unwrap(),
            serde_json::to_vec(&current).unwrap()
        );
    }

    #[test]
    fn corrupt_measurement_cache_entry_is_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier();
        verifier.image_cache_dir = directory.path().display().to_string();
        let config: VmConfig = serde_json::from_str("{}").unwrap();
        let key = CvmVerifier::vm_config_cache_key(&config).unwrap();
        let path = verifier.measurement_cache_path(&key);
        fs_err::create_dir_all(path.parent().unwrap()).unwrap();
        fs_err::write(path, b"{not json").unwrap();

        assert!(verifier
            .load_measurements_from_cache(&key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn concurrent_measurement_cache_writes_are_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier();
        verifier.image_cache_dir = directory.path().display().to_string();
        let config: VmConfig = serde_json::from_str("{}").unwrap();
        let key = CvmVerifier::vm_config_cache_key(&config).unwrap();
        let first = sample_measurements(0x11);
        let second = sample_measurements(0x22);

        std::thread::scope(|scope| {
            for index in 0..16 {
                let verifier = &verifier;
                let key = &key;
                let measurements = if index % 2 == 0 { &first } else { &second };
                scope.spawn(move || {
                    verifier
                        .store_measurements_in_cache(key, measurements)
                        .unwrap();
                });
            }
        });
        let cached = verifier
            .load_measurements_from_cache(&key)
            .unwrap()
            .expect("one complete cache entry");
        let encoded = serde_json::to_vec(&cached).unwrap();
        assert!(
            encoded == serde_json::to_vec(&first).unwrap()
                || encoded == serde_json::to_vec(&second).unwrap()
        );
        let entries = fs_err::read_dir(verifier.measurement_cache_dir())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1, "temporary cache files must not survive");
    }

    #[test]
    fn image_cache_pruning_keeps_checksum_identity() {
        let dir = tempfile::tempdir().expect("temp image directory");
        let files_doc = "00  metadata.json\n";
        fs_err::write(dir.path().join("sha256sum.txt"), files_doc).unwrap();
        fs_err::write(dir.path().join("metadata.json"), "{}").unwrap();
        fs_err::write(dir.path().join("unmeasured"), "remove me").unwrap();

        CvmVerifier::prune_unlisted_image_files(dir.path(), files_doc).unwrap();

        assert!(dir.path().join("sha256sum.txt").exists());
        assert!(dir.path().join("metadata.json").exists());
        assert!(!dir.path().join("unmeasured").exists());
    }

    #[test]
    fn image_paths_must_be_confined_and_manifest_paths_must_be_flat() {
        for path in ["../escape", "/absolute", "nested/../escape"] {
            assert!(
                !CvmVerifier::is_confined_archive_path(Path::new(path)),
                "{path}"
            );
        }
        // `.` components are stripped by `unpack_in` and cannot escape, so the
        // check must accept them: `tar -czf out.tar.gz .` prefixes every member
        // with `./` and published images are packed that way.
        for path in ["nested/artifact", "./metadata.json", ".", "./", ""] {
            assert!(
                CvmVerifier::is_confined_archive_path(Path::new(path)),
                "{path}"
            );
        }

        let digest = "00".repeat(32);
        assert!(
            CvmVerifier::validate_image_manifest_paths(&format!("{digest}  metadata.json\n"))
                .is_ok()
        );
        for path in [
            "../escape",
            "/absolute",
            "nested/artifact",
            "./metadata.json",
            ".",
            "sha256sum.txt",
        ] {
            assert!(
                CvmVerifier::validate_image_manifest_paths(&format!("{digest}  {path}\n")).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn image_archive_rejects_links_and_accepts_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.tar.gz");
        {
            let file = fs_err::File::create(&valid).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let payload = b"artifact";
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "nested/artifact", &payload[..])
                .unwrap();
            archive.finish().unwrap();
        }
        let output = directory.path().join("valid-output");
        fs_err::create_dir(&output).unwrap();
        CvmVerifier::extract_image_archive(&valid, &output).unwrap();
        assert_eq!(
            fs_err::read(output.join("nested/artifact")).unwrap(),
            b"artifact"
        );

        let linked = directory.path().join("linked.tar.gz");
        {
            let file = fs_err::File::create(&linked).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_link_name("../outside").unwrap();
            header.set_cksum();
            archive.append_data(&mut header, "link", &[][..]).unwrap();
            archive.finish().unwrap();
        }
        let output = directory.path().join("linked-output");
        fs_err::create_dir(&output).unwrap();
        assert!(CvmVerifier::extract_image_archive(&linked, &output).is_err());
    }

    /// Images published on download.dstack.org come in two shapes: members
    /// packed from a glob (`bzImage`, ...) and members packed from `.`
    /// (`./`, `./bzImage`, ...). Both must extract to the same flat layout.
    #[test]
    fn image_archive_accepts_dot_prefixed_members() {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("dot-prefixed.tar.gz");
        {
            let file = fs_err::File::create(&archive_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header, "./", &[][..]).unwrap();
            let payload = b"artifact";
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "./metadata.json", &payload[..])
                .unwrap();
            archive.finish().unwrap();
        }
        let output = directory.path().join("dot-prefixed-output");
        fs_err::create_dir(&output).unwrap();
        CvmVerifier::extract_image_archive(&archive_path, &output).unwrap();
        assert_eq!(
            fs_err::read(output.join("metadata.json")).unwrap(),
            b"artifact"
        );
    }

    /// `GzDecoder` stops at the first member of a concatenated gzip stream and
    /// reports clean EOF, which would truncate the archive without an error.
    #[test]
    fn image_archive_reads_every_gzip_member() {
        let directory = tempfile::tempdir().unwrap();
        let mut tarball = tar::Builder::new(Vec::new());
        let payload = b"artifact";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tarball
            .append_data(&mut header, "metadata.json", &payload[..])
            .unwrap();
        let tarball = tarball.into_inner().unwrap();

        let archive_path = directory.path().join("multi-member.tar.gz");
        {
            use std::io::Write;

            let mut file = fs_err::File::create(&archive_path).unwrap();
            // One gzip member per half of the tar stream.
            for half in tarball.chunks(tarball.len().div_ceil(2)) {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(half).unwrap();
                file.write_all(&encoder.finish().unwrap()).unwrap();
            }
            file.flush().unwrap();
        }
        let output = directory.path().join("multi-member-output");
        fs_err::create_dir(&output).unwrap();
        CvmVerifier::extract_image_archive(&archive_path, &output).unwrap();
        assert_eq!(
            fs_err::read(output.join("metadata.json")).unwrap(),
            b"artifact"
        );
    }

    #[tokio::test]
    async fn verifies_sev_snp_attestation_fixture_without_image_download() {
        let request: VerificationRequest =
            serde_json::from_str(include_str!("../fixtures/sev-snp-attestation.json"))
                .expect("SNP verifier fixture parses");
        let cache = tempfile::tempdir().expect("temp cache dir");
        let image_cache_dir = cache.path().join("cache");
        let verifier = CvmVerifier::new(
            image_cache_dir.display().to_string(),
            "http://127.0.0.1:9/should-not-download/{OS_IMAGE_HASH}.tar.gz".to_string(),
            Duration::from_secs(1),
            test_attestation_verifier(),
        );

        let response = verifier.verify(request).await.expect("verifier runs");
        assert!(response.is_valid, "{:?}", response.reason);
        assert!(response.details.quote_verified);
        assert!(response.details.event_log_verified);
        assert!(response.details.os_image_hash_verified);
        assert!(!response.details.acpi_tables_verified);
        assert_eq!(
            response.details.tee_variant,
            Some(ra_tls::attestation::TeeVariant::DstackAmdSevSnp)
        );
        assert!(
            !image_cache_dir.exists(),
            "SNP verification must not download or cache OS images"
        );
    }

    #[tokio::test]
    async fn attestation_fixture_ignores_conflicting_top_level_inputs() {
        let mut request: VerificationRequest =
            serde_json::from_str(include_str!("../fixtures/sev-snp-attestation.json"))
                .expect("SNP verifier fixture parses");
        request.quote = Some(vec![0]);
        request.event_log = Some("[]".to_string());
        request.vm_config = Some("not-json".to_string());
        let cache = tempfile::tempdir().expect("temp cache dir");
        let verifier = CvmVerifier::new(
            cache.path().join("cache").display().to_string(),
            "http://127.0.0.1:9/should-not-download/{OS_IMAGE_HASH}.tar.gz".to_string(),
            Duration::from_secs(1),
            test_attestation_verifier(),
        );

        let response = verifier.verify(request).await.expect("verifier runs");
        assert!(response.is_valid, "{:?}", response.reason);
        assert_eq!(
            response.details.tee_variant,
            Some(ra_tls::attestation::TeeVariant::DstackAmdSevSnp)
        );
    }

    /// The fixture was captured from a real CVM, so its RTMR0 ACPI digests are
    /// whatever QEMU actually produced. Reproducing them without the image
    /// proves the generator agrees with hardware, not just with itself.
    #[tokio::test]
    async fn verifies_tdx_lite_fixture_without_image_download() {
        let request: VerificationRequest =
            serde_json::from_str(include_str!("../fixtures/tdx-lite-attestation.json"))
                .expect("TDX lite verifier fixture parses");
        let cache = tempfile::tempdir().expect("temp cache dir");
        let image_cache_dir = cache.path().join("cache");
        let verifier = CvmVerifier::new(
            image_cache_dir.display().to_string(),
            "http://127.0.0.1:9/should-not-download/{OS_IMAGE_HASH}.tar.gz".to_string(),
            Duration::from_secs(1),
            test_attestation_verifier(),
        );

        let response = verifier.verify(request).await.expect("verifier runs");
        assert!(response.is_valid, "{:?}", response.reason);
        assert!(response.details.quote_verified);
        assert!(response.details.event_log_verified);
        assert!(response.details.os_image_hash_verified);
        assert!(response.details.acpi_tables_verified);
        assert_eq!(
            response.details.tee_variant,
            Some(ra_tls::attestation::TeeVariant::DstackTdx)
        );
        assert!(
            !image_cache_dir.exists(),
            "TDX lite verification must not download or cache OS images"
        );
    }

    /// The captured VM ran 2 vCPUs; a VM shape that disagrees with the quote
    /// must not reproduce its ACPI digests, which is what makes the recomputed
    /// digests worth comparing in the first place.
    #[test]
    fn tdx_lite_acpi_hashes_depend_on_the_reported_vm_shape() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/tdx-lite-getquote.json"))
                .expect("TDX lite getquote fixture parses");
        let mut vm_config: VmConfig = serde_json::from_str(
            fixture["vm_config"]
                .as_str()
                .expect("vm_config is a string"),
        )
        .expect("fixture vm_config parses");
        let event_log: Vec<TdxEvent> = serde_json::from_str(
            fixture["event_log"]
                .as_str()
                .expect("event_log is a string"),
        )
        .expect("fixture event log parses");
        let ovmf_variant = vm_config.ovmf_variant.unwrap_or_default();

        let reported = CvmVerifier::tdx_acpi_hashes_from_event_log(&event_log)
            .expect("fixture carries named ACPI digests");
        let expected = dstack_mr::tdx::expected_rtmr0_acpi_hashes(&vm_config, ovmf_variant)
            .expect("ACPI tables are generated for the fixture VM shape");
        CvmVerifier::assert_tdx_acpi_hashes_match(&expected, &reported)
            .expect("recomputed digests match the captured CVM");

        vm_config.cpu_count += 1;
        let expected = dstack_mr::tdx::expected_rtmr0_acpi_hashes(&vm_config, ovmf_variant)
            .expect("ACPI tables are generated for the altered VM shape");
        CvmVerifier::assert_tdx_acpi_hashes_match(&expected, &reported)
            .expect_err("an extra vCPU must change the ACPI tables");
    }

    #[test]
    fn tdx_lite_acpi_hash_mismatch_names_the_table() {
        let expected = TdxRtmr0AcpiHashes {
            loader: vec![1; 48],
            rsdp: vec![2; 48],
            tables: vec![3; 48],
        };
        let mut reported = expected.clone();
        reported.tables = vec![4; 48];
        let err = CvmVerifier::assert_tdx_acpi_hashes_match(&expected, &reported)
            .expect_err("mismatched tables digest is rejected");
        assert!(err.to_string().contains(TDX_ACPI_TABLES_EVENT), "{err:#}");
        assert!(CvmVerifier::assert_tdx_acpi_hashes_match(&expected, &expected).is_ok());
    }
}
