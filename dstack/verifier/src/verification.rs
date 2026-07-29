// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    io::Read,
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
use dstack_types::VmConfig;
use hex_literal::hex;
use ra_tls::attestation::{
    AppInfo, Attestation, AttestationQuote, AttestationVerifier, DstackVerifiedReport, NitroPcrs,
    TpmQuote, VerifiedAttestation, VersionedAttestation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::types::{
    AcpiTables, PolicyBootInfo, RtmrEventEntry, RtmrEventStatus, RtmrMismatch, VerificationDetails,
    VerificationRequest, VerificationResponse,
};

/// Return the canonical TCB status and advisory list used by auth policy.
pub fn policy_tcb_fields(attestation: &VerifiedAttestation) -> (String, Vec<String>) {
    match &attestation.report {
        DstackVerifiedReport::DstackAmdSevSnp(report) => (
            report.tcb_info.tcb_status().to_string(),
            report.advisory_ids.clone(),
        ),
        // AWS NitroTPM has no TDX/SNP-style TCB surface; a verified attestation
        // is normalized to "UpToDate" so the verifier's policy boot info matches
        // the KMS bootAuth payload and passes the shared "UpToDate" auth gate.
        // Other no-TCB platforms (e.g. nitro enclave) stay empty and fail-closed.
        DstackVerifiedReport::DstackAwsNitroTpm(_) => ("UpToDate".to_string(), Vec::new()),
        _ => attestation
            .report
            .tdx_report()
            .map(|report| (report.status.clone(), report.advisory_ids.clone()))
            .unwrap_or_default(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsImageVerificationStrategy {
    TdxFullDownload,
    TdxLiteMeasurement,
    SevSnpMeasurement,
    GcpTdxMeasurement,
    NitroEnclavePcrs,
    AwsNitroTpmPcrs,
}

impl OsImageVerificationStrategy {
    fn select(quote: &AttestationQuote, vm_config: &VmConfig) -> Self {
        match quote {
            AttestationQuote::DstackTdx(_) => {
                if vm_config.tdx_attestation_variant.is_lite()
                    || vm_config.tdx_measurement.is_some()
                {
                    Self::TdxLiteMeasurement
                } else {
                    Self::TdxFullDownload
                }
            }
            AttestationQuote::DstackAmdSevSnp(_) => Self::SevSnpMeasurement,
            AttestationQuote::DstackGcpTdx(_) => Self::GcpTdxMeasurement,
            AttestationQuote::DstackNitroEnclave(_) => Self::NitroEnclavePcrs,
            AttestationQuote::DstackAwsNitroTpm(_) => Self::AwsNitroTpmPcrs,
        }
    }
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

    fn measurement_cache_key_for_version(vm_config: &VmConfig, version: u32) -> Result<String> {
        let serialized = serde_json::to_vec(vm_config)
            .context("Failed to serialize VM config for cache key computation")?;
        let mut hasher = Sha256::new();
        hasher.update(b"dstack-verifier-measurement-cache");
        hasher.update(version.to_le_bytes());
        hasher.update(serialized);
        Ok(hex::encode(hasher.finalize()))
    }

    fn vm_config_cache_key(vm_config: &VmConfig) -> Result<String> {
        Self::measurement_cache_key_for_version(vm_config, MEASUREMENT_CACHE_VERSION)
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

    fn parse_image_manifest(files_doc: &str) -> Result<Vec<(PathBuf, [u8; 32])>> {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        for (line_index, line) in files_doc.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let digest = fields
                .next()
                .context("image manifest entry is missing a digest")?;
            let name = fields
                .next()
                .context("image manifest entry is missing a path")?;
            if fields.next().is_some() {
                bail!("image manifest line {} has extra fields", line_index + 1);
            }
            let path = PathBuf::from(name);
            if path.as_os_str().is_empty()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                bail!("image manifest line {} has an unsafe path", line_index + 1);
            }
            if path == Path::new("sha256sum.txt") {
                bail!("image manifest must not recursively list sha256sum.txt");
            }
            if !seen.insert(path.clone()) {
                bail!("image manifest contains duplicate path {}", path.display());
            }
            let digest: [u8; 32] = hex::decode(digest)
                .context("image manifest digest is not hexadecimal")?
                .try_into()
                .map_err(|_| anyhow!("image manifest digest is not SHA-256"))?;
            entries.push((path, digest));
        }
        if entries.is_empty() {
            bail!("image manifest contains no artifacts");
        }
        Ok(entries)
    }

    fn extract_image_archive(tarball_path: &Path, extracted_dir: &Path) -> Result<()> {
        let file = fs_err::File::open(tarball_path).context("Failed to open image archive")?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().context("Failed to read image archive")? {
            let mut entry = entry.context("Failed to read image archive entry")?;
            let path = entry
                .path()
                .context("Failed to decode image archive path")?;
            if path.as_os_str().is_empty()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                bail!("image archive contains unsafe path {}", path.display());
            }
            let kind = entry.header().entry_type();
            if !(kind.is_file() || kind.is_dir()) {
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

    fn verify_image_manifest(extracted_dir: &Path, entries: &[(PathBuf, [u8; 32])]) -> Result<()> {
        for (path, expected) in entries {
            let artifact = extracted_dir.join(path);
            let metadata = fs_err::symlink_metadata(&artifact)
                .with_context(|| format!("manifest artifact is missing: {}", path.display()))?;
            if !metadata.file_type().is_file() {
                bail!(
                    "manifest artifact is not a regular file: {}",
                    path.display()
                );
            }
            let mut file = fs_err::File::open(&artifact)
                .with_context(|| format!("failed to open manifest artifact {}", path.display()))?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).with_context(|| {
                    format!("failed to read manifest artifact {}", path.display())
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            if hasher.finalize().as_slice() != expected {
                bail!("checksum mismatch for manifest artifact {}", path.display());
            }
        }
        Ok(())
    }

    fn prune_unlisted_image_files(
        extracted_dir: &Path,
        entries: &[(PathBuf, [u8; 32])],
    ) -> Result<()> {
        let listed = entries
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<HashSet<_>>();
        let mut allowed_dirs = HashSet::new();
        for path in &listed {
            let mut parent = path.parent();
            while let Some(path) = parent {
                if path.as_os_str().is_empty() {
                    break;
                }
                allowed_dirs.insert(path.to_path_buf());
                parent = path.parent();
            }
        }
        let mut pending = vec![extracted_dir.to_path_buf()];
        let mut directories = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in fs_err::read_dir(&directory).context("Failed to read image directory")? {
                let entry = entry.context("Failed to read image directory entry")?;
                let path = entry.path();
                let relative = path
                    .strip_prefix(extracted_dir)
                    .context("image cache path escaped its root")?
                    .to_path_buf();
                let kind = entry
                    .file_type()
                    .context("Failed to inspect image cache entry")?;
                if kind.is_dir() {
                    pending.push(path.clone());
                    directories.push((path, relative));
                } else if relative != Path::new("sha256sum.txt") && !listed.contains(&relative) {
                    fs_err::remove_file(&path).context("Failed to remove unlisted image file")?;
                }
            }
        }
        directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, relative) in directories {
            if !allowed_dirs.contains(&relative) {
                fs_err::remove_dir_all(path)
                    .context("Failed to remove unlisted image directory")?;
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
        let mut details = VerificationDetails {
            simulated: self.attestation_verifier.is_simulated(),
            ..Default::default()
        };

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
        match OsImageVerificationStrategy::select(&attestation.quote, &vm_config) {
            OsImageVerificationStrategy::GcpTdxMeasurement => {
                let AttestationQuote::DstackGcpTdx(quote) = &attestation.quote else {
                    unreachable!("strategy selector returned the wrong GCP TDX branch")
                };
                self.verify_os_image_hash_for_gcp_tdx(&vm_config, &quote.tpm_quote)?;
            }
            OsImageVerificationStrategy::TdxLiteMeasurement => {
                self.verify_os_image_hash_for_dstack_tdx_lite(
                    &vm_config,
                    attestation,
                    debug,
                    details,
                )
                .await?;
            }
            OsImageVerificationStrategy::TdxFullDownload => {
                self.verify_os_image_hash_for_dstack_tdx(&vm_config, attestation, debug, details)
                    .await?;
            }
            OsImageVerificationStrategy::NitroEnclavePcrs => {
                let DstackVerifiedReport::DstackNitroEnclave(report) = &attestation.report else {
                    bail!("internal error: nitro quote without a verified nitro report");
                };
                self.verify_os_image_hash_for_nitro_enclave(&vm_config, &report.pcrs)?;
            }
            OsImageVerificationStrategy::AwsNitroTpmPcrs => {
                let DstackVerifiedReport::DstackAwsNitroTpm(report) = &attestation.report else {
                    bail!("internal error: NitroTPM quote without a verified NitroTPM report");
                };
                self.verify_os_image_hash_for_aws_nitro_tpm(&vm_config, &report.pcrs)?;
            }
            OsImageVerificationStrategy::SevSnpMeasurement => {
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
        _details: &mut VerificationDetails,
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
        // downloading the image or running QEMU-derived ACPI table generators.
        // The guest labels the three RTMR0 ACPI DATA events as acpi-loader,
        // acpi-rsdp, and acpi-tables before exposing the event log, so the
        // verifier does not guess based on event order.
        let acpi_hashes = Self::tdx_acpi_hashes_from_event_log(event_log)
            .context("TDX lite attestation is missing named RTMR0 ACPI DATA digests")?;
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
        let manifest = Self::parse_image_manifest(&files_doc)?;
        Self::verify_image_manifest(&extracted_dir, &manifest)?;
        Self::prune_unlisted_image_files(&extracted_dir, &manifest)?;

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
    use std::fmt::Write as _;

    use super::*;

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
    fn measurement_cache_key_binds_config_and_algorithm_version() {
        let base: VmConfig = serde_json::from_str("{}").unwrap();
        let base_key = CvmVerifier::vm_config_cache_key(&base).unwrap();
        assert_eq!(base_key, CvmVerifier::vm_config_cache_key(&base).unwrap());

        let mut changed = base.clone();
        changed.cpu_count = 2;
        assert_ne!(
            base_key,
            CvmVerifier::vm_config_cache_key(&changed).unwrap()
        );
        changed = base.clone();
        changed.os_image_hash = vec![0x42; 32];
        assert_ne!(
            base_key,
            CvmVerifier::vm_config_cache_key(&changed).unwrap()
        );
        changed = base.clone();
        changed.swtpm = true;
        assert_ne!(
            base_key,
            CvmVerifier::vm_config_cache_key(&changed).unwrap()
        );
        assert_ne!(
            base_key,
            CvmVerifier::measurement_cache_key_for_version(&base, MEASUREMENT_CACHE_VERSION + 1,)
                .unwrap()
        );
    }

    #[test]
    fn measurement_cache_rejects_corrupt_and_stale_entries() {
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier();
        verifier.image_cache_dir = directory.path().display().to_string();
        let config: VmConfig = serde_json::from_str("{}").unwrap();
        let key = CvmVerifier::vm_config_cache_key(&config).unwrap();
        let path = verifier.measurement_cache_path(&key);
        fs_err::create_dir_all(path.parent().unwrap()).unwrap();

        fs_err::write(&path, b"{not json").unwrap();
        assert!(verifier
            .load_measurements_from_cache(&key)
            .unwrap()
            .is_none());
        fs_err::write(
            &path,
            serde_json::to_vec(&CachedMeasurement {
                version: MEASUREMENT_CACHE_VERSION + 1,
                measurements: sample_measurements(1),
            })
            .unwrap(),
        )
        .unwrap();
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
        let files_doc =
            "0000000000000000000000000000000000000000000000000000000000000000  metadata.json\n";
        fs_err::write(dir.path().join("sha256sum.txt"), files_doc).unwrap();
        fs_err::write(dir.path().join("metadata.json"), "{}").unwrap();
        fs_err::write(dir.path().join("unmeasured"), "remove me").unwrap();

        let manifest = CvmVerifier::parse_image_manifest(files_doc).unwrap();
        CvmVerifier::prune_unlisted_image_files(dir.path(), &manifest).unwrap();

        assert!(dir.path().join("sha256sum.txt").exists());
        assert!(dir.path().join("metadata.json").exists());
        assert!(!dir.path().join("unmeasured").exists());
    }

    #[test]
    fn image_manifest_rejects_unsafe_duplicate_and_invalid_entries() {
        for document in [
            "00  ../escape\n",
            "00  /absolute\n",
            "00  nested/../escape\n",
            &format!(
                "{}  artifact\n{}  artifact\n",
                "00".repeat(32),
                "00".repeat(32)
            ),
            "not-a-digest  artifact\n",
            "",
        ] {
            assert!(
                CvmVerifier::parse_image_manifest(document).is_err(),
                "{document:?}"
            );
        }
    }

    #[test]
    fn image_archive_rejects_links_and_accepts_valid_nested_files() {
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

    #[tokio::test]
    async fn image_download_digest_redirect_timeout_and_retry_matrix() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        fn archive(link: bool) -> (Vec<u8>, String) {
            let metadata = br#"{"bios":"nested/firmware","kernel":"nested/kernel","initrd":"nested/initrd","cmdline":"console=ttyS0","is_dev":true,"version":"test"}"#;
            let artifacts = [
                ("metadata.json", metadata.as_slice()),
                ("nested/firmware", b"firmware".as_slice()),
                ("nested/kernel", b"kernel".as_slice()),
                ("nested/initrd", b"initrd".as_slice()),
            ];
            let files_doc = artifacts
                .iter()
                .map(|(name, data)| format!("{}  {name}\n", hex::encode(Sha256::digest(data))))
                .collect::<String>();
            let mut encoded = Vec::new();
            {
                let encoder =
                    flate2::write::GzEncoder::new(&mut encoded, flate2::Compression::default());
                let mut tar = tar::Builder::new(encoder);
                for (name, data) in artifacts {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_cksum();
                    tar.append_data(&mut header, name, data).unwrap();
                }
                let mut header = tar::Header::new_gnu();
                header.set_size(files_doc.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, "sha256sum.txt", files_doc.as_bytes())
                    .unwrap();
                let unlisted = b"must be pruned";
                let mut header = tar::Header::new_gnu();
                header.set_size(unlisted.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, "unlisted", &unlisted[..])
                    .unwrap();
                if link {
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_mode(0o777);
                    header.set_link_name("../outside").unwrap();
                    header.set_cksum();
                    tar.append_data(&mut header, "nested/link", &[][..])
                        .unwrap();
                }
                tar.finish().unwrap();
                tar.into_inner().unwrap().finish().unwrap();
            }
            let hash = hex::encode(Sha256::digest(files_doc.as_bytes()));
            (encoded, hash)
        }

        async fn server(
            responses: Vec<(u16, Vec<(String, String)>, Vec<u8>, Duration)>,
        ) -> (String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let observed = count.clone();
            let task = tokio::spawn(async move {
                for (status, headers, body, delay) in responses {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = vec![0u8; 4096];
                    let _ = stream.read(&mut request).await.unwrap();
                    observed.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let reason = if status == 200 {
                        "OK"
                    } else if status == 302 {
                        "Found"
                    } else {
                        "Error"
                    };
                    let mut response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    for (name, value) in headers {
                        writeln!(&mut response, "{name}: {value}\r").unwrap();
                    }
                    response.push_str("\r\n");
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                }
            });
            (format!("http://{address}"), task, count)
        }

        fn verifier(url: &str, cache: &Path, timeout: Duration) -> CvmVerifier {
            CvmVerifier::new(
                cache.display().to_string(),
                format!("{url}/{{OS_IMAGE_HASH}}.tar.gz"),
                timeout,
                test_attestation_verifier(),
            )
        }

        let (valid, hash) = archive(false);
        let cache = tempfile::tempdir().unwrap();
        let destination = cache.path().join("images").join(&hash);
        let (url, task, count) = server(vec![(200, vec![], valid.clone(), Duration::ZERO)]).await;
        verifier(&url, cache.path(), Duration::from_secs(1))
            .download_image(&hash, &destination)
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(destination.join("metadata.json").is_file());
        assert!(!destination.join("unlisted").exists());

        let wrong = "00".repeat(32);
        let wrong_destination = cache.path().join("images").join(&wrong);
        let (url, task, _) = server(vec![(200, vec![], valid.clone(), Duration::ZERO)]).await;
        assert!(verifier(&url, cache.path(), Duration::from_secs(1))
            .download_image(&wrong, &wrong_destination)
            .await
            .is_err());
        task.await.unwrap();
        assert!(!wrong_destination.exists());

        let truncated_destination = cache.path().join("images/truncated");
        let (url, task, _) =
            server(vec![(200, vec![], b"truncated".to_vec(), Duration::ZERO)]).await;
        assert!(verifier(&url, cache.path(), Duration::from_secs(1))
            .download_image("truncated", &truncated_destination)
            .await
            .is_err());
        task.await.unwrap();
        assert!(!truncated_destination.exists());

        let (linked, linked_hash) = archive(true);
        let linked_cache = tempfile::tempdir().unwrap();
        let linked_destination = linked_cache.path().join("images").join(&linked_hash);
        let (url, task, _) = server(vec![(200, vec![], linked, Duration::ZERO)]).await;
        assert!(verifier(&url, linked_cache.path(), Duration::from_secs(1))
            .download_image(&linked_hash, &linked_destination)
            .await
            .is_err());
        task.await.unwrap();
        assert!(!linked_destination.exists());

        let redirect_destination = cache.path().join("images/redirect");
        let (url, task, count) = server(vec![
            (
                302,
                vec![("Location".into(), format!("/actual/{hash}.tar.gz"))],
                vec![],
                Duration::ZERO,
            ),
            (200, vec![], valid.clone(), Duration::ZERO),
        ])
        .await;
        verifier(&url, cache.path(), Duration::from_secs(1))
            .download_image(&hash, &redirect_destination)
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);

        let timeout_cache = tempfile::tempdir().unwrap();
        let (url, task, _) = server(vec![(
            200,
            vec![],
            valid.clone(),
            Duration::from_millis(150),
        )])
        .await;
        let timed = verifier(&url, timeout_cache.path(), Duration::from_millis(20));
        let vm_config: VmConfig = serde_json::from_value(serde_json::json!({
            "os_image_hash": hash,
        }))
        .unwrap();
        assert!(timed.ensure_image_downloaded(&vm_config).await.is_err());
        task.abort();
        assert!(!timeout_cache.path().join("images").join(&hash).exists());

        let (url, task, _) = server(vec![(200, vec![], valid, Duration::ZERO)]).await;
        verifier(&url, timeout_cache.path(), Duration::from_secs(1))
            .ensure_image_downloaded(&vm_config)
            .await
            .unwrap();
        task.await.unwrap();
        assert!(timeout_cache.path().join("images").join(&hash).is_dir());
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

    #[tokio::test]
    async fn verifies_tdx_lite_fixture_without_acpi_table_verification() {
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
        assert!(!response.details.acpi_tables_verified);
        assert_eq!(
            response.details.tee_variant,
            Some(ra_tls::attestation::TeeVariant::DstackTdx)
        );
        assert!(
            !image_cache_dir.exists(),
            "TDX lite verification must not download or cache OS images"
        );
    }
}
