// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Build-time TDX OS-image static measurement material.
//!
//! The current verifier path recomputes TDX MRs from a downloaded image. This
//! module emits the image-static material needed by the no-image-download path:
//! MRTD candidates, compact TD HOB witness, command line, kernel/initrd digests
//! and sizes. VM-specific inputs (RAM size, vCPU count, QEMU topology knobs) are
//! intentionally excluded and must come from `VmConfig`.

use crate::kernel::{
    kernel_authenticode_sha384, patched_kernel_authenticode_sha384,
    tdx_kernel_hash_uses_precomputed_high_mem, TDX_KERNEL_HASH_COMPAT_2G_MEMORY,
    TDX_KERNEL_HASH_STABLE_MIN_MEMORY,
};
use crate::tdvf::{
    rtmr0_log_from_td_hob_hash_with_acpi_hashes, AcpiTableHashes, Tdvf, MAX_TDVF_SECTIONS,
};
use crate::util::{measure_log, measure_sha384};
use anyhow::{bail, Context, Result};
use cc_eventlog::{
    tdx::{
        TDX_ACPI_DATA_EVENT_PAYLOAD, TDX_ACPI_DATA_EVENT_TYPE, TDX_ACPI_LOADER_EVENT,
        TDX_ACPI_RSDP_EVENT, TDX_ACPI_TABLES_EVENT,
    },
    TdxEvent,
};
use dstack_types::{
    OvmfVariant, TdxAttestationVariant, TdxImageMeasurement, TdxMrtdCandidates,
    TdxOsImageMeasurement, TdxOsImageMeasurementDocument, TdxTdvfMeasurement, VmConfig,
};
use fs_err as fs;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ImageMetadata {
    #[serde(default)]
    cmdline: Option<String>,
    kernel: String,
    initrd: String,
    bios: String,
    #[serde(default)]
    ovmf_variant: Option<OvmfVariant>,
    /// Declares whether this image's OVMF normalizes the Linux setup header
    /// before measuring the kernel. Absent on every image built before that
    /// landed, and `false` is exactly their behavior.
    #[serde(default)]
    kernel_header_normalized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxRtmr0AcpiHashes {
    pub loader: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub tables: Vec<u8>,
}

/// Outcome of [`verify_tdx_lite_os`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxLiteOsCheck {
    pub os_image_hash: Vec<u8>,
    pub acpi_tables_verified: bool,
}

#[derive(Debug, Clone)]
pub struct TdxMeasurementsWithoutRtmr0 {
    pub mrtd: Vec<u8>,
    pub rtmr1: Vec<u8>,
    pub rtmr2: Vec<u8>,
}

fn validate_bytes_field(value: &[u8], field: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.len() != expected_len {
        bail!(
            "{field} has invalid length {}, expected {expected_len}",
            value.len()
        );
    }
    Ok(value.to_vec())
}

/// Build the machine description the lite path measures against.
///
/// Only the VM-shape inputs matter here: the firmware, kernel and initrd paths
/// stay empty because the lite path never reads image files, and the callers
/// (MRTD candidate selection and ACPI table generation) only consume the QEMU
/// topology knobs.
fn machine_from_vm_config(vm_config: &VmConfig, ovmf_variant: OvmfVariant) -> crate::Machine<'_> {
    crate::Machine::builder()
        .cpu_count(vm_config.cpu_count)
        .memory_size(vm_config.memory_size)
        .firmware("")
        .kernel("")
        .initrd("")
        .kernel_cmdline("")
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
        .numa_nodes(&vm_config.numa_nodes)
        .num_gpus(vm_config.num_gpus)
        .num_nics(vm_config.num_nics)
        .num_verity_volumes(vm_config.num_verity_volumes)
        .extra_root_devices(&vm_config.extra_root_devices)
        .swtpm(vm_config.swtpm)
        .num_nvswitches(vm_config.num_nvswitches)
        .host_share_mode(vm_config.host_share_mode.clone())
        .ovmf_variant(ovmf_variant)
        .build()
}

/// Recompute the three RTMR0 ACPI digests from the VM shape in `vm_config`.
///
/// The ACPI tables QEMU hands to OVMF depend only on the deployment topology
/// (vCPU count, RAM size, PCI devices, QEMU version), never on the OS image, so
/// they can be regenerated without downloading anything. The lite path
/// otherwise replays the digests the guest reported in its event log, which
/// makes those three RTMR0 entries self-consistent but unconstrained; comparing
/// against these expected digests is what turns them into a verified value.
/// The verifier does exactly that on both TDX paths, and treats a mismatch --
/// and a VM shape this cannot model -- as fatal rather than unverified.
pub fn expected_rtmr0_acpi_hashes(
    vm_config: &VmConfig,
    ovmf_variant: OvmfVariant,
) -> Result<TdxRtmr0AcpiHashes> {
    let tables = machine_from_vm_config(vm_config, ovmf_variant)
        .build_tables()
        .context("failed to generate expected ACPI tables")?;
    Ok(TdxRtmr0AcpiHashes {
        loader: measure_sha384(&tables.loader),
        rsdp: measure_sha384(&tables.rsdp),
        tables: measure_sha384(&tables.tables),
    })
}

fn select_mrtd(measurement: &TdxOsImageMeasurement, vm_config: &VmConfig) -> Result<Vec<u8>> {
    let machine = machine_from_vm_config(vm_config, measurement.tdvf.ovmf_variant);
    let opts = machine
        .versioned_options()
        .context("failed to resolve QEMU measurement options")?;
    let mrtd = if opts.two_pass_add_pages {
        &measurement.tdvf.mrtd.two_pass
    } else {
        &measurement.tdvf.mrtd.single_pass
    };
    validate_bytes_field(mrtd, "tdx.measurement.tdvf.mrtd", 48)
}

fn read_varuint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let (&byte, rest) = input
            .split_first()
            .context("truncated TD HOB witness varuint")?;
        *input = rest;
        if shift == 63 && byte & 0x7e != 0 {
            bail!("TD HOB witness varuint is too large");
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            bail!("TD HOB witness varuint is too large");
        }
    }
}

/// q35 keeps guest RAM in one block below 4G until it reaches this size, then
/// caps the below-4G block at 2 GiB and moves the remainder above 4G
/// (`lowmem = 0xb0000000 unless ram_size >= 0xb0000000`). The TD HOB memory
/// ranges follow that split.
const Q35_HIGH_MEMORY_SPLIT: u64 = 0xB000_0000;

/// Largest number of accepted ranges a TD HOB witness may declare. The witness
/// carries one range per TD_HOB/TEMP_MEM section -- four in the real metadata
/// -- so the TDVF section-table limit is an upper bound no firmware the parser
/// accepts can reach. On the TDX-lite path the witness bytes come from
/// `vm_config.tdx_measurement`, which the requester authors, and a range costs
/// about two bytes there while `MemoryAcceptor::accept` rebuilds and re-sorts
/// the whole range vector per call: a 1 MiB body is a quarter-million ranges
/// and O(n^2 log n) work.
const MAX_TD_HOB_WITNESS_RANGES: u64 = MAX_TDVF_SECTIONS as u64;

fn measure_td_hob_from_witness_data(data: &[u8], memory_size: u64) -> Result<Vec<u8>> {
    let mut input = data;
    let base_page = read_varuint(&mut input)?;
    let td_hob_page_delta = read_varuint(&mut input)?;
    let range_count = read_varuint(&mut input)?;
    if range_count > MAX_TD_HOB_WITNESS_RANGES {
        bail!("TD HOB witness declares {range_count} ranges, more than the {MAX_TD_HOB_WITNESS_RANGES} supported");
    }
    let td_hob_base_addr = base_page
        .checked_add(td_hob_page_delta)
        .and_then(|page| page.checked_mul(0x1000))
        .context("TD HOB base address overflow")?;

    let mut memory_acceptor = MemoryAcceptor::new(0, memory_size);
    for _ in 0..range_count {
        let start_page_delta = read_varuint(&mut input)?;
        let page_count = read_varuint(&mut input)?;
        let start = base_page
            .checked_add(start_page_delta)
            .and_then(|page| page.checked_mul(0x1000))
            .context("TD HOB range start overflow")?;
        let len = page_count
            .checked_mul(0x1000)
            .context("TD HOB range length overflow")?;
        let end = start
            .checked_add(len)
            .context("TD HOB range end overflow")?;
        memory_acceptor.accept(start, end);
    }
    if !input.is_empty() {
        bail!("TD HOB witness has trailing bytes");
    }

    let mut td_hob = Vec::new();
    td_hob.extend_from_slice(&[0x01, 0x00]); // HobType
    td_hob.extend_from_slice(&56u16.to_le_bytes()); // HobLength
    td_hob.extend_from_slice(&[0u8; 4]); // Reserved
    td_hob.extend_from_slice(&9u32.to_le_bytes()); // Version
    td_hob.extend_from_slice(&[0u8; 4]); // BootMode
    td_hob.extend_from_slice(&[0u8; 8]); // EfiMemoryTop
    td_hob.extend_from_slice(&[0u8; 8]); // EfiMemoryBottom
    td_hob.extend_from_slice(&[0u8; 8]); // EfiFreeMemoryTop
    td_hob.extend_from_slice(&[0u8; 8]); // EfiFreeMemoryBottom
    td_hob.extend_from_slice(&[0u8; 8]); // EfiEndOfHobList (placeholder)

    let mut add_memory_resource_hob = |resource_type: u8, start: u64, length: u64| {
        td_hob.extend_from_slice(&[0x03, 0x00]); // HobType
        td_hob.extend_from_slice(&48u16.to_le_bytes()); // HobLength
        td_hob.extend_from_slice(&[0u8; 4]); // Reserved
        td_hob.extend_from_slice(&[0u8; 16]); // Owner
        td_hob.extend_from_slice(&resource_type.to_le_bytes());
        td_hob.extend_from_slice(&[0u8; 3]); // Padding for resource type
        td_hob.extend_from_slice(&7u32.to_le_bytes()); // ResourceAttribute
        td_hob.extend_from_slice(&start.to_le_bytes());
        td_hob.extend_from_slice(&length.to_le_bytes());
    };

    let (_, last_start, last_end) = memory_acceptor.ranges.pop().context("No ranges")?;

    for (accepted, start, end) in memory_acceptor.ranges {
        if end < start {
            bail!("Invalid memory range: end < start");
        }
        let size = end - start;
        if accepted {
            add_memory_resource_hob(0x00, start, size);
        } else {
            add_memory_resource_hob(0x07, start, size);
        }
    }

    if last_end < last_start {
        bail!("Invalid last memory range: end < start");
    }
    if memory_size >= Q35_HIGH_MEMORY_SPLIT {
        if last_start < 0x80000000u64 {
            add_memory_resource_hob(0x07, last_start, 0x80000000u64 - last_start);
        }
        if last_end > 0x80000000u64 {
            add_memory_resource_hob(0x07, 0x100000000, last_end - 0x80000000u64);
        }
    } else {
        add_memory_resource_hob(0x07, last_start, last_end - last_start);
    }

    let end_of_hob_list = td_hob_base_addr
        .checked_add(td_hob.len() as u64 + 8)
        .context("TD HOB end-of-list address overflow")?;
    td_hob[48..56].copy_from_slice(&end_of_hob_list.to_le_bytes());

    Ok(measure_sha384(&td_hob))
}

struct MemoryAcceptor {
    ranges: Vec<(bool, u64, u64)>,
}

impl MemoryAcceptor {
    fn new(start: u64, size: u64) -> Self {
        Self {
            ranges: vec![(false, start, start + size)],
        }
    }

    fn accept(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        let mut new_ranges = Vec::new();

        for &(is_accepted, range_start, range_end) in &self.ranges {
            if is_accepted || range_end <= start || range_start >= end {
                new_ranges.push((is_accepted, range_start, range_end));
            } else {
                if range_start < start {
                    new_ranges.push((false, range_start, start));
                }
                if range_end > end {
                    new_ranges.push((false, end, range_end));
                }
            }
        }
        new_ranges.push((true, start, end));
        new_ranges.sort_by_key(|&(_, start, _)| start);
        self.ranges = new_ranges;
    }
}

fn rtmr1_log_from_kernel_hash(kernel_hash: Vec<u8>) -> Vec<Vec<u8>> {
    vec![
        kernel_hash,
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
        measure_sha384(b"Exit Boot Services Invocation"),
        measure_sha384(b"Exit Boot Services Returned with Success"),
    ]
}

/// The kernel command-line suffix OVMF appends before measuring.
///
/// `QemuKernelLoaderFsDxe` exposes the initrd as a loader-fs file and appends
/// this so the kernel picks it up, so the measured command line is never the
/// bare image-provided one. Every site that reconstructs the measured command
/// line must go through [`measured_kernel_cmdline`] rather than restating this.
pub const OVMF_INITRD_CMDLINE_SUFFIX: &str = " initrd=initrd";

/// Return the measured TDX kernel command line for a metadata cmdline.
///
/// This mirrors the existing dstack TDX measurement replay path, which measures
/// the image-provided cmdline plus OVMF/QEMU's `initrd=initrd` suffix.
///
/// AMD SEV-SNP does not share this suffix; see `sev::normalize_kernel_cmdline`.
pub fn measured_kernel_cmdline(base_cmdline: &str) -> String {
    format!("{base_cmdline}{OVMF_INITRD_CMDLINE_SUFFIX}")
}

/// Generate the image-static TDX measurement material from an image directory.
pub fn tdx_os_image_measurement_for_image_dir(image_dir: &Path) -> Result<TdxOsImageMeasurement> {
    let meta_path = image_dir.join("metadata.json");
    let meta_str = fs::read_to_string(&meta_path)
        .with_context(|| format!("cannot read {}", meta_path.display()))?;
    let meta: ImageMetadata =
        serde_json::from_str(&meta_str).context("failed to parse image metadata.json")?;

    let base_cmdline = meta
        .cmdline
        .filter(|s| !s.trim().is_empty())
        .context("metadata.json cmdline is required for TDX measurement")?
        .to_string();

    // Validate that the image identity carried by the measured cmdline is
    // well-formed. The normalized rootfs hash is not stored separately to keep
    // the TDX projection compact; it is already committed by the command line
    // the document carries.
    crate::sev::rootfs_hash_from_cmdline(Some(&base_cmdline))
        .context("failed to parse dstack.rootfs_hash from TDX cmdline")?;

    let ovmf_variant = meta.ovmf_variant.unwrap_or_default();

    let fw_data = fs::read(image_dir.join(&meta.bios))
        .with_context(|| format!("cannot read {}", image_dir.join(&meta.bios).display()))?;
    let tdvf = Tdvf::parse(&fw_data).context("failed to parse TDX TDVF metadata")?;

    let initrd_path = image_dir.join(&meta.initrd);
    let initrd =
        fs::read(&initrd_path).with_context(|| format!("cannot read {}", initrd_path.display()))?;
    let kernel_path = image_dir.join(&meta.kernel);
    let kernel =
        fs::read(&kernel_path).with_context(|| format!("cannot read {}", kernel_path.display()))?;
    // Which bytes OVMF will measure is a property of this image's firmware, so
    // it is read from the image rather than from anything the host says.
    let kernel_authenticode = if meta.kernel_header_normalized {
        kernel_authenticode_sha384(&kernel)?
    } else {
        patched_kernel_authenticode_sha384(
            &kernel,
            initrd.len() as u32,
            TDX_KERNEL_HASH_STABLE_MIN_MEMORY,
            0x28000,
        )
        .context("failed to compute high-memory QEMU-patched kernel hash")?
    };

    Ok(TdxOsImageMeasurement {
        kernel_header_normalized: meta.kernel_header_normalized,
        image: TdxImageMeasurement {
            base_cmdline: base_cmdline.clone(),
            kernel_authenticode,
            initrd_sha384: measure_sha384(&initrd),
        },
        tdvf: TdxTdvfMeasurement {
            ovmf_variant,
            mrtd: TdxMrtdCandidates {
                single_pass: tdvf.mrtd_single_pass()?,
                two_pass: tdvf.mrtd_two_pass()?,
            },
            td_hob_witness: tdvf.td_hob_witness_v1()?,
        },
    })
}

/// Generate the raw `measurement.tdx.cbor` bytes for an image directory.
pub fn tdx_os_image_measurement_cbor_for_image_dir(image_dir: &Path) -> Result<Vec<u8>> {
    Ok(tdx_os_image_measurement_for_image_dir(image_dir)?.to_cbor_vec())
}

/// Compute the TDX static measurement-material hash for an image directory.
pub fn tdx_measurement_hash_for_image_dir(image_dir: &Path) -> Result<[u8; 32]> {
    Ok(tdx_os_image_measurement_for_image_dir(image_dir)?.measurement_hash())
}

/// Compute expected TDX measurements from self-contained TDX measurement
/// material and the three ACPI table digests captured in RTMR[0].
///
/// This path intentionally does not download or read the OS image. Every
/// guest memory size is supported: the kernel digest is a plain hash of the
/// image file, because the setup header is normalized on both sides.
pub fn tdx_measurements_from_measurement_document(
    document: &TdxOsImageMeasurementDocument,
    vm_config: &VmConfig,
    acpi_hashes: &TdxRtmr0AcpiHashes,
) -> Result<crate::TdxMeasurements> {
    let measurement = document
        .decode_measurement()
        .map_err(anyhow::Error::msg)
        .context("failed to decode TDX measurement CBOR")?;
    if !measurement.kernel_header_normalized
        && !tdx_kernel_hash_uses_precomputed_high_mem(vm_config.memory_size)
    {
        bail!(
            "TDX lite attestation without image download requires memory_size == {} bytes ({} MiB) or >= {} bytes ({} MiB); got {} bytes. This restriction only applies to images whose OVMF does not normalize the kernel setup header, because QEMU's rewrite moves the initrd with guest RAM; re-emit the image to remove it",
            TDX_KERNEL_HASH_COMPAT_2G_MEMORY,
            TDX_KERNEL_HASH_COMPAT_2G_MEMORY / 1024 / 1024,
            TDX_KERNEL_HASH_STABLE_MIN_MEMORY,
            TDX_KERNEL_HASH_STABLE_MIN_MEMORY / 1024 / 1024,
            vm_config.memory_size
        );
    }
    let mrtd = select_mrtd(&measurement, vm_config)?;

    let td_hob_hash =
        measure_td_hob_from_witness_data(&measurement.tdvf.td_hob_witness, vm_config.memory_size)
            .context("failed to measure TD HOB from witness")?;
    let rtmr0_log = rtmr0_log_from_td_hob_hash_with_acpi_hashes(
        td_hob_hash,
        measurement.tdvf.ovmf_variant,
        &AcpiTableHashes {
            loader: acpi_hashes.loader.clone(),
            rsdp: acpi_hashes.rsdp.clone(),
            tables: acpi_hashes.tables.clone(),
        },
    )
    .context("failed to compute RTMR0 from measurement document")?;
    let rtmr0 = measure_log(&rtmr0_log);

    let kernel_hash = validate_bytes_field(
        &measurement.image.kernel_authenticode,
        "tdx.measurement.image.kernel_authenticode",
        48,
    )?;
    let rtmr1 = measure_log(&rtmr1_log_from_kernel_hash(kernel_hash));

    let initrd_hash = validate_bytes_field(
        &measurement.image.initrd_sha384,
        "tdx.measurement.image.initrd_sha384",
        48,
    )?;
    // Now that the document carries the command line rather than its digest,
    // the no-download path can enforce the same rootfs-identity invariant the
    // build path does, instead of trusting an opaque 48-byte value.
    crate::sev::rootfs_hash_from_cmdline(Some(&measurement.image.base_cmdline))
        .context("failed to parse dstack.rootfs_hash from tdx.measurement.image.base_cmdline")?;
    let kernel_cmdline_hash =
        crate::kernel::measure_cmdline(&measured_kernel_cmdline(&measurement.image.base_cmdline));
    let rtmr2 = measure_log(&[kernel_cmdline_hash, initrd_hash]);

    Ok(crate::TdxMeasurements {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
    })
}

fn rtmr0_acpi_hashes_from_event_log(event_log: &[TdxEvent]) -> Result<TdxRtmr0AcpiHashes> {
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

fn assert_tdx_mrs_eq(
    expected: &crate::TdxMeasurements,
    actual: &crate::TdxMeasurements,
) -> Result<()> {
    for (name, expected, actual) in [
        ("MRTD", &expected.mrtd, &actual.mrtd),
        ("RTMR0", &expected.rtmr0, &actual.rtmr0),
        ("RTMR1", &expected.rtmr1, &actual.rtmr1),
        ("RTMR2", &expected.rtmr2, &actual.rtmr2),
    ] {
        if expected != actual {
            bail!(
                "{name} mismatch: expected={}, actual={}",
                hex::encode(expected),
                hex::encode(actual)
            );
        }
    }
    Ok(())
}

/// Verify a dstack TDX lite CVM's OS against already-verified MRTD/RTMR0-2.
///
/// Regenerates the three RTMR0 ACPI digests from `vm_config` with qemu-acpi,
/// checks them against the named events in `event_log`, recomputes MRTD and
/// RTMR0-2 from `vm_config.tdx_measurement`, and compares them with
/// `verified_mrs`. Does not judge os_image_hash approval, DCAP quote validity,
/// or RTMR3: those stay the caller's job.
///
/// This is the single source of truth used by `dstack-verifier` and the wasm
/// package. It takes only primitive, already-verified values so it can build
/// for wasm32 without tokio/reqwest/tempfile.
pub fn verify_tdx_lite_os(
    verified_mrs: &crate::TdxMeasurements,
    event_log: &[TdxEvent],
    vm_config: &VmConfig,
) -> Result<TdxLiteOsCheck> {
    if vm_config.tdx_attestation_variant != TdxAttestationVariant::Lite {
        bail!("vm_config is not a TDX lite attestation");
    }
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

    // The guest labels the three RTMR0 ACPI DATA events as acpi-loader,
    // acpi-rsdp, and acpi-tables before exposing the event log, so this does
    // not guess based on event order.
    let reported_acpi_hashes = rtmr0_acpi_hashes_from_event_log(event_log)
        .context("TDX lite attestation is missing named RTMR0 ACPI DATA digests")?;
    // Recompute the digests from the declared VM shape instead of trusting
    // the reported ones, and treat both failure modes as fatal: a mismatch
    // means the tables are not the ones this shape produces, and a shape
    // the generator cannot model (`swtpm`, a QEMU older than any profile)
    // leaves nothing to compare against. Downgrading either case to "pass,
    // but unverified" would make the check optional at the host's
    // discretion, because `swtpm` and `qemu_version` are host-declared
    // fields that no other measurement independently constrains.
    let acpi_hashes = expected_rtmr0_acpi_hashes(vm_config, measurement.tdvf.ovmf_variant)
        .context("failed to recompute expected TDX lite ACPI table digests")?;
    assert_tdx_acpi_hashes_match(&acpi_hashes, &reported_acpi_hashes)?;
    // RTMR0 below is rebuilt from the recomputed digests, so the expected
    // value depends on nothing the host reported about the tables.
    let expected_mrs =
        tdx_measurements_from_measurement_document(document, vm_config, &acpi_hashes)
            .context("Failed to compute TDX expected measurements without image download")?;
    assert_tdx_mrs_eq(&expected_mrs, verified_mrs).context("MRs do not match")?;
    Ok(TdxLiteOsCheck {
        os_image_hash: vm_config.os_image_hash.clone(),
        acpi_tables_verified: true,
    })
}

/// Compute image-critical TDX measurements without RTMR[0].
///
/// RTMR[0] contains QEMU-generated ACPI blobs and other launch-environment
/// material. This helper verifies the OS-image binding pieces that do not need
/// QEMU: MRTD (TDVF firmware), RTMR[1] (QEMU-patched kernel image), and RTMR[2]
/// (kernel command line + initrd).
pub fn tdx_measurements_for_image_dir_without_rtmr0(
    image_dir: &Path,
    vm_config: &VmConfig,
) -> Result<TdxMeasurementsWithoutRtmr0> {
    let meta_path = image_dir.join("metadata.json");
    let meta_str = fs::read_to_string(&meta_path)
        .with_context(|| format!("cannot read {}", meta_path.display()))?;
    let meta: ImageMetadata =
        serde_json::from_str(&meta_str).context("failed to parse image metadata.json")?;

    let base_cmdline = meta
        .cmdline
        .filter(|s| !s.trim().is_empty())
        .context("metadata.json cmdline is required for TDX measurement")?
        .to_string();
    let kernel_cmdline = measured_kernel_cmdline(&base_cmdline);

    let firmware_path = image_dir.join(&meta.bios);
    let kernel_path = image_dir.join(&meta.kernel);
    let initrd_path = image_dir.join(&meta.initrd);

    let fw_data = fs::read(&firmware_path)
        .with_context(|| format!("cannot read {}", firmware_path.display()))?;
    let kernel_data =
        fs::read(&kernel_path).with_context(|| format!("cannot read {}", kernel_path.display()))?;
    let initrd_data =
        fs::read(&initrd_path).with_context(|| format!("cannot read {}", initrd_path.display()))?;

    let ovmf_variant = vm_config
        .ovmf_variant
        .or(meta.ovmf_variant)
        .unwrap_or_default();

    let firmware = firmware_path.display().to_string();
    let kernel = kernel_path.display().to_string();
    let initrd = initrd_path.display().to_string();
    let machine = crate::Machine::builder()
        .cpu_count(vm_config.cpu_count)
        .memory_size(vm_config.memory_size)
        .firmware(&firmware)
        .kernel(&kernel)
        .initrd(&initrd)
        .kernel_cmdline(&kernel_cmdline)
        .root_verity(true)
        .hotplug_off(vm_config.hotplug_off)
        .maybe_two_pass_add_pages(vm_config.qemu_single_pass_add_pages)
        .normalized_setup_header(meta.kernel_header_normalized)
        .maybe_pic(vm_config.pic)
        .maybe_qemu_version(vm_config.qemu_version.clone())
        .maybe_pci_hole64_size(if vm_config.pci_hole64_size > 0 {
            Some(vm_config.pci_hole64_size)
        } else {
            None
        })
        .hugepages(vm_config.hugepages)
        .numa_nodes(&vm_config.numa_nodes)
        .num_gpus(vm_config.num_gpus)
        .num_nics(vm_config.num_nics)
        .num_verity_volumes(vm_config.num_verity_volumes)
        .extra_root_devices(&vm_config.extra_root_devices)
        .swtpm(vm_config.swtpm)
        .num_nvswitches(vm_config.num_nvswitches)
        .host_share_mode(vm_config.host_share_mode.clone())
        .ovmf_variant(ovmf_variant)
        .build();

    let tdvf = Tdvf::parse(&fw_data).context("failed to parse TDX TDVF metadata")?;
    let mrtd = tdvf.mrtd(&machine).context("failed to compute MRTD")?;

    let rtmr1_log = crate::kernel::rtmr1_log(
        &kernel_data,
        initrd_data.len() as u32,
        vm_config.memory_size,
        0x28000,
        meta.kernel_header_normalized,
    )
    .context("failed to compute RTMR1")?;
    let rtmr1 = measure_log(&rtmr1_log);

    let rtmr2_log = vec![
        crate::kernel::measure_cmdline(&kernel_cmdline),
        measure_sha384(&initrd_data),
    ];
    let rtmr2 = measure_log(&rtmr2_log);

    Ok(TdxMeasurementsWithoutRtmr0 { mrtd, rtmr1, rtmr2 })
}

/// Compute TDX measurements without invoking QEMU-derived helper binaries.
///
/// RTMR[0] includes ACPI blobs generated by QEMU at launch time. The caller
/// supplies the already-measured ACPI event digests from the hardware-bound
/// event log; this function recomputes the rest of the TDX image measurement
/// from image files and VM configuration.
pub fn tdx_measurements_for_image_dir_with_acpi_hashes(
    image_dir: &Path,
    vm_config: &VmConfig,
    acpi_hashes: &TdxRtmr0AcpiHashes,
) -> Result<crate::TdxMeasurements> {
    let meta_path = image_dir.join("metadata.json");
    let meta_str = fs::read_to_string(&meta_path)
        .with_context(|| format!("cannot read {}", meta_path.display()))?;
    let meta: ImageMetadata =
        serde_json::from_str(&meta_str).context("failed to parse image metadata.json")?;

    let base_cmdline = meta
        .cmdline
        .filter(|s| !s.trim().is_empty())
        .context("metadata.json cmdline is required for TDX measurement")?
        .to_string();
    let kernel_cmdline = measured_kernel_cmdline(&base_cmdline);

    let firmware_path = image_dir.join(&meta.bios);
    let kernel_path = image_dir.join(&meta.kernel);
    let initrd_path = image_dir.join(&meta.initrd);

    let fw_data = fs::read(&firmware_path)
        .with_context(|| format!("cannot read {}", firmware_path.display()))?;
    let kernel_data =
        fs::read(&kernel_path).with_context(|| format!("cannot read {}", kernel_path.display()))?;
    let initrd_data =
        fs::read(&initrd_path).with_context(|| format!("cannot read {}", initrd_path.display()))?;

    let ovmf_variant = vm_config
        .ovmf_variant
        .or(meta.ovmf_variant)
        .unwrap_or_default();

    let firmware = firmware_path.display().to_string();
    let kernel = kernel_path.display().to_string();
    let initrd = initrd_path.display().to_string();
    let machine = crate::Machine::builder()
        .cpu_count(vm_config.cpu_count)
        .memory_size(vm_config.memory_size)
        .firmware(&firmware)
        .kernel(&kernel)
        .initrd(&initrd)
        .kernel_cmdline(&kernel_cmdline)
        .root_verity(true)
        .hotplug_off(vm_config.hotplug_off)
        .maybe_two_pass_add_pages(vm_config.qemu_single_pass_add_pages)
        .normalized_setup_header(meta.kernel_header_normalized)
        .maybe_pic(vm_config.pic)
        .maybe_qemu_version(vm_config.qemu_version.clone())
        .maybe_pci_hole64_size(if vm_config.pci_hole64_size > 0 {
            Some(vm_config.pci_hole64_size)
        } else {
            None
        })
        .hugepages(vm_config.hugepages)
        .numa_nodes(&vm_config.numa_nodes)
        .num_gpus(vm_config.num_gpus)
        .num_nics(vm_config.num_nics)
        .num_verity_volumes(vm_config.num_verity_volumes)
        .extra_root_devices(&vm_config.extra_root_devices)
        .swtpm(vm_config.swtpm)
        .num_nvswitches(vm_config.num_nvswitches)
        .host_share_mode(vm_config.host_share_mode.clone())
        .ovmf_variant(ovmf_variant)
        .build();

    let tdvf = Tdvf::parse(&fw_data).context("failed to parse TDX TDVF metadata")?;
    let mrtd = tdvf.mrtd(&machine).context("failed to compute MRTD")?;

    let rtmr0_log = tdvf
        .rtmr0_log_with_acpi_hashes(
            vm_config.memory_size,
            ovmf_variant,
            &AcpiTableHashes {
                loader: acpi_hashes.loader.clone(),
                rsdp: acpi_hashes.rsdp.clone(),
                tables: acpi_hashes.tables.clone(),
            },
        )
        .context("failed to compute RTMR0 without ACPI table generation")?;
    let rtmr0 = measure_log(&rtmr0_log);

    let rtmr1_log = crate::kernel::rtmr1_log(
        &kernel_data,
        initrd_data.len() as u32,
        vm_config.memory_size,
        0x28000,
        meta.kernel_header_normalized,
    )
    .context("failed to compute RTMR1")?;
    let rtmr1 = measure_log(&rtmr1_log);

    let rtmr2_log = vec![
        crate::kernel::measure_cmdline(&kernel_cmdline),
        measure_sha384(&initrd_data),
    ];
    let rtmr2 = measure_log(&rtmr2_log);

    Ok(crate::TdxMeasurements {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::measure_cmdline;

    /// Shaped like a real `os/image/kernel-cmdline.sh` command line: it always
    /// carries `dstack.rootfs_hash`, which is what pins the rootfs.
    const SAMPLE_BASE_CMDLINE: &str = "console=ttyS0 init=/init panic=1 \
         dstack.rootfs_hash=1111111111111111111111111111111111111111111111111111111111111111 \
         dstack.rootfs_size=4096";

    fn sample_measurement() -> TdxOsImageMeasurement {
        TdxOsImageMeasurement {
            image: TdxImageMeasurement {
                base_cmdline: SAMPLE_BASE_CMDLINE.to_string(),
                kernel_authenticode: vec![0x22; 48],
                initrd_sha384: vec![0x33; 48],
            },
            tdvf: TdxTdvfMeasurement {
                ovmf_variant: OvmfVariant::Pre202505,
                mrtd: TdxMrtdCandidates {
                    single_pass: vec![0x44; 48],
                    two_pass: vec![0x55; 48],
                },
                td_hob_witness: vec![0x66; 16],
            },
            kernel_header_normalized: true,
        }
    }

    #[test]
    fn measured_kernel_cmdline_appends_the_ovmf_suffix() {
        assert_eq!(
            measured_kernel_cmdline(SAMPLE_BASE_CMDLINE),
            format!("{SAMPLE_BASE_CMDLINE}{OVMF_INITRD_CMDLINE_SUFFIX}"),
        );
        assert_eq!(OVMF_INITRD_CMDLINE_SUFFIX, " initrd=initrd");
    }

    /// Golden vector. The command-line event is the first RTMR[2] entry, so a
    /// change here silently invalidates every deployed `os_image_hash`. If this
    /// fails, the measurement protocol changed: that must be a deliberate,
    /// reviewed decision, not a side effect.
    #[test]
    fn rtmr2_command_line_event_digest_is_stable() {
        let digest = measure_cmdline(&measured_kernel_cmdline(SAMPLE_BASE_CMDLINE));
        assert_eq!(hex::encode(digest), "bb4154e6e429e184bc63d544ae5720f868e5859b378b13bab69860e1fc65c09f1b67277bba010841fbe8bc3619e58d58");
    }

    /// Golden vector for the full RTMR[2] replay (command line, then initrd).
    #[test]
    fn rtmr2_replay_is_stable() {
        let cmdline_digest = measure_cmdline(&measured_kernel_cmdline(SAMPLE_BASE_CMDLINE));
        let initrd_digest = vec![0x33; 48];
        assert_eq!(
            hex::encode(measure_log(&[cmdline_digest, initrd_digest])),
            "2fb6d31492cd2f073fe8fdaa9dbdff4dfdde92bf07f9a16c2b7123ae7be5090007974d33bfe8807ac56974160f8f2948",
        );
    }

    /// Golden vector for the CBOR that `sha256sum.txt` commits to, and hence
    /// for `os_image_hash` itself. Changing the encoding requires rebuilding and
    /// re-registering every image, so it must never change accidentally.
    #[test]
    fn tdx_measurement_document_cbor_is_stable() {
        assert_eq!(
            hex::encode(sample_measurement().to_cbor_vec()),
            "a36776657273696f6e0465696d616765a467636d646c696e65788c636f6e736f6c653d747479533020696e69743d2f696e69742070616e69633d312064737461636b2e726f6f7466735f686173683d313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131312064737461636b2e726f6f7466735f73697a653d34303936736b65726e656c5f61757468656e7469636f6465583022222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222278186b65726e656c5f6865616465725f6e6f726d616c697a6564f56d696e697472645f73686133383458303333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333336474647666a3646f766d6669707265323032353035646d727464a26b73696e676c655f7061737358304444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444446874776f5f7061737358305555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555556674645f686f625066666666666666666666666666666666",
        );
    }

    fn put_varuint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    #[test]
    fn read_varuint_rejects_values_larger_than_u64() {
        let mut max = Vec::new();
        put_varuint(u64::MAX, &mut max);
        assert_eq!(read_varuint(&mut max.as_slice()).unwrap(), u64::MAX);

        let mut bytes = [0xff; 10];
        bytes[9] = 0x02;
        let mut encoded = bytes.as_slice();

        let err = read_varuint(&mut encoded).expect_err("an overflowing varuint must be rejected");
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );
    }

    fn witness_within_deadline(witness: Vec<u8>, memory_size: u64) -> Result<(), String> {
        use std::sync::mpsc::{channel, RecvTimeoutError};

        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                measure_td_hob_from_witness_data(&witness, memory_size)
                    .map(|_| ())
                    .map_err(|err| format!("{err:#}")),
            );
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                panic!("witness measurement did not finish within 5s")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("witness measurement panicked"),
        }
    }

    /// The witness is decoded from `vm_config.tdx_measurement`, which the
    /// requester supplies, and every range costs about two bytes. A body an
    /// attacker can post in one request must not turn into quadratic work.
    #[test]
    fn measure_td_hob_from_witness_data_rejects_more_ranges_than_a_firmware_has_sections() {
        const RANGES: u64 = 50_000;

        let mut witness = Vec::new();
        put_varuint(0x800, &mut witness); // base_page
        put_varuint(0, &mut witness); // td_hob_page_delta
        put_varuint(RANGES, &mut witness); // range_count
        for i in 0..RANGES {
            put_varuint(i * 2, &mut witness); // start_page_delta
            put_varuint(1, &mut witness); // page_count
        }

        let err = witness_within_deadline(witness, 2 * 1024 * 1024 * 1024)
            .expect_err("an oversized range count must be rejected");
        assert!(err.contains("ranges"), "unexpected error: {err}");
    }

    /// Every address in the witness is a varint the requester chose, so the
    /// page-to-address arithmetic has to survive values no generator emits.
    #[test]
    fn measure_td_hob_from_witness_data_rejects_ranges_whose_addresses_wrap() {
        let with_range = |base_page: u64, start_page_delta: u64, page_count: u64| {
            let mut witness = Vec::new();
            put_varuint(base_page, &mut witness);
            put_varuint(0, &mut witness); // td_hob_page_delta
            put_varuint(1, &mut witness); // range_count
            put_varuint(start_page_delta, &mut witness);
            put_varuint(page_count, &mut witness);
            witness
        };

        // `base_page + start_page_delta` wraps.
        let err = witness_within_deadline(with_range(0x1000, u64::MAX, 1), 2 * 1024 * 1024 * 1024)
            .expect_err("a wrapping range start must be rejected");
        assert!(err.contains("overflow"), "unexpected error: {err}");

        // The start is representable, but `start + len` wraps.
        let err = witness_within_deadline(
            with_range(0x000f_ffff_ffff_ffff, 0, 2),
            2 * 1024 * 1024 * 1024,
        )
        .expect_err("a wrapping range end must be rejected");
        assert!(err.contains("overflow"), "unexpected error: {err}");
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

        let hashes = rtmr0_acpi_hashes_from_event_log(&event_log).expect("named ACPI hashes");

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

        assert!(rtmr0_acpi_hashes_from_event_log(&event_log).is_err());
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
        let err = assert_tdx_acpi_hashes_match(&expected, &reported)
            .expect_err("mismatched tables digest is rejected");
        assert!(err.to_string().contains(TDX_ACPI_TABLES_EVENT), "{err:#}");
        assert!(assert_tdx_acpi_hashes_match(&expected, &expected).is_ok());
    }

    #[derive(serde::Deserialize)]
    struct GetQuoteFixture {
        quote: String,
        event_log: String,
        vm_config: String,
    }

    fn tdx_lite_getquote_fixture() -> GetQuoteFixture {
        serde_json::from_str(include_str!(
            "../../verifier/fixtures/tdx-lite-getquote.json"
        ))
        .expect("TDX lite getquote fixture parses")
    }

    fn mrs_from_quote_hex(quote_hex: &str) -> crate::TdxMeasurements {
        let quote = hex::decode(quote_hex).expect("quote is hex");
        let version = u16::from_le_bytes(quote[..2].try_into().expect("quote header"));
        let header = if version == 5 { 54 } else { 48 };
        let field = |offset: usize| quote[header + offset..header + offset + 48].to_vec();
        crate::TdxMeasurements {
            mrtd: field(136),
            rtmr0: field(328),
            rtmr1: field(376),
            rtmr2: field(424),
        }
    }

    fn parse_fixture(
        fixture: &GetQuoteFixture,
    ) -> (crate::TdxMeasurements, Vec<TdxEvent>, VmConfig) {
        let events: Vec<TdxEvent> =
            serde_json::from_str(&fixture.event_log).expect("fixture event log parses");
        let vm_config: VmConfig =
            serde_json::from_str(&fixture.vm_config).expect("fixture vm_config parses");
        (mrs_from_quote_hex(&fixture.quote), events, vm_config)
    }

    #[test]
    fn tdx_lite_getquote_fixture_is_accepted() {
        let fixture = tdx_lite_getquote_fixture();
        let (mrs, events, vm_config) = parse_fixture(&fixture);
        let check =
            verify_tdx_lite_os(&mrs, &events, &vm_config).expect("captured TDX lite CVM verifies");
        assert!(check.acpi_tables_verified);
        assert_eq!(check.os_image_hash, vm_config.os_image_hash);
    }

    #[test]
    fn tdx_lite_rejects_tampered_vm_shape() {
        let fixture = tdx_lite_getquote_fixture();
        let (mrs, events, vm_config) = parse_fixture(&fixture);
        let mut cases = Vec::new();

        let mut tampered = vm_config.clone();
        tampered.memory_size = 4 * 1024 * 1024 * 1024;
        cases.push(("memory_size", tampered));

        let mut tampered = vm_config.clone();
        tampered.pci_hole64_size = if vm_config.pci_hole64_size == 0 {
            1 << 50
        } else {
            0
        };
        cases.push(("pci_hole64_size", tampered));

        let mut tampered = vm_config.clone();
        tampered.hotplug_off = !vm_config.hotplug_off;
        cases.push(("hotplug_off", tampered));

        let mut tampered = vm_config.clone();
        tampered.num_nics = 2;
        cases.push(("num_nics", tampered));

        let mut tampered = vm_config.clone();
        tampered.cpu_count += 1;
        cases.push(("cpu_count", tampered));

        let mut tampered = vm_config.clone();
        tampered.qemu_version = Some("9.2.1".into());
        cases.push(("qemu_version", tampered));

        for (name, tampered) in cases {
            verify_tdx_lite_os(&mrs, &events, &tampered)
                .expect_err(&format!("{name} tamper must be rejected"));
        }
    }

    #[test]
    fn tdx_lite_rejects_tampered_acpi_event_and_rtmr2() {
        let fixture = tdx_lite_getquote_fixture();
        let (mrs, mut events, vm_config) = parse_fixture(&fixture);
        let index = events
            .iter()
            .position(|event| event.event == TDX_ACPI_TABLES_EVENT)
            .expect("acpi-tables event");
        events[index].digest[0] ^= 0x01;
        let err = verify_tdx_lite_os(&mrs, &events, &vm_config)
            .expect_err("edited acpi-tables digest must be rejected");
        assert!(
            format!("{err:#}").contains(TDX_ACPI_TABLES_EVENT),
            "unexpected error: {err:#}"
        );

        let (mrs, events, vm_config) = parse_fixture(&fixture);
        let mut mrs = mrs;
        mrs.rtmr2 = vec![0; 48];
        let err = verify_tdx_lite_os(&mrs, &events, &vm_config)
            .expect_err("zeroed RTMR2 must be rejected");
        assert!(
            format!("{err:#}").contains("RTMR2"),
            "unexpected error: {err:#}"
        );
    }

    /// The captured VM ran 2 vCPUs; a VM shape that disagrees with the quote
    /// must not reproduce its ACPI digests, which is what makes the recomputed
    /// digests worth comparing in the first place.
    #[test]
    fn tdx_lite_acpi_hashes_depend_on_the_reported_vm_shape() {
        let fixture = tdx_lite_getquote_fixture();
        let (_, events, mut vm_config) = parse_fixture(&fixture);
        let ovmf_variant = vm_config.ovmf_variant.unwrap_or_default();

        let reported =
            rtmr0_acpi_hashes_from_event_log(&events).expect("fixture carries named ACPI digests");
        let expected = expected_rtmr0_acpi_hashes(&vm_config, ovmf_variant)
            .expect("ACPI tables are generated for the fixture VM shape");
        assert_tdx_acpi_hashes_match(&expected, &reported)
            .expect("recomputed digests match the captured CVM");

        vm_config.cpu_count += 1;
        let expected = expected_rtmr0_acpi_hashes(&vm_config, ovmf_variant)
            .expect("ACPI tables are generated for the altered VM shape");
        assert_tdx_acpi_hashes_match(&expected, &reported)
            .expect_err("an extra vCPU must change the ACPI tables");
    }
}
