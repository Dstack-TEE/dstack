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
    patched_kernel_authenticode_sha384, tdx_kernel_hash_uses_precomputed_high_mem,
    TDX_KERNEL_HASH_COMPAT_2G_MEMORY, TDX_KERNEL_HASH_STABLE_MIN_MEMORY,
};
use crate::tdvf::{rtmr0_log_from_td_hob_hash_with_acpi_hashes, AcpiTableHashes, Tdvf};
use crate::util::{measure_log, measure_sha384};
use anyhow::{bail, Context, Result};
use dstack_types::{
    OvmfVariant, TdxImageMeasurement, TdxMrtdCandidates, TdxOsImageMeasurement,
    TdxOsImageMeasurementDocument, TdxTdvfMeasurement, VmConfig,
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
    version: String,
    #[serde(default)]
    ovmf_variant: Option<OvmfVariant>,
}

#[derive(Debug, Clone)]
pub struct TdxRtmr0AcpiHashes {
    pub loader: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub tables: Vec<u8>,
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

fn select_mrtd(measurement: &TdxOsImageMeasurement, vm_config: &VmConfig) -> Result<Vec<u8>> {
    let machine = crate::Machine::builder()
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
        .num_gpus(vm_config.num_gpus)
        .num_nvswitches(vm_config.num_nvswitches)
        .host_share_mode(vm_config.host_share_mode.clone())
        .ovmf_variant(measurement.tdvf.ovmf_variant)
        .build();
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

fn measure_td_hob_from_witness_data(data: &[u8], memory_size: u64) -> Result<Vec<u8>> {
    let mut input = data;
    let base_page = read_varuint(&mut input)?;
    let td_hob_page_delta = read_varuint(&mut input)?;
    let range_count = read_varuint(&mut input)?;
    let td_hob_base_addr = (base_page + td_hob_page_delta)
        .checked_mul(0x1000)
        .context("TD HOB base address overflow")?;

    let mut memory_acceptor = MemoryAcceptor::new(0, memory_size);
    for _ in 0..range_count {
        let start_page_delta = read_varuint(&mut input)?;
        let page_count = read_varuint(&mut input)?;
        let start = (base_page + start_page_delta)
            .checked_mul(0x1000)
            .context("TD HOB range start overflow")?;
        let len = page_count
            .checked_mul(0x1000)
            .context("TD HOB range length overflow")?;
        memory_acceptor.accept(start, start + len);
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
    if memory_size >= TDX_KERNEL_HASH_STABLE_MIN_MEMORY {
        if last_start < 0x80000000u64 {
            add_memory_resource_hob(0x07, last_start, 0x80000000u64 - last_start);
        }
        if last_end > 0x80000000u64 {
            add_memory_resource_hob(0x07, 0x100000000, last_end - 0x80000000u64);
        }
    } else {
        add_memory_resource_hob(0x07, last_start, last_end - last_start);
    }

    let end_of_hob_list = td_hob_base_addr + td_hob.len() as u64 + 8;
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

/// Return the measured TDX kernel command line for a metadata cmdline.
///
/// This mirrors the existing dstack TDX measurement replay path, which measures
/// the image-provided cmdline plus OVMF/QEMU's `initrd=initrd` suffix.
pub fn measured_kernel_cmdline(base_cmdline: &str) -> String {
    format!("{base_cmdline} initrd=initrd")
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
        .context("metadata.json cmdline is required for TDX os_image_hash")?
        .to_string();

    // Validate that the image identity carried by the measured cmdline is
    // well-formed. The normalized rootfs hash is not stored separately to keep
    // the TDX projection compact; it is already committed by the measured
    // kernel command line digest.
    crate::sev::rootfs_hash_from_cmdline(Some(&base_cmdline))
        .context("failed to parse dstack.rootfs_hash from TDX cmdline")?;

    let ovmf_variant = meta
        .ovmf_variant
        .or_else(|| {
            if meta.version.is_empty() {
                None
            } else {
                crate::ovmf_variant_for_version(&meta.version).ok()
            }
        })
        .unwrap_or_default();

    let fw_data = fs::read(image_dir.join(&meta.bios))
        .with_context(|| format!("cannot read {}", image_dir.join(&meta.bios).display()))?;
    let tdvf = Tdvf::parse(&fw_data).context("failed to parse TDX TDVF metadata")?;

    let initrd_path = image_dir.join(&meta.initrd);
    let initrd =
        fs::read(&initrd_path).with_context(|| format!("cannot read {}", initrd_path.display()))?;
    let kernel_path = image_dir.join(&meta.kernel);
    let kernel =
        fs::read(&kernel_path).with_context(|| format!("cannot read {}", kernel_path.display()))?;
    let kernel_authenticode = patched_kernel_authenticode_sha384(
        &kernel,
        initrd.len() as u32,
        TDX_KERNEL_HASH_STABLE_MIN_MEMORY,
        0x28000,
    )
    .context("failed to compute high-memory QEMU-patched kernel hash")?;

    Ok(TdxOsImageMeasurement {
        image: TdxImageMeasurement {
            kernel_cmdline_sha384: crate::kernel::measure_cmdline(&measured_kernel_cmdline(
                &base_cmdline,
            )),
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

/// Generate the self-contained TDX measurement document for an image directory.
///
/// The document contains both the hash projection and the resulting
/// `os_image_hash`, avoiding a separate `digest.tdx.txt` artifact.
pub fn tdx_os_image_measurement_document_for_image_dir(
    image_dir: &Path,
) -> Result<TdxOsImageMeasurementDocument> {
    Ok(TdxOsImageMeasurementDocument::new(
        tdx_os_image_measurement_for_image_dir(image_dir)?,
    ))
}

/// Compute the TDX static-material OS image hash for an image directory.
pub fn tdx_os_image_hash_for_image_dir(image_dir: &Path) -> Result<[u8; 32]> {
    Ok(tdx_os_image_measurement_for_image_dir(image_dir)?.os_image_hash())
}

/// Compute expected TDX measurements from the self-contained `measurement.json`
/// TDX document and the three ACPI table digests captured in RTMR[0].
///
/// This path intentionally does not download or read the OS image. Because
/// QEMU's patched kernel Authenticode hash depends on exact guest RAM below
/// `TDX_KERNEL_HASH_STABLE_MIN_MEMORY`, the no-image-download path supports
/// CVMs at or above that threshold plus the exact 2 GiB placement, which QEMU
/// patches to the same kernel bytes as the high-memory case.
pub fn tdx_measurements_from_measurement_document(
    document: &TdxOsImageMeasurementDocument,
    vm_config: &VmConfig,
    acpi_hashes: &TdxRtmr0AcpiHashes,
) -> Result<crate::TdxMeasurements> {
    if document.version != TdxOsImageMeasurementDocument::VERSION {
        bail!(
            "unsupported TDX measurement document version {}",
            document.version
        );
    }
    if !tdx_kernel_hash_uses_precomputed_high_mem(vm_config.memory_size) {
        bail!(
            "TDX measurement attestation without image download requires memory_size == {} bytes ({} MiB) or >= {} bytes ({} MiB); got {} bytes",
            TDX_KERNEL_HASH_COMPAT_2G_MEMORY,
            TDX_KERNEL_HASH_COMPAT_2G_MEMORY / 1024 / 1024,
            TDX_KERNEL_HASH_STABLE_MIN_MEMORY,
            TDX_KERNEL_HASH_STABLE_MIN_MEMORY / 1024 / 1024,
            vm_config.memory_size
        );
    }

    let measurement = document
        .decode_measurement()
        .map_err(anyhow::Error::msg)
        .context("failed to decode TDX measurement CBOR")?;
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
    let kernel_cmdline_hash = validate_bytes_field(
        &measurement.image.kernel_cmdline_sha384,
        "tdx.measurement.image.kernel_cmdline_sha384",
        48,
    )?;
    let rtmr2 = measure_log(&[kernel_cmdline_hash, initrd_hash]);

    Ok(crate::TdxMeasurements {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
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
        .or_else(|| {
            if meta.version.is_empty() {
                None
            } else {
                crate::ovmf_variant_for_version(&meta.version).ok()
            }
        })
        .unwrap_or_else(|| crate::ovmf_variant_for_image(vm_config.image.as_deref()));

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
        .build();

    let tdvf = Tdvf::parse(&fw_data).context("failed to parse TDX TDVF metadata")?;
    let mrtd = tdvf.mrtd(&machine).context("failed to compute MRTD")?;

    let rtmr1_log = crate::kernel::rtmr1_log(
        &kernel_data,
        initrd_data.len() as u32,
        vm_config.memory_size,
        0x28000,
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
        .or_else(|| {
            if meta.version.is_empty() {
                None
            } else {
                crate::ovmf_variant_for_version(&meta.version).ok()
            }
        })
        .unwrap_or_else(|| crate::ovmf_variant_for_image(vm_config.image.as_deref()));

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
