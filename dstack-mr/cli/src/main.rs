// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use dstack_mr::{Machine, OvmfVariant, ovmf_variant_for_image, ovmf_variant_for_version};
use dstack_types::{ImageInfo, VmConfig};
use fs_err as fs;
use size_parser::parse_memory_size;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Measure a machine configuration
    Measure(MachineConfig),
    /// Compute expected MRs from a `VmConfig` JSON and explain the RTMR0 event log entry by
    /// entry. Optionally compare against actual MRTD/RTMR hex values from a quote.
    Diagnose(DiagnoseConfig),
}

type Bool = bool;

#[derive(Parser)]
struct MachineConfig {
    /// Number of CPUs
    #[arg(short, long, default_value = "1")]
    cpu: u32,

    /// Memory size in bytes
    #[arg(short, long, default_value = "2G", value_parser = parse_memory_size)]
    memory: u64,

    /// Path to dstack image metadata.json
    metadata: PathBuf,

    /// Enable two-pass add pages
    #[arg(long)]
    two_pass_add_pages: Option<Bool>,

    /// Enable PIC
    #[arg(long)]
    pic: Option<Bool>,

    /// Enable SMM
    #[arg(long, default_value = "false")]
    smm: Bool,

    /// PCI hole64 size (accepts decimal or hex with 0x prefix)
    #[arg(long, value_parser = parse_memory_size)]
    pci_hole64_size: Option<u64>,

    /// Enable hugepages
    #[arg(long, default_value = "false")]
    hugepages: bool,

    /// Number of GPUs
    #[arg(long, default_value = "0")]
    num_gpus: u32,

    /// Number of NVSwitches
    #[arg(long, default_value = "0")]
    num_nvswitches: u32,

    /// Disable hotplug
    #[arg(long, default_value = "false")]
    hotplug_off: Bool,

    /// Enable root verity
    #[arg(long, default_value = "true")]
    root_verity: Bool,

    /// QEMU version
    #[arg(long)]
    qemu_version: Option<String>,

    /// dstack OS version (MAJOR.MINOR.PATCH), used to pick the OVMF measurement layout.
    /// 0.5.10 <= ver < 0.6.0 and ver >= 0.6.1 use the edk2-stable202505 layout; everything
    /// else uses the legacy layout. If omitted, falls back to `image_info.version`.
    #[arg(long)]
    dstack_os_version: Option<String>,

    /// Output JSON
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Measure(config) => {
            let metadata =
                fs::read_to_string(&config.metadata).context("Failed to read image metadata")?;
            let image_info: ImageInfo =
                serde_json::from_str(&metadata).context("Failed to parse image metadata")?;
            let parent_dir = config.metadata.parent().unwrap_or(".".as_ref());
            let firmware_path = parent_dir.join(&image_info.bios).display().to_string();
            let kernel_path = parent_dir.join(&image_info.kernel).display().to_string();
            let initrd_path = parent_dir.join(&image_info.initrd).display().to_string();
            let cmdline = image_info.cmdline + " initrd=initrd";

            // CLI flag wins, then the explicit `ovmf_variant` in metadata.json,
            // and finally the OS version field. Older metadata.json files may
            // carry neither, in which case fall back to the default.
            let ovmf_variant = if let Some(v) = config.dstack_os_version.as_deref() {
                ovmf_variant_for_version(v)
                    .with_context(|| format!("invalid dstack OS version: {v}"))?
            } else if let Some(variant) = image_info.ovmf_variant {
                variant
            } else if !image_info.version.is_empty() {
                ovmf_variant_for_version(&image_info.version)
                    .with_context(|| format!("invalid dstack OS version: {}", image_info.version))?
            } else {
                OvmfVariant::default()
            };

            let machine = Machine::builder()
                .cpu_count(config.cpu)
                .memory_size(config.memory)
                .firmware(&firmware_path)
                .kernel(&kernel_path)
                .initrd(&initrd_path)
                .kernel_cmdline(&cmdline)
                .maybe_two_pass_add_pages(config.two_pass_add_pages)
                .maybe_pic(config.pic)
                .smm(config.smm)
                .maybe_pci_hole64_size(config.pci_hole64_size)
                .hugepages(config.hugepages)
                .num_gpus(config.num_gpus)
                .num_nvswitches(config.num_nvswitches)
                .hotplug_off(config.hotplug_off)
                .root_verity(config.root_verity)
                .maybe_qemu_version(config.qemu_version.clone())
                .ovmf_variant(ovmf_variant)
                .build();

            let measurements = machine
                .measure()
                .context("Failed to measure machine configuration")?;

            if config.json {
                println!("{}", serde_json::to_string_pretty(&measurements)?);
            } else {
                println!("Machine measurements:");
                println!("MRTD: {}", hex::encode(measurements.mrtd));
                println!("RTMR0: {}", hex::encode(measurements.rtmr0));
                println!("RTMR1: {}", hex::encode(measurements.rtmr1));
                println!("RTMR2: {}", hex::encode(measurements.rtmr2));
            }
        }
        Commands::Diagnose(config) => run_diagnose(config)?,
    }

    Ok(())
}

#[derive(Parser)]
struct DiagnoseConfig {
    /// VmConfig JSON. Matches the schema VMM serializes into KMS metadata
    /// (dstack_types::VmConfig). When KMS/verifier reports an MR mismatch, dump
    /// the same VmConfig payload it used and pass it here.
    #[arg(long)]
    vm_config: PathBuf,

    /// Image directory containing ovmf.fd / bzImage / initramfs.cpio.gz /
    /// metadata.json. If omitted, falls back to looking up `vm_config.image`
    /// under `--image-base-dir`.
    #[arg(long)]
    image_dir: Option<PathBuf>,

    /// Base directory containing one subdir per image (e.g.
    /// /opt/dstack/dstack-images). Only used when `--image-dir` is not given.
    #[arg(long)]
    image_base_dir: Option<PathBuf>,

    /// Optional actual measurements for comparison. Hex strings (no `0x` prefix).
    #[arg(long)]
    actual_mrtd: Option<String>,
    #[arg(long)]
    actual_rtmr0: Option<String>,
    #[arg(long)]
    actual_rtmr1: Option<String>,
    #[arg(long)]
    actual_rtmr2: Option<String>,

    /// Output JSON
    #[arg(long)]
    json: bool,
}

/// Semantic label for each RTMR0 event log entry. Indices match
/// `tdvf::rtmr0_log` (see dstack-mr/src/tdvf.rs).
fn rtmr0_labels(variant: OvmfVariant) -> &'static [(&'static str, &'static str)] {
    match variant {
        OvmfVariant::Pre202505 => &[
            (
                "td_hob",
                "varies-with: memory_size, firmware section layout",
            ),
            ("cfv_image", "fixed: hardcoded constant"),
            ("efi:SecureBoot", "fixed: TDX EFI variable"),
            ("efi:PK", "fixed: TDX EFI variable"),
            ("efi:KEK", "fixed: TDX EFI variable"),
            ("efi:db", "fixed: TDX EFI variable"),
            ("efi:dbx", "fixed: TDX EFI variable"),
            ("separator", "fixed: sha384(0x00000000)"),
            (
                "acpi_loader",
                "varies-with: cpu_count, pic, smm, hpet, hotplug_off, pci_hole64, root_verity, host_share_mode, num_gpus, num_nvswitches, hugepages, qemu_version",
            ),
            ("acpi_rsdp", "same as acpi_loader"),
            ("acpi_tables", "same as acpi_loader"),
            (
                "boot_order",
                "fixed: sha384(0x0000) — raw 2 bytes in legacy OVMF",
            ),
            ("Boot0000", "fixed: legacy OVMF UiApp constant"),
        ],
        OvmfVariant::Stable202505 => &[
            (
                "td_hob",
                "varies-with: memory_size, firmware section layout",
            ),
            ("cfv_image", "fixed: hardcoded constant"),
            (
                "fwcfg:BootMenu",
                "fixed: sha384(0x0000) — dstack never sets -boot menu=on",
            ),
            (
                "fwcfg:bootorder",
                "fixed: sha384 of /rom@genroms/linuxboot_dma.bin (q35 + -kernel)",
            ),
            ("efi:SecureBoot", "fixed: TDX EFI variable"),
            ("efi:PK", "fixed: TDX EFI variable"),
            ("efi:KEK", "fixed: TDX EFI variable"),
            ("efi:db", "fixed: TDX EFI variable"),
            ("efi:dbx", "fixed: TDX EFI variable"),
            ("separator", "fixed: sha384(0x00000000)"),
            (
                "acpi_loader",
                "varies-with: cpu_count, pic, smm, hpet, hotplug_off, pci_hole64, root_verity, host_share_mode, num_gpus, num_nvswitches, hugepages, qemu_version",
            ),
            ("acpi_rsdp", "same as acpi_loader"),
            ("acpi_tables", "same as acpi_loader"),
            (
                "variable_authority",
                "fixed: signer cert constant (edk2-stable202505 build)",
            ),
            (
                "boot_order_var",
                "fixed: sha384 of UEFI_VARIABLE_DATA for [Boot0000,Boot0001]",
            ),
            ("Boot0000", "fixed: BootManagerMenuApp (OVMF FV)"),
            (
                "Boot0001",
                "fixed: EFI Firmware Setup / FrontPage (OVMF FV)",
            ),
        ],
    }
}

fn resolve_image_dir(config: &DiagnoseConfig, vm: &VmConfig) -> Result<PathBuf> {
    if let Some(dir) = &config.image_dir {
        return Ok(dir.clone());
    }
    let base = config
        .image_base_dir
        .as_ref()
        .context("either --image-dir or --image-base-dir must be set")?;
    let image_name = vm
        .image
        .as_ref()
        .context("vm_config.image is empty; pass --image-dir directly")?;
    Ok(base.join(image_name))
}

fn check(label: &str, expected: &[u8], actual_hex: &Option<String>) -> Option<bool> {
    actual_hex.as_ref().map(|hex_str| {
        let trimmed = hex_str.trim().trim_start_matches("0x");
        match hex::decode(trimmed) {
            Ok(actual) if actual == expected => {
                println!("  {label}: MATCH");
                true
            }
            Ok(actual) => {
                println!(
                    "  {label}: MISMATCH\n    expected: {}\n    actual:   {}",
                    hex::encode(expected),
                    hex::encode(&actual),
                );
                false
            }
            Err(e) => {
                eprintln!("  {label}: invalid actual hex ({e})");
                false
            }
        }
    })
}

fn run_diagnose(config: &DiagnoseConfig) -> Result<()> {
    let raw = fs::read_to_string(&config.vm_config).context("failed to read --vm-config")?;
    let vm: VmConfig = serde_json::from_str(&raw).context("failed to parse VmConfig JSON")?;

    let image_dir = resolve_image_dir(config, &vm)?;
    let metadata_path = image_dir.join("metadata.json");
    let metadata = fs::read_to_string(&metadata_path)
        .with_context(|| format!("failed to read {}", metadata_path.display()))?;
    let image_info: ImageInfo = serde_json::from_str(&metadata)?;

    let firmware = image_dir.join(&image_info.bios).display().to_string();
    let kernel = image_dir.join(&image_info.kernel).display().to_string();
    let initrd = image_dir.join(&image_info.initrd).display().to_string();
    let cmdline = format!("{} initrd=initrd", image_info.cmdline);

    // Same resolution order as the verifier (see verifier::compute_measurement_details):
    // explicit vm_config.ovmf_variant > image_info.ovmf_variant > parse vm_config.image
    // > parse image_info.version > legacy default.
    let ovmf_variant = vm
        .ovmf_variant
        .or(image_info.ovmf_variant)
        .unwrap_or_else(|| {
            let from_image = ovmf_variant_for_image(vm.image.as_deref());
            if !image_info.version.is_empty() {
                ovmf_variant_for_version(&image_info.version).unwrap_or(from_image)
            } else {
                from_image
            }
        });

    let details = Machine::builder()
        .cpu_count(vm.cpu_count)
        .memory_size(vm.memory_size)
        .firmware(&firmware)
        .kernel(&kernel)
        .initrd(&initrd)
        .kernel_cmdline(&cmdline)
        .root_verity(true)
        .hotplug_off(vm.hotplug_off)
        .maybe_two_pass_add_pages(vm.qemu_single_pass_add_pages)
        .maybe_pic(vm.pic)
        .maybe_qemu_version(vm.qemu_version.clone())
        .maybe_pci_hole64_size(if vm.pci_hole64_size > 0 {
            Some(vm.pci_hole64_size)
        } else {
            None
        })
        .hugepages(vm.hugepages)
        .num_gpus(vm.num_gpus)
        .num_nvswitches(vm.num_nvswitches)
        .host_share_mode(vm.host_share_mode.clone())
        .ovmf_variant(ovmf_variant)
        .build()
        .measure_with_logs()
        .context("failed to compute expected MRs")?;

    let labels = rtmr0_labels(ovmf_variant);

    if config.json {
        let log: Vec<serde_json::Value> = details.rtmr_logs[0]
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let (label, note) = labels.get(i).copied().unwrap_or(("(unlabelled)", ""));
                serde_json::json!({
                    "index": i,
                    "label": label,
                    "digest": hex::encode(h),
                    "note": note,
                })
            })
            .collect();
        let out = serde_json::json!({
            "ovmf_variant": format!("{:?}", ovmf_variant),
            "mrtd": hex::encode(&details.measurements.mrtd),
            "rtmr0": hex::encode(&details.measurements.rtmr0),
            "rtmr1": hex::encode(&details.measurements.rtmr1),
            "rtmr2": hex::encode(&details.measurements.rtmr2),
            "rtmr0_log": log,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("=== inputs ===");
    println!(
        "  cpu={} mem={} qemu_version={:?} pic={:?} two_pass={:?}",
        vm.cpu_count, vm.memory_size, vm.qemu_version, vm.pic, vm.qemu_single_pass_add_pages,
    );
    println!(
        "  hugepages={} num_gpus={} num_nvswitches={} hotplug_off={} pci_hole64={}",
        vm.hugepages, vm.num_gpus, vm.num_nvswitches, vm.hotplug_off, vm.pci_hole64_size,
    );
    println!("  host_share_mode={:?}", vm.host_share_mode);
    println!("  image_dir={}", image_dir.display());
    println!("  ovmf_variant={:?}", ovmf_variant);

    println!("\n=== expected measurements ===");
    println!("  MRTD:  {}", hex::encode(&details.measurements.mrtd));
    println!("  RTMR0: {}", hex::encode(&details.measurements.rtmr0));
    println!("  RTMR1: {}", hex::encode(&details.measurements.rtmr1));
    println!("  RTMR2: {}", hex::encode(&details.measurements.rtmr2));

    println!(
        "\n=== RTMR0 event log ({} entries) ===",
        details.rtmr_logs[0].len()
    );
    for (i, hash) in details.rtmr_logs[0].iter().enumerate() {
        let (label, note) = labels.get(i).copied().unwrap_or(("(unlabelled)", ""));
        println!("  [{:>2}] {:<20} {}", i, label, hex::encode(hash));
        if !note.is_empty() {
            println!("       {note}");
        }
    }

    let want_compare = config.actual_mrtd.is_some()
        || config.actual_rtmr0.is_some()
        || config.actual_rtmr1.is_some()
        || config.actual_rtmr2.is_some();
    if want_compare {
        println!("\n=== comparison ===");
        let mut all_ok = true;
        for (label, expected, actual) in [
            ("MRTD ", &details.measurements.mrtd, &config.actual_mrtd),
            ("RTMR0", &details.measurements.rtmr0, &config.actual_rtmr0),
            ("RTMR1", &details.measurements.rtmr1, &config.actual_rtmr1),
            ("RTMR2", &details.measurements.rtmr2, &config.actual_rtmr2),
        ] {
            if let Some(ok) = check(label, expected, actual) {
                all_ok &= ok;
            }
        }
        if !all_ok {
            bail!("one or more measurements mismatched");
        }
    }

    Ok(())
}
