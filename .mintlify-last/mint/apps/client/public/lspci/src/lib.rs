use std::process::Command;

use anyhow::{Context, Result};

/// Represents a PCI device with the specified fields.
#[derive(Debug)]
pub struct Device {
    pub slot: String,
    pub class: String,
    pub class_id: String,
    pub description: String,
    pub vendor_id: String,
    pub product_id: String,
    pub control: Control,
    pub numa_node: Option<u32>,
}

/// Represents the control settings of a PCI device.
#[derive(Debug)]
pub struct Control {
    pub io: bool,
    pub mem: bool,
    pub bus_master: bool,
}

impl Device {
    pub fn full_product_id(&self) -> String {
        format!("{}:{}", self.vendor_id, self.product_id)
    }

    pub fn in_use(&self) -> bool {
        self.control.bus_master
    }
}

/// Runs `lspci` and parses the output into a vector of `Device` structs.
pub fn lspci_filtered(filter: impl Fn(&Device) -> bool) -> Result<Vec<Device>> {
    let output = Command::new("lspci")
        .args(["-nn", "-vv"])
        .output()
        .context("Failed to run lspci")?;
    Ok(parse_lspci(
        &String::from_utf8(output.stdout).context("Failed to parse lspci output")?,
        filter,
    ))
}

/// Parses the `lspci` output into a vector of `Device` structs.
///
/// # Arguments
/// * `output` - A string slice containing the `lspci` output.
///
/// # Returns
/// A vector of `Device` structs, each representing a parsed PCI device.
pub fn parse_lspci(output: &str, filter: impl Fn(&Device) -> bool) -> Vec<Device> {
    let lines: Vec<&str> = output.lines().collect();
    let mut devices = Vec::new();
    let mut current_device = Vec::new();

    // Group lines into device sections
    for line in lines {
        let line = line.trim_end();
        if !line.is_empty() {
            if !line.starts_with("\t") {
                if !current_device.is_empty() {
                    let device = parse_device(&current_device);
                    if filter(&device) {
                        devices.push(device);
                    }
                    current_device = Vec::new();
                }
                current_device.push(line);
            } else {
                current_device.push(line.trim_start()); // Remove leading tab
            }
        }
    }
    if !current_device.is_empty() {
        let device = parse_device(&current_device);
        if filter(&device) {
            devices.push(device);
        }
    }
    devices
}

/// Parses a single device section into a `Device` struct.
///
/// # Arguments
/// * `device_lines` - A slice of strings representing the lines for one device.
///
/// # Returns
/// A `Device` struct with the parsed fields.
fn parse_device(device_lines: &[&str]) -> Device {
    let device_line = device_lines[0];
    let (slot, class, class_id, description, vendor_id, product_id) =
        parse_device_line(device_line);

    let mut control = Control {
        io: false,
        mem: false,
        bus_master: false,
    };
    let mut numa_node = None;

    // Parse detail lines
    for line in device_lines.iter().skip(1) {
        if line.starts_with("Control: ") {
            control = parse_control_line(line);
        } else if line.starts_with("NUMA node: ") {
            numa_node = parse_numa_node_line(line);
        }
    }

    Device {
        slot,
        class,
        class_id,
        description,
        vendor_id,
        product_id,
        control,
        numa_node,
    }
}

/// Parses the main device line to extract slot, class, class_id, description, vendor_id, and product_id.
///
/// # Arguments
/// * `line` - The main line of a device entry (e.g., "ff:1e.5 System peripheral [0880]: ...").
///
/// # Returns
/// A tuple of strings containing the parsed fields.
fn parse_device_line(line: &str) -> (String, String, String, String, String, String) {
    let words: Vec<&str> = line.split_whitespace().collect();
    if let Some(i) = words.iter().position(|w| w.ends_with("]:")) {
        let slot = words[0].to_string();
        let class = words[1..i].join(" ");
        let class_id = &words[i][1..words[i].len() - 2]; // Remove [ and ]:

        // Look for the vendor ID and product ID pattern [vendor_id:product_id]
        if let Some(j) = words[i + 1..]
            .iter()
            .position(|w| w.starts_with("[") && w.contains(":") && w.ends_with("]"))
        {
            // Extract vendor name without including the "Device" keyword
            let vendor_end = i + 1 + j;
            let mut vendor_words = Vec::new();

            #[allow(clippy::needless_range_loop)]
            for k in i + 1..vendor_end {
                // Skip the word "Device" if it's standalone
                if words[k] != "Device" {
                    vendor_words.push(words[k]);
                }
            }

            let description = vendor_words.join(" ");
            let id_part = &words[vendor_end][1..words[vendor_end].len() - 1]; // Remove [ and ]

            if let Some((vendor_id, product_id)) = id_part.split_once(':') {
                return (
                    slot,
                    class,
                    class_id.to_string(),
                    description,
                    vendor_id.to_string(),
                    product_id.to_string(),
                );
            }
        }
    }
    // Return defaults if parsing fails
    (
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    )
}

/// Parses the control line to extract io, mem, and bus_master settings.
///
/// # Arguments
/// * `line` - The control line (e.g., "Control: I/O- Mem- BusMaster- ...").
///
/// # Returns
/// A `Control` struct with the parsed settings.
fn parse_control_line(line: &str) -> Control {
    let mut control = Control {
        io: false,
        mem: false,
        bus_master: false,
    };
    if let Some(items) = line.strip_prefix("Control: ") {
        for item in items.split_whitespace() {
            match item {
                "I/O+" => control.io = true,
                "I/O-" => control.io = false,
                "Mem+" => control.mem = true,
                "Mem-" => control.mem = false,
                "BusMaster+" => control.bus_master = true,
                "BusMaster-" => control.bus_master = false,
                _ => {}
            }
        }
    }
    control
}

/// Parses the NUMA node line to extract the node number.
///
/// # Arguments
/// * `line` - The NUMA node line (e.g., "NUMA node: 1").
///
/// # Returns
/// An `Option<u32>` with the parsed NUMA node number, or `None` if not applicable.
fn parse_numa_node_line(line: &str) -> Option<u32> {
    if let Some(numa_str) = line.strip_prefix("NUMA node: ") {
        numa_str.parse::<u32>().ok()
    } else {
        None
    }
}

#[test]
fn test_lspci() {
    let lspci_output = r#"
bc:02.0 PCI bridge [0604]: PMC-Sierra Inc. Device [11f8:4128] (prog-if 00 [Normal decode])
	Subsystem: NVIDIA Corporation Device [10de:1643]
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr+ Stepping- SERR+ FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0, Cache Line Size: 32 bytes
	Interrupt: pin ? routed to IRQ 92
	NUMA node: 1
	IOMMU group: 82
	Bus: primary=bc, secondary=bf, subordinate=bf, sec-latency=0
	I/O behind bridge: 0000f000-00000fff [disabled] [32-bit]
	Memory behind bridge: de000000-dfffffff [size=32M] [32-bit]
	Prefetchable memory behind bridge: 00000000fff00000-00000000000fffff [disabled] [64-bit]
	Secondary status: 66MHz- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- <SERR- <PERR-
	BridgeCtl: Parity+ SERR+ NoISA- VGA- VGA16- MAbort- >Reset- FastB2B-
		PriDiscTmr- SecDiscTmr- DiscTmrStat- DiscTmrSERREn-
	Capabilities: <access denied>
	Kernel driver in use: pcieport

bc:03.0 PCI bridge [0604]: PMC-Sierra Inc. Device [11f8:4128] (prog-if 00 [Normal decode])
	Subsystem: NVIDIA Corporation Device [10de:1643]
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr+ Stepping- SERR+ FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0, Cache Line Size: 32 bytes
	Interrupt: pin ? routed to IRQ 93
	NUMA node: 1
	IOMMU group: 82
	Bus: primary=bc, secondary=c0, subordinate=c0, sec-latency=0
	I/O behind bridge: 0000f000-00000fff [disabled] [32-bit]
	Memory behind bridge: dc000000-ddffffff [size=32M] [32-bit]
	Prefetchable memory behind bridge: 00000000fff00000-00000000000fffff [disabled] [64-bit]
	Secondary status: 66MHz- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- <SERR- <PERR-
	BridgeCtl: Parity+ SERR+ NoISA- VGA- VGA16- MAbort- >Reset- FastB2B-
		PriDiscTmr- SecDiscTmr- DiscTmrStat- DiscTmrSERREn-
	Capabilities: <access denied>
	Kernel driver in use: pcieport

bd:00.0 Bridge [0680]: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:22a3] (rev a1)
	Subsystem: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:1796]
	Physical Slot: 1-1
	Control: I/O- Mem- BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr+ Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Interrupt: pin A routed to IRQ 10
	NUMA node: 1
	IOMMU group: 82
	Region 0: Memory at e2000000 (64-bit, non-prefetchable) [disabled] [size=32M]
	Capabilities: <access denied>

be:00.0 Bridge [0680]: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:22a3] (rev a1)
	Subsystem: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:1796]
	Physical Slot: 2-1
	Control: I/O- Mem- BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr+ Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Interrupt: pin A routed to IRQ 5
	NUMA node: 1
	IOMMU group: 82
	Region 0: Memory at e0000000 (64-bit, non-prefetchable) [disabled] [size=32M]
	Capabilities: <access denied>

bf:00.0 Bridge [0680]: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:22a3] (rev a1)
	Subsystem: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:1796]
	Physical Slot: 3-1
	Control: I/O- Mem- BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr+ Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Interrupt: pin A routed to IRQ 11
	NUMA node: 1
	IOMMU group: 82
	Region 0: Memory at de000000 (64-bit, non-prefetchable) [disabled] [size=32M]
	Capabilities: <access denied>
	IOMMU group: 468
"#;

    let devices = parse_lspci(lspci_output, |_| true);
    insta::assert_debug_snapshot!(devices);
    assert_eq!(devices[0].full_product_id(), "11f8:4128");
}
