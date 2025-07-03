use crate::tdvf::Tdvf;
use crate::util::debug_print_log;
use crate::{kernel, TdxMeasurements};
use crate::{measure_log, measure_sha384};
use anyhow::{Context, Result};
use fs_err as fs;
use log::debug;

#[derive(Debug, bon::Builder)]
pub struct Machine<'a> {
    pub cpu_count: u8,
    pub memory_size: u64,
    pub firmware: &'a str,
    pub kernel: &'a str,
    pub initrd: &'a str,
    pub kernel_cmdline: &'a str,
    pub two_pass_add_pages: bool,
    pub pic: bool,
    #[builder(default = false)]
    pub smm: bool,
    pub pci_hole64_size: Option<u64>,
    pub hugepages: bool,
    pub num_gpus: u32,
    pub num_nvswitches: u32,
    pub hotplug_off: bool,
    pub root_verity: bool,
}

impl Machine<'_> {
    pub fn measure(&self) -> Result<TdxMeasurements> {
        debug!("measuring machine: {self:#?}");
        let fw_data = fs::read(self.firmware)?;
        let kernel_data = fs::read(self.kernel)?;
        let initrd_data = fs::read(self.initrd)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd(self).context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;
        let rtmr1 = kernel::measure_kernel(
            &kernel_data,
            initrd_data.len() as u32,
            self.memory_size,
            0x28000,
        )?;

        let rtmr2_log = vec![
            kernel::measure_cmdline(self.kernel_cmdline),
            measure_sha384(&initrd_data),
        ];
        debug_print_log("RTMR2", &rtmr2_log);
        let rtmr2 = measure_log(&rtmr2_log);

        Ok(TdxMeasurements {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
        })
    }
}
