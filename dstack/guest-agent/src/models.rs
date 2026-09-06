// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use guest_api::{Container, GpuInfoResponse, SystemInfo};
use rinja::Template;

mod filters {
    use anyhow::Result;

    pub fn cname<'a>(s: &'a Option<&'a String>) -> Result<&'a str, rinja::Error> {
        let name = s.map(|s| s.as_str()).unwrap_or_default();
        Ok(name.strip_prefix("/").unwrap_or(name))
    }

    pub fn hsize(s: &u64) -> Result<String, rinja::Error> {
        // convert bytes to human readable size
        let mut size = *s as f64;
        let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
        let mut unit_index = 0;
        while size >= 1024.0 && unit_index < units.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        Ok(format!(
            "{:.2} {}",
            size,
            units.get(unit_index).unwrap_or(&"?")
        ))
    }

    pub fn hex(s: &[u8]) -> Result<String, rinja::Error> {
        Ok(hex::encode(s))
    }

    /// The label set every `dstack_gpu_*` series carries, matching
    /// dcgm-exporter so host-side tooling that speaks BDF can correlate.
    /// Written once here rather than repeated in the template for each metric.
    pub fn gpu_labels(gpu: &guest_api::GpuDevice) -> Result<String, rinja::Error> {
        Ok(format!(
            "{{index=\"{}\", uuid=\"{}\", pci_bus_id=\"{}\"}}",
            gpu.index,
            prometheus_label(&gpu.uuid)?,
            prometheus_label(&gpu.pci_bus_id)?,
        ))
    }

    pub fn prometheus_label(s: &str) -> Result<String, rinja::Error> {
        Ok(s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('"', "\\\""))
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct Dashboard {
    pub app_name: String,
    pub app_id: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub key_provider_info: String,
    pub tcb_info: String,
    pub containers: Vec<Container>,
    pub system_info: SystemInfo,
    pub public_sysinfo: bool,
    pub public_logs: bool,
    pub public_tcbinfo: bool,
    pub cloud_vendor: String,
    pub cloud_product: String,
    pub gpu_info: GpuInfoResponse,
}

#[derive(Template)]
#[template(path = "metrics.tpl", escape = "none")]
pub struct Metrics {
    pub system_info: SystemInfo,
    pub gpu_info: GpuInfoResponse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use guest_api::GpuDevice;
    use rinja::Template;

    fn render(gpu_info: GpuInfoResponse) -> String {
        Metrics {
            system_info: Default::default(),
            gpu_info,
        }
        .render()
        .expect("render")
    }

    fn gpu(index: u32) -> GpuDevice {
        GpuDevice {
            index,
            uuid: format!("GPU-{index}"),
            pci_bus_id: format!("00000000:0{index}:00.0"),
            ..Default::default()
        }
    }

    /// The regression this whole design exists for: a sample older than the
    /// collection TTL is still exposed. Emitting nothing meant every scrape at
    /// Prometheus' default interval saw zero GPU series on a healthy card.
    #[test]
    fn a_stale_sample_still_produces_series() {
        let body = render(GpuInfoResponse {
            gpus: vec![GpuDevice {
                utilization_gpu: Some(37),
                ..gpu(0)
            }],
            sample_age_ms: Some(60_000),
            ..Default::default()
        });
        assert!(body.contains(
            r#"dstack_gpu_utilization_percent{index="0", uuid="GPU-0", pci_bus_id="00000000:00:00.0"} 37"#
        ));
        assert!(body.contains("dstack_gpu_nvml_up 1"));
        assert!(body.contains("dstack_gpu_sample_age_seconds 60"));
    }

    /// A field NVML could not answer must be absent, not zero: a scraped 0 is
    /// indistinguishable from an idle GPU.
    #[test]
    fn a_field_that_failed_to_sample_emits_no_series() {
        let body = render(GpuInfoResponse {
            gpus: vec![GpuDevice {
                utilization_gpu: None,
                temperature_c: Some(0),
                ..gpu(0)
            }],
            ..Default::default()
        });
        assert!(!body.contains("dstack_gpu_utilization_percent{"));
        assert!(body.contains(r#"dstack_gpu_temperature_celsius{index="0""#));
    }

    /// Failed queries are counted from a list. When they were a `"; "`-joined
    /// string, a message containing that separator inflated the count.
    #[test]
    fn query_errors_counts_entries_not_separators() {
        let body = render(GpuInfoResponse {
            gpus: vec![GpuDevice {
                errors: vec![
                    "power: not supported".into(),
                    "memory: unknown error; retry advised".into(),
                ],
                ..gpu(0)
            }],
            ..Default::default()
        });
        assert!(body.contains(
            r#"dstack_gpu_query_errors{index="0", uuid="GPU-0", pci_bus_id="00000000:00:00.0"} 2"#
        ));
    }

    /// A guest with no GPU reports `nvml_up 1` with no devices: the collector
    /// ran and found nothing. `nvml_up 0` is reserved for "could not tell".
    #[test]
    fn a_guest_without_gpus_is_not_reported_as_a_collection_failure() {
        let body = render(GpuInfoResponse::default());
        assert!(body.contains("dstack_gpu_nvml_up 1"));
        assert!(!body.contains("dstack_gpu_utilization_percent{"));
        assert!(!body.contains("dstack_gpu_cc_ready"));

        let failed = render(GpuInfoResponse {
            error: "NVIDIA driver is not loaded".into(),
            ..Default::default()
        });
        assert!(failed.contains("dstack_gpu_nvml_up 0"));
    }

    /// Label values are escaped, so a hostile UUID cannot inject a series.
    #[test]
    fn label_values_are_escaped() {
        let body = render(GpuInfoResponse {
            gpus: vec![GpuDevice {
                uuid: r#"GPU-"injected" \ end"#.into(),
                utilization_gpu: Some(1),
                ..gpu(0)
            }],
            ..Default::default()
        });
        assert!(body.contains(r#"uuid="GPU-\"injected\" \\ end""#), "{body}");
    }

    /// Watts are rendered from milliwatts. Raw f32 Display would print
    /// 70.123001 for a card drawing 70.123 W.
    #[test]
    fn dashboard_power_is_formatted_to_one_decimal() {
        let dashboard = Dashboard {
            app_name: String::new(),
            app_id: vec![],
            instance_id: vec![],
            device_id: vec![],
            key_provider_info: String::new(),
            tcb_info: String::new(),
            containers: vec![],
            system_info: Default::default(),
            public_sysinfo: true,
            public_logs: false,
            public_tcbinfo: false,
            cloud_vendor: String::new(),
            cloud_product: String::new(),
            gpu_info: GpuInfoResponse {
                gpus: vec![GpuDevice {
                    power_usage_mw: Some(70_123),
                    ..gpu(0)
                }],
                cc_enabled: Some(true),
                sample_age_ms: Some(2_500),
                ..Default::default()
            },
        };
        let html = dashboard.render().expect("render");
        assert!(html.contains("70.1 W"), "{html}");
    }
}
