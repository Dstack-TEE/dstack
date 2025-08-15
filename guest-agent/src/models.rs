// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use guest_api::{Container, SystemInfo};
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
}

#[derive(Template)]
#[template(path = "metrics.tpl", escape = "none")]
pub struct Metrics {
    pub system_info: SystemInfo,
}
