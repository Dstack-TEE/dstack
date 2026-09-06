// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

pub use generated::*;

mod generated;

#[cfg(feature = "client")]
pub mod client;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn gpu_info_response_roundtrips_optional_fields() {
        let original = GpuInfoResponse {
            error: String::new(),
            cc_ready: Some(true),
            gpus: vec![GpuDevice {
                index: 0,
                uuid: "GPU-abc".into(),
                pci_bus_id: "00000000:01:00.0".into(),
                utilization_gpu: Some(12),
                utilization_memory: None,
                memory_total_bytes: Some(8 << 30),
                memory_used_bytes: Some(0),
                memory_free_bytes: None,
                temperature_c: Some(0),
                power_usage_mw: None,
                error: "temperature: timeout".into(),
                cc_enabled: Some(true),
            }],
        };
        let bytes = original.encode_to_vec();
        let decoded = GpuInfoResponse::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.gpus[0].utilization_memory, None);
        assert_eq!(decoded.gpus[0].memory_used_bytes, Some(0));
        assert_eq!(decoded.cc_ready, Some(true));
    }

    #[test]
    fn gpu_info_response_omits_unset_optionals() {
        let original = GpuInfoResponse {
            error: "failed to initialize NVML: driver not loaded".into(),
            cc_ready: None,
            gpus: vec![],
        };
        let decoded = GpuInfoResponse::decode(original.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded, original);
        assert!(decoded.gpus.is_empty());
        assert!(!decoded.error.is_empty());
        assert_eq!(decoded.cc_ready, None);
    }
}
