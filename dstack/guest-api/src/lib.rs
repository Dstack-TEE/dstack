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

    /// Every numeric field is `optional` so a consumer can tell "the query
    /// failed" from a genuine zero. That distinction only holds if it survives
    /// the wire, which is what this pins.
    #[test]
    fn gpu_info_response_roundtrips_optional_fields() {
        let original = GpuInfoResponse {
            error: String::new(),
            cc_ready: Some(true),
            cc_enabled: Some(true),
            sample_age_ms: Some(4200),
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
                errors: vec!["temperature: timeout".into()],
            }],
        };
        let bytes = original.encode_to_vec();
        let decoded = GpuInfoResponse::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(decoded.gpus[0].utilization_memory, None);
        assert_eq!(decoded.gpus[0].memory_used_bytes, Some(0));
        assert_eq!(decoded.cc_ready, Some(true));
        assert_eq!(decoded.sample_age_ms, Some(4200));
    }

    /// The NVML-unavailable shape: an error, no devices, and no CC state at
    /// all. `cc_ready` unset must not decode as `Some(false)`, which would
    /// read as "the handshake failed" rather than "we could not ask".
    #[test]
    fn gpu_info_response_omits_unset_optionals() {
        let original = GpuInfoResponse {
            error: "failed to initialize NVML: driver not loaded".into(),
            cc_ready: None,
            cc_enabled: None,
            sample_age_ms: None,
            gpus: vec![],
        };
        let decoded = GpuInfoResponse::decode(original.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded, original);
        assert!(decoded.gpus.is_empty());
        assert!(!decoded.error.is_empty());
        assert_eq!(decoded.cc_ready, None);
        assert_eq!(decoded.cc_enabled, None);
    }

    /// "No GPUs" is the default response: empty devices, empty error. It must
    /// stay distinguishable from every failure shape above.
    #[test]
    fn the_default_response_means_no_gpus_rather_than_a_failure() {
        let decoded =
            GpuInfoResponse::decode(GpuInfoResponse::default().encode_to_vec().as_slice())
                .expect("decode");
        assert!(decoded.gpus.is_empty());
        assert!(decoded.error.is_empty());
        assert_eq!(decoded.sample_age_ms, None);
    }

    /// Per-field failures are a list, so counting them for
    /// `dstack_gpu_query_errors` does not mean re-parsing a joined string.
    #[test]
    fn per_device_errors_are_counted_not_parsed() {
        let device = GpuDevice {
            index: 0,
            errors: vec![
                "power: not supported".into(),
                // A message containing the old "; " separator would have
                // inflated the count when errors were a joined string.
                "memory: unknown error; retry advised".into(),
            ],
            ..Default::default()
        };
        let decoded = GpuDevice::decode(device.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded.errors.len(), 2);
    }
}
