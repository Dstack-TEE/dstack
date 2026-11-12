// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WASM ABI for [`dstack_mr::tdx::verify_tdx_lite_os`].
//!
//! Zero imports, no wasm-bindgen. JSON in/out:
//! input `{mrtd, rtmr0, rtmr1, rtmr2, event_log, vm_config}`,
//! output `{ok, os_image_hash, reason}`. `os_image_hash` is set only when `ok`.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use cc_eventlog::TdxEvent;
use dstack_mr::{tdx::verify_tdx_lite_os, TdxMeasurements};
use dstack_types::VmConfig;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    event_log: String,
    vm_config: String,
}

#[derive(Serialize, Default)]
struct Output {
    ok: bool,
    os_image_hash: Option<String>,
    reason: Option<String>,
}

fn parse_mr(name: &str, value: &str) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes = hex::decode(value).with_context(|| format!("{name} is not valid hex"))?;
    if bytes.len() != 48 {
        bail!("{name} has length {}, expected 48 bytes", bytes.len());
    }
    Ok(bytes)
}

fn verify_input(input: Input) -> Result<Output> {
    let vm: VmConfig =
        serde_json::from_str(&input.vm_config).context("vm_config is not valid JSON")?;
    let mrs = TdxMeasurements {
        mrtd: parse_mr("mrtd", &input.mrtd)?,
        rtmr0: parse_mr("rtmr0", &input.rtmr0)?,
        rtmr1: parse_mr("rtmr1", &input.rtmr1)?,
        rtmr2: parse_mr("rtmr2", &input.rtmr2)?,
    };
    let events: Vec<TdxEvent> =
        serde_json::from_str(&input.event_log).context("event_log is not valid JSON")?;
    verify_tdx_lite_os(&mrs, &events, &vm)?;
    Ok(Output {
        ok: true,
        os_image_hash: Some(hex::encode(&vm.os_image_hash)),
        reason: None,
    })
}

fn run(bytes: &[u8]) -> Output {
    match serde_json::from_slice::<Input>(bytes)
        .context("input is not valid JSON")
        .and_then(verify_input)
    {
        Ok(out) => out,
        Err(err) => Output {
            ok: false,
            os_image_hash: None,
            reason: Some(format!("{err:#}")),
        },
    }
}

#[cfg(target_arch = "wasm32")]
mod abi {
    use super::run;

    #[no_mangle]
    pub extern "C" fn alloc(len: usize) -> *mut u8 {
        let mut v = Vec::<u8>::with_capacity(len);
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        ptr
    }

    /// # Safety
    /// `ptr`/`len` must come from [`alloc`] or a result of [`verify_tdx_lite`].
    #[no_mangle]
    pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
        drop(Vec::from_raw_parts(ptr, 0, len));
    }

    /// # Safety
    /// `ptr`/`len` must describe a buffer obtained from [`alloc`] and filled by
    /// the caller.
    #[no_mangle]
    pub unsafe extern "C" fn verify_tdx_lite(ptr: *const u8, len: usize) -> u64 {
        let input = core::slice::from_raw_parts(ptr, len);
        let out = serde_json::to_vec(&run(input)).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
        let mut out = out.into_boxed_slice();
        let (ptr, len) = (out.as_mut_ptr() as u64, out.len() as u64);
        core::mem::forget(out);
        (ptr << 32) | len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct GetQuoteFixture {
        quote: String,
        event_log: String,
        vm_config: String,
    }

    /// Builds the ABI input from the captured GetQuote fixture, letting each
    /// test edit it before serialization.
    fn fixture_payload(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let fixture: GetQuoteFixture = serde_json::from_str(include_str!(
            "../../../verifier/fixtures/tdx-lite-getquote.json"
        ))
        .expect("fixture parses");
        let quote = hex::decode(&fixture.quote).expect("quote is hex");
        let quote = dcap_qvl::quote::Quote::parse(&quote).expect("fixture quote parses");
        let report = quote.report.as_td10().expect("TDX 1.0 report");
        let mut payload = serde_json::json!({
            "mrtd": hex::encode(report.mr_td),
            "rtmr0": hex::encode(report.rt_mr0),
            "rtmr1": hex::encode(report.rt_mr1),
            "rtmr2": hex::encode(report.rt_mr2),
            "event_log": fixture.event_log,
            "vm_config": fixture.vm_config,
        });
        edit(&mut payload);
        serde_json::to_vec(&payload).expect("payload serializes")
    }

    #[test]
    fn fixture_is_accepted() {
        let out = run(&fixture_payload(|_| {}));
        assert!(out.ok, "{:?}", out.reason);
        assert!(out.os_image_hash.is_some());
        assert!(out.reason.is_none());
    }

    #[test]
    fn stuffed_os_image_hash_is_not_returned_on_failure() {
        let out = run(&fixture_payload(|payload| {
            let mut vm: serde_json::Value =
                serde_json::from_str(payload["vm_config"].as_str().expect("vm_config string"))
                    .expect("vm_config parses");
            vm["os_image_hash"] = "ab".repeat(32).into();
            payload["vm_config"] = vm.to_string().into();
        }));
        assert!(!out.ok);
        assert_eq!(out.os_image_hash, None);
    }

    #[test]
    fn mixed_case_hex_is_accepted() {
        let out = run(&fixture_payload(|payload| {
            let mrtd = payload["mrtd"]
                .as_str()
                .expect("mrtd string")
                .to_uppercase();
            payload["mrtd"] = mrtd.into();
        }));
        assert!(out.ok, "{:?}", out.reason);
    }

    #[test]
    fn garbage_input_is_rejected_without_panic() {
        let out = run(
            br#"{"mrtd":"","rtmr0":"","rtmr1":"","rtmr2":"","event_log":"[]","vm_config":"{}"}"#,
        );
        assert!(!out.ok);
        assert!(out.reason.is_some());
        assert_eq!(out.os_image_hash, None);
    }
}
