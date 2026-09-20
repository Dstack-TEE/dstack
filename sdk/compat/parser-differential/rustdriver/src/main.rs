// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(deprecated)]
use dstack_sdk::dstack_client_v0::{DstackClientV0, TlsKeyConfig};
use dstack_sdk::dstack_client_v1::DstackClientV1;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn select(sock: &str, case: &str) {
    let mut s = UnixStream::connect(sock).unwrap();
    let req = format!("POST /__case/{case} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = [0u8; 4096];
    let _ = s.read(&mut buf);
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (sock, case, method) = (a[1].clone(), a[2].clone(), a[3].clone());
    select(&sock, &case);
    if method.starts_with("v0") {
        let c0 = DstackClientV0::new(Some(&sock));
        let out = match method.as_str() {
            "v0GetKey" => c0.get_key(Some("d".into()), None).await.map(|r| {
                format!("key={} chain={} decode={}", &r.key[..16.min(r.key.len())],
                    r.signature_chain.len(),
                    match r.decode_key() { Ok(b) => hex::encode(b), Err(e) => format!("<{e}>") })
            }),
            "v0Info" => c0.info().await.map(|r| {
                format!("app_id={} tcb=ok mrtd={}", &r.app_id[..16.min(r.app_id.len())],
                    &r.tcb_info.mrtd[..8.min(r.tcb_info.mrtd.len())])
            }),
            "v0TlsKey" => c0.get_tls_key(TlsKeyConfig::builder().build()).await.map(|r| {
                format!("key_len={} chain={}", r.key.len(), r.certificate_chain.len())
            }),
            _ => unreachable!(),
        };
        report(out);
        return;
    }
    let c = DstackClientV1::new(Some(&sock));
    let out = match method.as_str() {
        "GetKey" => c.get_key("d", "secp256k1").await.map(|r| {
            format!("key={} chain={}", &hex::encode(&r.key)[..16.min(r.key.len()*2)], r.signature_chain.len())
        }),
        "Info" => c.info().await.map(|r| {
            format!("app_id={} app_name={:?} os_image_hash={}",
                &hex::encode(&r.app_id)[..16.min(r.app_id.len()*2)], r.app_name,
                &hex::encode(&r.os_image_hash)[..16.min(r.os_image_hash.len()*2)])
        }),
        "Attest" => c.attest(vec![1u8; 32], false).await.map(|r| {
            format!("attestation={}B gpu={}", r.attestation.len(), r.boottime_gpu_evidence.len())
        }),
        _ => unreachable!(),
    };
    report(out);
}

fn report(out: anyhow::Result<String>) {
    match out {
        Ok(s) => println!("OK|{s}"),
        Err(e) => println!("ERR|{}", format!("{e:#}").replace('\n', " ").chars().take(160).collect::<String>()),
    }
}
