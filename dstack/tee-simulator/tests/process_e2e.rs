// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use mock_attestation::server::MockCollateralState;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn start(platform: &str, seed: [u8; 32]) -> (tempfile::TempDir, ChildGuard) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sys-config.json");
    fs_err::write(
        &path,
        serde_json::json!({
            "kms_urls": [], "gateway_urls": [], "pccs_url": null,
            "docker_registry": null, "host_api_url": null, "vm_config": "{}",
            "tee_simulator": {
                "platform": platform,
                "mock_attestation_seed": hex::encode(seed),
                "collateral_base_url": "http://127.0.0.1:18088"
            }
        })
        .to_string(),
    )
    .unwrap();
    let mountpoint = dir.path().join("tsm");
    let mut args = vec![
        "--sys-config".to_string(),
        path.display().to_string(),
        "--runtime-dir".to_string(),
        dir.path().display().to_string(),
    ];
    if platform == "tdx" {
        args.extend(["--mountpoint".into(), mountpoint.display().to_string()]);
    }
    let child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_dstack-tee-simulator"))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        let ready = if platform == "tdx" {
            mountpoint.join("com.intel.dcap/outblob").exists()
        } else {
            reqwest::get("http://127.0.0.1:8088/tpm/aia/root.pem")
                .await
                .is_ok()
        };
        if ready {
            return (dir, child);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("simulator process did not become ready")
}

#[tokio::test]
async fn separate_simulator_process_imports_sys_config_seed_for_all_platforms() {
    let seed = [0x71; 32];
    let host = MockCollateralState::from_seed(seed, "http://127.0.0.1:18088").unwrap();
    let client = reqwest::Client::new();

    let (dir, child) = start("tdx", seed).await;
    let rd = [0x21; 64];
    let provider = dir.path().join("tsm/com.intel.dcap");
    fs_err::write(provider.join("inblob"), rd).unwrap();
    let quote = fs_err::read(provider.join("outblob")).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    dcap_qvl::verify::QuoteVerifier::new(host.tdx.root_ca_der())
        .verify(&quote, &host.tdx.sample_collateral().unwrap(), now)
        .unwrap();
    drop(child);

    let (_dir, child) = start("sev-snp", seed).await;
    let evidence: mock_attestation::sev_snp::SevSnpEvidence = client
        .post("http://127.0.0.1:8088/attest/sev-snp")
        .body(rd.to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    sev_snp_qvl::QuoteVerifier::new_with_root(
        sev_snp_qvl::AmdSnpProduct::Milan,
        host.sev_snp.root_ca_pem().into_bytes(),
    )
    .verify(&evidence.report, &evidence.cert_chain, &rd)
    .unwrap();
    drop(child);

    let (_dir, child) = start("tpm", seed).await;
    let qualifying = [0x22; 32];
    let quote: tpm_types::TpmQuote = client
        .post("http://127.0.0.1:8088/attest/tpm")
        .body(qualifying.to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    tpm_qvl::QuoteVerifier::new(host.tpm.root_ca_pem())
        .verify(&quote, &host.tpm.collateral())
        .unwrap();
    drop(child);

    let (_dir, child) = start("nsm", seed).await;
    let evidence = client
        .post("http://127.0.0.1:8088/attest/nsm")
        .body(rd.to_vec())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let verified = nsm_qvl::QuoteVerifier::new(host.nsm.root_ca_pem())
        .verify(&evidence, None, None)
        .unwrap();
    assert_eq!(verified.user_data.as_deref(), Some(rd.as_slice()));
    drop(child);
}
