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
    let path = dir.path().join("tee-simulator.json");
    fs_err::write(
        &path,
        serde_json::json!({
            "vm_config": "{}",
            "mr_config": "{\"version\":3,\"app_id\":\"\",\"compose_hash\":\"\",\"key_provider\":\"none\"}",
            "platform": platform,
            "mock_attestation_seed": hex::encode(seed),
            "collateral_base_url": "http://127.0.0.1:18088"
        })
        .to_string(),
    )
    .unwrap();
    let mountpoint = dir.path().join("tsm");
    let mut args = vec![
        "--config".to_string(),
        path.display().to_string(),
        "--runtime-dir".to_string(),
        dir.path().display().to_string(),
        "--dmi-root".to_string(),
        dir.path().join("dmi").display().to_string(),
    ];
    if matches!(platform, "dstack-tdx" | "dstack-amd-sev-snp") {
        args.extend(["--mountpoint".into(), mountpoint.display().to_string()]);
    }
    let child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_dstack-tee-simulator"))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        let ready = match platform {
            "dstack-tdx" => mountpoint.join("com.intel.dcap/outblob").exists(),
            "dstack-amd-sev-snp" => mountpoint.join("provider").exists(),
            _ => false,
        };
        if ready {
            return (dir, child);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{platform} simulator process did not become ready")
}

#[tokio::test]
async fn separate_simulator_process_imports_config_seed_for_tsm_platforms() {
    let seed = [0x71; 32];
    let host = MockCollateralState::from_seed(seed, "http://127.0.0.1:18088").unwrap();

    let (dir, child) = start("dstack-tdx", seed).await;
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

    let (dir, child) = start("dstack-amd-sev-snp", seed).await;
    let provider = dir.path().join("tsm");
    let entry = provider.join(format!("dstack-{}", std::process::id()));
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .open(entry.join("inblob"))
        .unwrap()
        .write_all(&rd)
        .unwrap();
    let report = fs_err::read(entry.join("outblob")).unwrap();
    let cert_chain = fs_err::read(entry.join("certs")).unwrap();
    sev_snp_qvl::QuoteVerifier::new_with_root(
        sev_snp_qvl::AmdSnpProduct::Milan,
        host.sev_snp.root_ca_pem().into_bytes(),
    )
    .verify(&report, &[cert_chain], &rd)
    .unwrap();
    drop(child);
}
