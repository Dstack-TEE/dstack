// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use mock_attestation::server::MockCollateralState;

/// The simulator derives a development PKI before it mounts anything, so the
/// budget has to cover process spawn plus four key generations, not just the
/// mount. A debug build on a loaded CI runner is an order of magnitude slower
/// than a local release-ish one, so keep the headroom generous: the test still
/// returns as soon as the mountpoint appears, and a dead child is reported
/// immediately rather than waited out.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

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
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_dstack-tee-simulator"))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let ready = match platform {
            "dstack-tdx" => mountpoint.join("com.intel.dcap/outblob").exists(),
            "dstack-amd-sev-snp" => mountpoint.join("provider").exists(),
            _ => false,
        };
        if ready {
            return (dir, child);
        }
        // A simulator that already exited never becomes ready. Say which one
        // and with what status instead of reporting a timeout that hides it.
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("{platform} simulator exited before becoming ready: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "{platform} simulator did not become ready within {READY_TIMEOUT:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
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

    // The guest verifier's trust anchor comes from the simulator, never from
    // the host, so the published root must be the one that signed this quote.
    let published = dstack_attest::trust_anchors::load_anchors(&dir.path().join("attestation"))
        .unwrap()
        .expect("simulator should publish external trust anchors");
    let root = fs_err::read(published.tdx.unwrap()).unwrap();
    assert_eq!(String::from_utf8(root).unwrap(), host.tdx.root_ca_pem());
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
