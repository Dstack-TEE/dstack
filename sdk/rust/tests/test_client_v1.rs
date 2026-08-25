// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `DstackClientV1` against the guest-agent simulator.

use dstack_sdk::dstack_client::DstackClientV0;
use dstack_sdk::dstack_client_v1::{DstackClientV1, IssueCertConfig};

fn client() -> DstackClientV1 {
    DstackClientV1::new(None)
}

#[tokio::test]
async fn version_answers_on_the_v1_surface() {
    let response = client().version().await.unwrap();
    assert!(!response.version.is_empty());
}

#[tokio::test]
async fn get_key_returns_a_key_public_key_and_two_link_chain() {
    for algorithm in ["secp256k1", "ed25519"] {
        let response = client()
            .get_key("storage-encryption", algorithm)
            .await
            .unwrap();

        // 32 raw bytes for both algorithms, hex-encoded on the wire.
        assert_eq!(response.decode_key().unwrap().len(), 32);
        // The chain is the key's chain and nothing else: the claim link and the
        // KMS link. v0's `Sign` prepended the payload signature to its list, so
        // the real chain there started at index 1.
        assert_eq!(response.signature_chain.len(), 2);
        assert_eq!(response.decode_signature_chain().unwrap()[0].len(), 65);
    }
}

#[tokio::test]
async fn get_key_public_key_lengths_are_the_specified_ones() {
    let secp = client()
        .get_key("storage-encryption", "secp256k1")
        .await
        .unwrap();
    assert_eq!(
        secp.decode_public_key().unwrap().len(),
        33,
        "SEC1 compressed"
    );

    let ed = client()
        .get_key("storage-encryption", "ed25519")
        .await
        .unwrap();
    assert_eq!(ed.decode_public_key().unwrap().len(), 32);
}

/// v1 has no default algorithm and no `k256` alias, so a caller cannot ask for
/// nothing in particular and get a key.
#[tokio::test]
async fn get_key_rejects_an_empty_or_unknown_algorithm() {
    assert!(client().get_key("storage-encryption", "").await.is_err());
    for algorithm in ["k256", "rsa", "secp256k1_prehashed"] {
        assert!(
            client()
                .get_key("storage-encryption", algorithm)
                .await
                .is_err(),
            "v1 accepted algorithm {algorithm:?}"
        );
    }
}

/// Derivation is flat: a domain that looks like a path is just a domain.
#[tokio::test]
async fn different_domains_yield_different_keys() {
    let a = client().get_key("a", "secp256k1").await.unwrap();
    let b = client().get_key("a/b", "secp256k1").await.unwrap();
    assert_ne!(a.key, b.key);
}

/// The two curves no longer share one secret, which is the whole reason the v1
/// KDF exists.
#[tokio::test]
async fn the_two_algorithms_never_share_key_material() {
    let secp = client()
        .get_key("storage-encryption", "secp256k1")
        .await
        .unwrap();
    let ed = client()
        .get_key("storage-encryption", "ed25519")
        .await
        .unwrap();
    assert_ne!(secp.key, ed.key);
}

/// **v1 keys are not v0 keys.** This is the migration contract, asserted rather
/// than merely documented: an app that reuses its v0 path as a v1 domain gets
/// different key material.
#[tokio::test]
async fn v1_keys_differ_from_v0_keys_for_the_same_name() {
    let v1 = client().get_key("test", "secp256k1").await.unwrap();
    let v0 = DstackClientV0::new(None)
        .get_key(Some("test".to_string()), Some("signing".to_string()))
        .await
        .unwrap();
    assert_ne!(v1.key, v0.key);
}

#[tokio::test]
async fn attest_returns_an_attestation() {
    let response = client().attest(b"test".to_vec(), false).await.unwrap();
    assert!(!response.decode_attestation().unwrap().is_empty());
    assert!(response.boottime_gpu_evidence.is_empty());
}

/// Boot-time GPU evidence comes back in the same bundle shape `attest_gpu`
/// uses, so a consumer needs one parser rather than two. Absence is the empty
/// list, not a sentinel.
#[tokio::test]
async fn attest_can_ask_for_the_boot_time_gpu_evidence() {
    // The simulator has no GPU output, so the list comes back empty. What is
    // under test is that the flag is accepted on this surface at all -- it is
    // reserved on v0 -- and that the field decodes as a bundle list.
    let response = client().attest(b"test".to_vec(), true).await.unwrap();
    assert!(!response.decode_attestation().unwrap().is_empty());

    let bundles: &Vec<dstack_sdk::dstack_client_v1::GpuEvidenceBundle> =
        &response.boottime_gpu_evidence;
    assert!(bundles.is_empty(), "the simulator has no GPU output");
    for bundle in bundles {
        assert_eq!(bundle.vendor, "nvidia");
        assert_eq!(bundle.format, dstack_sdk::dstack_client_v1::FORMAT_BOOTTIME);
        assert!(bundle.decode_evidence().is_ok());
    }
}

/// The two sources must stay distinguishable: a verifier for the live
/// measurement does not appraise the boot record.
#[test]
fn the_two_gpu_evidence_formats_are_distinct() {
    use dstack_sdk::dstack_client_v1::{FORMAT_BOOTTIME, FORMAT_ON_DEMAND};
    assert_eq!(FORMAT_BOOTTIME, "nvidia-nvattest-boottime-json-v1");
    assert_eq!(FORMAT_ON_DEMAND, "nvidia-nvattest-collect-evidence-json-v1");
    assert_ne!(FORMAT_BOOTTIME, FORMAT_ON_DEMAND);
}

#[tokio::test]
async fn attest_rejects_report_data_outside_1_to_64_bytes() {
    assert!(client().attest(vec![], false).await.is_err());
    assert!(client().attest(vec![0u8; 65], false).await.is_err());
}

#[tokio::test]
async fn attest_gpu_validates_the_nonce_length() {
    for len in [0usize, 16, 31, 33, 64] {
        assert!(
            client().attest_gpu(vec![0u8; len]).await.is_err(),
            "a {len}-byte nonce must be rejected"
        );
    }
    // A correctly sized nonce gets past the client and fails at the simulator,
    // which has no GPU to attest. 501, not 4xx: the request was well-formed and
    // no retry of it will ever succeed on an image that ships no nvattest.
    let err = client()
        .attest_gpu(vec![0xab; 32])
        .await
        .expect_err("the simulator has no GPU to attest");
    let err = format!("{err:#}");
    assert!(err.contains("HTTP 501"), "{err}");
    assert!(err.contains("GPU attestation is not available"), "{err}");
}

#[tokio::test]
async fn info_reports_identity_and_configuration() {
    let info = client().info().await.unwrap();

    assert!(!info.decode_app_id().unwrap().is_empty());
    assert!(!info.decode_instance_id().unwrap().is_empty());
    assert_eq!(info.decode_compose_hash().unwrap().len(), 32);
    // The app-compose document is served directly rather than nested inside a
    // `tcb_info` JSON string, which is what v0 did.
    assert!(info.app_compose.starts_with('{'));
}

#[tokio::test]
async fn issue_cert_returns_a_key_and_a_chain() {
    let response = client()
        .issue_cert(
            IssueCertConfig::builder()
                .subject("example.com")
                .usage_server_auth(true)
                .build(),
        )
        .await
        .unwrap();

    assert!(response.key.contains("BEGIN"), "expected a PEM key");
    assert!(!response.certificate_chain.is_empty());
}

/// Committed v1 key vectors, as the agent produces them from the simulator's
/// fixed app root key (`sdk/simulator/appkeys.json`).
///
/// The SDK derives nothing itself -- it is a transport mirror -- so what this
/// pins is the pair of things it can actually get wrong or notice: that the
/// client decodes the v1 wire format correctly, and that the agent's KDF has
/// not moved under it. The construction these bytes come from is specified in
/// `docs/guest-api-v1.md` and implemented once in `ra_tls::api_v1`, which
/// is the source of truth; the vectors there pin the primitive directly.
///
/// A diff here is a change to deployed key material. Fix the derivation, do not
/// update the vector.
#[tokio::test]
async fn derives_the_committed_key_vectors() {
    let vectors = [
        (
            "storage-encryption",
            "secp256k1",
            "b9fa657a9b12a35468341fe9204cad53d393b35f05184546fbc5c329a526cf79",
            "0380a54b49c2ad61341d7ade1f41df5061783f8be45911bed81a8048bed2a60b36",
        ),
        (
            "storage-encryption",
            "ed25519",
            "4330ca9a8816f4e2be49b6b1c54a619940d70263429e9efe1fa5c3e269ef2786",
            "ec766df0797ac4be0e85af6cd48cf26c834527ec0156550cbd4e68c9934748b7",
        ),
        (
            "",
            "secp256k1",
            "1405a12f0670bad157ae87f2da4f29e531bde7d05ff17a070e5191120557613a",
            "02b3634254d8ec857b5149237c7232c9c9355a3186b20d3e873029f7a161a50284",
        ),
    ];
    for (domain, algorithm, expected_key, expected_public_key) in vectors {
        let response = client().get_key(domain, algorithm).await.unwrap();
        assert_eq!(
            response.key, expected_key,
            "v1 key vector changed for ({domain:?}, {algorithm})"
        );
        assert_eq!(
            response.public_key, expected_public_key,
            "v1 public key vector changed for ({domain:?}, {algorithm})"
        );
    }
}

/// The private key `issue_cert` returns is not derived from the app identity:
/// two identical requests produce two unrelated keys.
#[tokio::test]
async fn issue_cert_generates_a_fresh_key_per_call() {
    let config = || IssueCertConfig::builder().subject("example.com").build();
    let first = client().issue_cert(config()).await.unwrap();
    let second = client().issue_cert(config()).await.unwrap();
    assert_ne!(first.key, second.key);
}

/// An agent that predates v1 has no `/v1` mount, so it answers with a plain
/// HTML 404 rather than a prpc error -- and that page is the only clue the
/// caller gets. The simulator's tappd socket serves no `/v1` either, so it
/// stands in for one here.
#[tokio::test]
async fn a_missing_v1_mount_is_reported_with_its_status() {
    let endpoint = std::env::var("TAPPD_SIMULATOR_ENDPOINT")
        .expect("TAPPD_SIMULATOR_ENDPOINT must point at the simulator");
    let err = DstackClientV1::new(Some(&endpoint))
        .version()
        .await
        .unwrap_err();

    let message = format!("{err:#}");
    assert!(
        message.starts_with("HTTP 404: <!DOCTYPE html>"),
        "expected the status and the server's page, got: {message}"
    );
}
