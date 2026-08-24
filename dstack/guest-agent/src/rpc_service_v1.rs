// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The `dstack.guest.v1` API surface.
//!
//! Two handlers, one per trust surface, mirroring the two unversioned ones:
//!
//! - [`V1RpcHandler`] on the internal socket at `/v1`, which hands out key
//!   material because only the application itself can reach that socket;
//! - [`ExternalV1RpcHandler`] on the external listener at `/prpc/v1`, which
//!   never does, because anyone who can route to the CVM can reach it.
//!
//! The unversioned handlers in [`crate::rpc_service`] keep serving `/` and
//! `/prpc` unchanged; a caller picks a surface by URL and nothing else.
//!
//! This handler shares every backend with the unversioned one -- the same
//! `AppState`, the same certificate client, the same platform attestation and
//! GPU attestor. What it does not share is key derivation and the
//! signature-chain claim, which are new in v1 and live in [`keys`].
//!
//! v1 serves only what needs the TEE: deriving from the app root key, and
//! attesting. It has no `Sign` and no `Verify`, because a caller that can
//! reach this socket can get the private key from `GetKey` and do both
//! itself.

use std::path::Path;

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::v1::{
    dstack_guest_v1_server::{DstackGuestV1Rpc, DstackGuestV1Server},
    worker_v1_server::{WorkerV1Rpc, WorkerV1Server},
    AttestAppKeyRequest, AttestGpuRequest, AttestGpuResponse, AttestRequest, AttestResponse,
    GetKeyRequest, GetKeyResponse, GpuEvidenceBundle, HealthRequest, HealthResponse, InfoRequest,
    InfoResponse, IssueCertRequest, IssueCertResponse, VersionRequest, VersionResponse,
};
use dstack_types::GPU_ATTESTATION_OUTPUT;
use fs_err as fs;
use ra_rpc::{CallContext, RpcCall};
use ra_tls::cert::CertConfigV2;
use tracing::warn;

use crate::rpc_service::{
    generate_cert_key, pad64, read_dmi_file, validate_cert_validity, AppState, ExternalRpcHandler,
};

pub(crate) mod keys;

use keys::{Algorithm, AppKey};

/// Read the GPU attestation output saved during boot. Returns an empty string
/// when no output is available (e.g. no GPU attached or attestation disabled).
fn read_gpu_attestation(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(attestation) => attestation,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!("failed to read GPU attestation output: {err:?}");
            }
            String::new()
        }
    }
}

/// GPU evidence to return alongside an attestation. Opt-in, so a caller that
/// does not care about GPUs neither pays the disk read nor carries the payload.
fn boottime_gpu_evidence(include: bool, path: &Path) -> String {
    if include {
        read_gpu_attestation(path)
    } else {
        String::new()
    }
}

/// Build the v1 `Info` response.
///
/// Built straight from the attestation's app info rather than from the
/// unversioned `AppInfo`, because v1 needs the verbatim app-compose document
/// that v0 only ever exposed nested inside the `tcb_info` JSON string.
///
/// `hide_documents` applies the app's `public_tcbinfo` choice: with it set, the
/// three document fields come back empty and everything identifying the app
/// stays visible. That is the same line the unversioned `Worker.Info` drew, and
/// it is drawn only on the external listener -- an app cannot need protecting
/// from itself.
fn info_response(state: &AppState, hide_documents: bool) -> Result<InfoResponse> {
    let attestation = state.info_attestation()?.into_v1();
    let app_info = attestation
        .decode_app_info(false)
        .context("Failed to decode app info")?;
    let document = |value: String| if hide_documents { String::new() } else { value };
    Ok(InfoResponse {
        app_id: app_info.app_id,
        app_name: state.config().app_compose.name.clone(),
        compose_hash: app_info.compose_hash,
        app_compose: document(state.config().app_compose.raw.clone()),
        instance_id: app_info.instance_id,
        device_id: app_info.device_id,
        os_image_hash: app_info.os_image_hash,
        mr_aggregated: app_info.mr_aggregated.to_vec(),
        vm_config: document(state.vm_config().to_string()),
        key_provider_info: document(
            String::from_utf8(app_info.key_provider_info).unwrap_or_default(),
        ),
        cloud_vendor: read_dmi_file("sys_vendor"),
        cloud_product: read_dmi_file("product_name"),
    })
}

pub struct V1RpcHandler {
    state: AppState,
}

impl V1RpcHandler {
    #[cfg(test)]
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Derive the key named by `(domain, algorithm)` together with its
    /// signature chain.
    fn derive(&self, domain: &str, algorithm: &str) -> Result<(AppKey, Vec<Vec<u8>>)> {
        let algorithm = Algorithm::parse(algorithm)?;
        let app_root_key = self.state.app_root_k256_key();
        let key = AppKey::derive(app_root_key, domain, algorithm)?;
        let chain = vec![
            key.claim_signature(app_root_key)?,
            self.state.kms_k256_signature(),
        ];
        Ok((key, chain))
    }
}

impl DstackGuestV1Rpc for V1RpcHandler {
    async fn issue_cert(self, request: IssueCertRequest) -> Result<IssueCertResponse> {
        validate_cert_validity(request.not_before, request.not_after)?;
        let key = generate_cert_key()?;
        let config = CertConfigV2 {
            org_name: None,
            subject: request.subject,
            subject_alt_names: request.alt_names,
            usage_server_auth: request.usage_server_auth,
            usage_client_auth: request.usage_client_auth,
            ext_quote: request.usage_ra_tls,
            ext_app_info: request.with_app_info,
            not_after: request.not_after,
            not_before: request.not_before,
        };
        let certificate_chain = self.state.issue_cert(&key, config).await?;
        Ok(IssueCertResponse {
            key: key.serialize_pem(),
            certificate_chain,
        })
    }

    async fn get_key(self, request: GetKeyRequest) -> Result<GetKeyResponse> {
        let (key, signature_chain) = self.derive(&request.domain, &request.algorithm)?;
        Ok(GetKeyResponse {
            key: key.secret(),
            public_key: key.public_key(),
            signature_chain,
        })
    }

    async fn attest(self, request: AttestRequest) -> Result<AttestResponse> {
        let report_data = pad64(&request.report_data).context("Report data is too long")?;
        Ok(AttestResponse {
            attestation: self.state.attest_cvm(report_data)?,
            boottime_gpu_evidence: boottime_gpu_evidence(
                request.include_boottime_gpu_evidence,
                Path::new(GPU_ATTESTATION_OUTPUT),
            ),
        })
    }

    async fn attest_gpu(self, request: AttestGpuRequest) -> Result<AttestGpuResponse> {
        let evidence = self
            .state
            .gpu_attestor()
            .attest(&request.nonce)
            .await
            .context("GPU attestation failed")?;
        Ok(AttestGpuResponse {
            bundles: vec![GpuEvidenceBundle {
                vendor: "nvidia".to_string(),
                format: "nvidia-nvattest-collect-evidence-json-v1".to_string(),
                evidence,
            }],
        })
    }

    /// Identity and configuration, never attestation.
    ///
    /// Ungated: the internal socket is reachable only by the application
    /// itself, so there is nobody to hide from. The external surface applies
    /// `public_tcbinfo`; see [`ExternalV1RpcHandler::info`].
    async fn info(self, _request: InfoRequest) -> Result<InfoResponse> {
        info_response(&self.state, false)
    }

    async fn version(self, _request: VersionRequest) -> Result<VersionResponse> {
        Ok(VersionResponse {
            version: crate::CARGO_PKG_VERSION.to_string(),
            rev: crate::GIT_REV.to_string(),
        })
    }
}

impl RpcCall<AppState> for V1RpcHandler {
    type PrpcService = DstackGuestV1Server<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(V1RpcHandler {
            state: context.state.clone(),
        })
    }
}

/// The v1 handler on the external listener.
///
/// Reachable by anyone who can route to the CVM, so it serves no key material
/// and lets no caller choose what gets signed.
pub struct ExternalV1RpcHandler {
    state: AppState,
}

impl ExternalV1RpcHandler {
    #[cfg(test)]
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl WorkerV1Rpc for ExternalV1RpcHandler {
    async fn info(self, _request: InfoRequest) -> Result<InfoResponse> {
        let hide = !self.state.config().app_compose.public_tcbinfo;
        info_response(&self.state, hide)
    }

    async fn version(self, _request: VersionRequest) -> Result<VersionResponse> {
        Ok(VersionResponse {
            version: crate::CARGO_PKG_VERSION.to_string(),
            rev: crate::GIT_REV.to_string(),
        })
    }

    async fn attest_app_key(self, request: AttestAppKeyRequest) -> Result<AttestResponse> {
        // Same report data the frozen `Worker.GetAttestationForAppKey` builds,
        // so both surfaces attest the same public key for a given algorithm.
        // What changes is the envelope: an attestation answers on every
        // platform, a `GetQuoteResponse` only on Intel TDX.
        let report_data = ExternalRpcHandler::new(self.state.clone())
            .app_key_report_data(&request.algorithm)
            .await?;
        Ok(AttestResponse {
            attestation: self.state.attest_cvm(report_data)?,
            // This method attests a key, not the machine. A caller that wants
            // the boot-time GPU evidence asks `Attest` for it.
            boottime_gpu_evidence: String::new(),
        })
    }

    async fn health(self, _request: HealthRequest) -> Result<HealthResponse> {
        // One lock and one clone. Everything that costs anything happens on the
        // agent's own timer in `health`, because this method is served on the
        // publicly reachable listener and is polled by every gateway node in
        // the cluster: any work done here is work an anonymous caller can ask
        // for at an arbitrary rate, multiplied by the operator's fleet size.
        let Some(monitor) = self.state.health() else {
            // The app did not opt in, so it registered as "do not poll me" and
            // no gateway asks. Anything that does ask gets the same answer the
            // gateway would have assumed.
            return Ok(HealthResponse {
                healthy: true,
                unhealthy: vec![],
                error: String::new(),
            });
        };
        // Deliberately infallible: see `HealthResponse.error`. A failure to see
        // the app has to come back as a verdict, because an RPC error is
        // indistinguishable from an agent that predates this method.
        let verdict = monitor.report();
        Ok(HealthResponse {
            healthy: verdict.healthy,
            unhealthy: verdict.unhealthy,
            error: verdict.error,
        })
    }
}

impl RpcCall<AppState> for ExternalV1RpcHandler {
    type PrpcService = WorkerV1Server<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(ExternalV1RpcHandler {
            state: context.state.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_service::get_info;
    use crate::rpc_service::tests::setup_test_state;
    use dstack_guest_agent_rpc::dstack_guest_server::DstackGuestRpc;
    use dstack_guest_agent_rpc::GetKeyArgs;
    use k256::ecdsa::Signature as K256Signature;
    use std::io::Write as _;

    async fn handler() -> (V1RpcHandler, AppState, tempfile::NamedTempFile) {
        let (state, guard) = setup_test_state().await;
        (V1RpcHandler::new(state.clone()), state, guard)
    }

    fn get_key_request(domain: &str, algorithm: &str) -> GetKeyRequest {
        GetKeyRequest {
            domain: domain.to_string(),
            algorithm: algorithm.to_string(),
        }
    }

    /// The fixture's app root key is what `keys::tests` committed its vectors
    /// against. If the two drift, the vectors stop describing what this
    /// handler serves and every assertion built on them goes quiet.
    #[tokio::test]
    async fn the_fixture_root_key_matches_the_committed_vectors() {
        let (_, state, _guard) = handler().await;
        assert_eq!(
            hex::encode(state.app_root_k256_key()),
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
        );
    }

    #[tokio::test]
    async fn get_key_returns_a_two_link_chain_for_both_algorithms() {
        for algorithm in ["secp256k1", "ed25519"] {
            let (_, state, _guard) = handler().await;
            let key = V1RpcHandler::new(state)
                .get_key(get_key_request("wallet", algorithm))
                .await
                .unwrap();

            assert_eq!(key.key.len(), 32);
            assert_eq!(key.signature_chain.len(), 2);
            // r || s || recovery id.
            assert_eq!(key.signature_chain[0].len(), 65);
        }
    }

    /// The chain's first link verifies under the app root key, over the claim
    /// a relying party rebuilds from `(domain, algorithm, public_key)`.
    #[tokio::test]
    async fn the_chain_claim_verifies_under_the_app_root_key() {
        use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
        use sha3::{Digest as _, Keccak256};

        let (_, state, _guard) = handler().await;
        let key = V1RpcHandler::new(state.clone())
            .get_key(get_key_request("wallet", "secp256k1"))
            .await
            .unwrap();

        let claim = keys::key_claim(keys::Algorithm::Secp256k1, "wallet", &key.public_key).unwrap();
        let link = &key.signature_chain[0];
        let recovered = VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(&claim),
            &K256Signature::from_slice(&link[..64]).unwrap(),
            RecoveryId::from_byte(link[64]).unwrap(),
        )
        .unwrap();

        let app_root = *SigningKey::from_slice(state.app_root_k256_key())
            .unwrap()
            .verifying_key();
        assert_eq!(recovered, app_root);
    }

    /// The public key in the response is the one the returned private key
    /// actually has. An app that signs locally with `key` must land on
    /// `public_key`, which is what the chain vouches for.
    #[tokio::test]
    async fn the_public_key_belongs_to_the_returned_private_key() {
        let (_, state, _guard) = handler().await;

        let secp = V1RpcHandler::new(state.clone())
            .get_key(get_key_request("wallet", "secp256k1"))
            .await
            .unwrap();
        let derived = k256::ecdsa::SigningKey::from_slice(&secp.key).unwrap();
        assert_eq!(
            derived.verifying_key().to_sec1_bytes().to_vec(),
            secp.public_key
        );

        let ed = V1RpcHandler::new(state)
            .get_key(get_key_request("wallet", "ed25519"))
            .await
            .unwrap();
        let seed: [u8; 32] = ed.key.as_slice().try_into().unwrap();
        let derived = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(derived.verifying_key().to_bytes().to_vec(), ed.public_key);
    }

    #[tokio::test]
    async fn rejects_an_empty_or_unknown_algorithm() {
        let (_, state, _guard) = handler().await;
        for algorithm in ["", "k256", "rsa", "secp256k1_prehashed"] {
            let result = V1RpcHandler::new(state.clone())
                .get_key(get_key_request("wallet", algorithm))
                .await;
            assert!(result.is_err(), "v1 accepted algorithm {algorithm:?}");
        }
    }

    /// v1 keys are new key material. An app that reuses its v0 path as a v1
    /// domain gets a different key, and that is the migration contract, not a
    /// bug to paper over.
    #[tokio::test]
    async fn v1_keys_differ_from_the_unversioned_keys_for_the_same_name() {
        let (_, state, _guard) = handler().await;
        let v1 = V1RpcHandler::new(state.clone())
            .get_key(get_key_request("wallet", "secp256k1"))
            .await
            .unwrap();
        let v0 = crate::rpc_service::InternalRpcHandler::new(state)
            .get_key(GetKeyArgs {
                path: "wallet".to_string(),
                purpose: "signing".to_string(),
                algorithm: "secp256k1".to_string(),
            })
            .await
            .unwrap();

        assert_ne!(v1.key, v0.key);
        // The second link is the KMS's, produced outside the agent, so both
        // surfaces pass through the same bytes.
        assert_eq!(v1.signature_chain[1], v0.signature_chain[1]);
        assert_ne!(v1.signature_chain[0], v0.signature_chain[0]);
    }

    /// The unversioned handler is untouched by any of this: same fixture, same
    /// path, the v0.5.x answer.
    #[tokio::test]
    async fn the_unversioned_surface_still_serves_its_own_key() {
        let (_, state, _guard) = handler().await;
        // v0 defaults an empty algorithm to secp256k1 and derives from the
        // path alone; v1 rejects the same request outright.
        let expected = ra_tls::kdf::derive_key(state.app_root_k256_key(), &[b"test"], 32).unwrap();
        let v0 = crate::rpc_service::InternalRpcHandler::new(state)
            .get_key(GetKeyArgs {
                path: "test".to_string(),
                purpose: "signing".to_string(),
                algorithm: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(v0.key, expected);
    }

    /// v1 `Info` reports identity and configuration, and nothing that only an
    /// attestation should be trusted for.
    #[tokio::test]
    async fn info_reports_identity_and_configuration() {
        let (_, state, _guard) = handler().await;
        let v1 = V1RpcHandler::new(state.clone())
            .info(InfoRequest {})
            .await
            .unwrap();
        let v0 = get_info(&state, false).await.unwrap();

        // The identity fields carry the same values the unversioned surface
        // reports; only the shape changed.
        assert_eq!(v1.app_id, v0.app_id);
        assert_eq!(v1.instance_id, v0.instance_id);
        assert_eq!(v1.device_id, v0.device_id);
        assert_eq!(v1.mr_aggregated, v0.mr_aggregated);
        assert_eq!(v1.os_image_hash, v0.os_image_hash);
        assert_eq!(v1.compose_hash, v0.compose_hash);
        assert_eq!(v1.app_name, v0.app_name);
        assert_eq!(v1.vm_config, v0.vm_config);
        assert_eq!(v1.key_provider_info, v0.key_provider_info);
        assert_eq!(v1.cloud_vendor, v0.cloud_vendor);
        assert_eq!(v1.cloud_product, v0.cloud_product);

        // The app-compose document is served directly rather than nested in a
        // JSON string, which is the one thing v0 could not do.
        assert_eq!(v1.app_compose, state.config().app_compose.raw);
    }

    /// GPU evidence rides on `Attest`, which is the only way to get it now.
    #[tokio::test]
    async fn attest_returns_boot_time_gpu_evidence_only_when_asked() {
        let mut output = tempfile::NamedTempFile::new().unwrap();
        let evidence = r#"{"result_code":0,"claims":[]}"#;
        output.write_all(evidence.as_bytes()).unwrap();
        output.flush().unwrap();

        assert_eq!(boottime_gpu_evidence(true, output.path()), evidence);
        assert_eq!(boottime_gpu_evidence(false, output.path()), "");
    }

    #[test]
    fn reads_gpu_attestation_output_verbatim() {
        let mut output = tempfile::NamedTempFile::new().unwrap();
        let attestation = r#"{"result_code":0,"claims":[]}"#;
        output.write_all(attestation.as_bytes()).unwrap();
        output.flush().unwrap();

        assert_eq!(read_gpu_attestation(output.path()), attestation);
    }

    #[test]
    fn missing_gpu_attestation_output_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_gpu_attestation(&dir.path().join("missing")), "");
    }

    /// `Attest` is v1's only CVM attestation entry point, and the versioned
    /// attestation it returns carries the report data the caller asked for.
    #[tokio::test]
    async fn attest_reports_the_padded_report_data() {
        use ra_tls::attestation::VersionedAttestation;

        let (_, state, _guard) = handler().await;
        let response = V1RpcHandler::new(state)
            .attest(AttestRequest {
                report_data: b"hello".to_vec(),
                include_boottime_gpu_evidence: false,
            })
            .await
            .unwrap();

        let report_data = VersionedAttestation::from_bytes(&response.attestation)
            .unwrap()
            .into_v1()
            .report_data()
            .unwrap();
        assert_eq!(&report_data[..5], b"hello");
        assert!(report_data[5..].iter().all(|b| *b == 0));
    }

    #[tokio::test]
    async fn rejects_report_data_longer_than_64_bytes() {
        let (_, state, _guard) = handler().await;
        let err = V1RpcHandler::new(state)
            .attest(AttestRequest {
                report_data: vec![0; 65],
                include_boottime_gpu_evidence: false,
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("too long"), "{err}");
    }

    #[tokio::test]
    async fn version_answers() {
        let (_, state, _guard) = handler().await;
        let response = V1RpcHandler::new(state)
            .version(VersionRequest {})
            .await
            .unwrap();
        assert!(!response.version.is_empty());
    }

    /// The external v1 surface attests the same app key the frozen
    /// `GetAttestationForAppKey` commits to, but wraps it in an attestation, so
    /// it answers on a platform with no TDX quote. That is the whole point of
    /// the replacement.
    #[tokio::test]
    async fn external_attest_app_key_answers_without_a_tdx_quote() {
        use ra_tls::attestation::{PlatformEvidence, VersionedAttestation};

        let (state, _guard) = crate::rpc_service::tests::setup_test_state_with_platform(Some(
            PlatformEvidence::SevSnp {
                report: vec![0u8; 1184],
                cert_chain: Vec::new(),
                mr_config: String::new(),
            },
        ))
        .await;

        let response = ExternalV1RpcHandler::new(state)
            .attest_app_key(AttestAppKeyRequest {
                algorithm: "ed25519".to_string(),
            })
            .await
            .expect("v1 must attest an app key on a non-TDX platform");

        let report_data = VersionedAttestation::from_bytes(&response.attestation)
            .unwrap()
            .into_v1()
            .report_data()
            .unwrap();
        assert_eq!(
            b"dip1::ed25519-pk:5Pbre1Amf1hrp2V2bbfKlIfxpQb2pJAmrgmhxgVoG9s\0\0\0\0",
            &report_data
        );
        // This method attests a key, not the machine.
        assert!(response.boottime_gpu_evidence.is_empty());
    }

    /// The external surface honours the app's `public_tcbinfo` choice; the
    /// internal one has nobody to hide from.
    #[tokio::test]
    async fn the_external_surface_hides_documents_unless_the_app_opted_in() {
        let (_, state, _guard) = handler().await;
        assert!(
            !state.config().app_compose.public_tcbinfo,
            "the fixture must default to private for this test to mean anything"
        );

        let external = ExternalV1RpcHandler::new(state.clone())
            .info(InfoRequest {})
            .await
            .unwrap();
        assert_eq!(external.app_compose, "");
        assert_eq!(external.vm_config, "");
        assert_eq!(external.key_provider_info, "");

        // Identity and the measurement hashes stay visible, which is the line
        // the unversioned `Worker.Info` drew too.
        let internal = V1RpcHandler::new(state).info(InfoRequest {}).await.unwrap();
        assert_eq!(external.app_id, internal.app_id);
        assert_eq!(external.instance_id, internal.instance_id);
        assert_eq!(external.compose_hash, internal.compose_hash);
        assert_eq!(external.os_image_hash, internal.os_image_hash);
        assert_eq!(external.mr_aggregated, internal.mr_aggregated);
    }

    /// An app that opted in gets the full response on the external surface.
    #[tokio::test]
    async fn the_external_surface_serves_documents_when_the_app_opted_in() {
        let (state, _guard) =
            crate::rpc_service::tests::setup_test_state_with_public_tcbinfo().await;
        let external = ExternalV1RpcHandler::new(state.clone())
            .info(InfoRequest {})
            .await
            .unwrap();
        assert_eq!(external.app_compose, state.config().app_compose.raw);
    }

    /// An app that never opted into health gating is never polled, and anything
    /// that asks anyway gets the answer the gateway would have assumed.
    #[tokio::test]
    async fn health_fails_open_for_an_app_that_did_not_opt_in() {
        let (_, state, _guard) = handler().await;
        let response = ExternalV1RpcHandler::new(state)
            .health(HealthRequest {})
            .await
            .unwrap();
        assert!(response.healthy);
        assert!(response.unhealthy.is_empty());
        assert!(response.error.is_empty());
    }

    /// Route-level check without a live socket: the two generated dispatchers
    /// own disjoint method tables, which is what makes mounting one at `/` and
    /// the other at `/v1` a version selector rather than a name collision.
    #[test]
    fn the_two_surfaces_expose_different_method_sets() {
        use dstack_guest_agent_rpc::dstack_guest_server::DstackGuestServer;

        let v0 = DstackGuestServer::<crate::rpc_service::InternalRpcHandler>::supported_methods();
        let v1 = DstackGuestV1Server::<V1RpcHandler>::supported_methods();

        assert_eq!(
            v1,
            &[
                "IssueCert",
                "GetKey",
                "Attest",
                "AttestGpu",
                "Info",
                "Version"
            ],
            "the v1 surface changed"
        );

        // The unversioned surface is closed at exactly v0.5.11.
        assert_eq!(
            v0,
            &[
                "GetTlsKey",
                "GetKey",
                "GetQuote",
                "Attest",
                "EmitEvent",
                "Info",
                "Sign",
                "Verify",
                "Version"
            ],
            "the unversioned surface is frozen at the v0.5.11 method set"
        );

        // Everything v1 deliberately does not serve. `Sign` and `Verify` are
        // pure computation over a key the caller can already fetch, `GetQuote`
        // is the TDX-only channel `Attest` subsumes, and RTMR3 is
        // system-owned. All four stay on the frozen surface.
        for dropped in ["Sign", "Verify", "GetQuote", "EmitEvent"] {
            assert!(!v1.contains(&dropped), "v1 must not serve {dropped}");
        }

        // v0 keeps the old name for what v1 calls `IssueCert`.
        assert!(!v1.contains(&"GetTlsKey"));

        // Never-released `next` additions that now live only in v1, or nowhere.
        assert!(!v0.contains(&"AttestGpu"));
        assert!(v1.contains(&"AttestGpu"));
        assert!(!v0.contains(&"GpuInfo") && !v1.contains(&"GpuInfo"));
    }

    /// The external pair, checked the same way.
    #[test]
    fn the_two_external_surfaces_expose_different_method_sets() {
        use dstack_guest_agent_rpc::v1::worker_v1_server::WorkerV1Server;
        use dstack_guest_agent_rpc::worker_server::WorkerServer;

        let v0 = WorkerServer::<ExternalRpcHandler>::supported_methods();
        let v1 = WorkerV1Server::<ExternalV1RpcHandler>::supported_methods();

        // Closed at v0.5.11: `AttestAppKey` and `Health` are post-0.5.11 and
        // never released, so they live only on v1.
        assert_eq!(
            v0,
            &["Info", "Version", "GetAttestationForAppKey"],
            "the unversioned external surface is frozen at the v0.5.11 method set"
        );
        assert_eq!(v1, &["Info", "Version", "AttestAppKey", "Health"]);
    }
}
