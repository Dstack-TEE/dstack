// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{kms_client::KmsClient, AppKeyResponse, GetAppKeyRequest, SignCertRequest};
use dstack_types::{AppKeys, KeyProvider};
use ra_rpc::client::{CertInfo, RaClient, RaClientConfig};
use ra_tls::{
    attestation::{AppInfo, AttestationVerifier, VersionedAttestation},
    cert::{generate_self_signed_ra_cert, CaCert, CertPair, CertSigningRequestV2},
};

pub enum CertRequestClient {
    Local {
        ca: Box<CaCert>,
    },
    Kms {
        client: KmsClient<RaClient>,
        vm_config: String,
    },
}

/// The identity a locally issued certificate should carry, if any.
///
/// Reading the attestation unverified is sound only here: the guest agent signs
/// its own CSR with a CA key it already holds.
fn local_ca_app_info(attestation: &VersionedAttestation) -> Option<AppInfo> {
    attestation.clone().into_v1().decode_app_info(false).ok()
}

const KMS_RPC_CERT_USAGE: &str = "kms:rpc";

/// The KMS root also anchors every per-app CA, whose leaves may carry any
/// hostname an app asks for, so pinning the root alone accepts any app's
/// certificate. Only the KMS's own RPC certificate carries `kms:rpc`.
pub fn validate_kms_rpc_cert(cert: Option<CertInfo>) -> Result<()> {
    let Some(cert) = cert else {
        bail!("missing server cert");
    };
    let Some(usage) = cert.special_usage else {
        bail!("missing server cert usage");
    };
    if usage != KMS_RPC_CERT_USAGE {
        bail!("invalid server cert usage: {usage}");
    }
    Ok(())
}

/// Fetch keys directly over the attested connection, without a metadata/CA preflight.
/// Historical requests must pin the already trusted current KMS CA, since their
/// response CA belongs to the requested epoch rather than the TLS listener.
/// Without a supplied CA, the caller must still bind the returned root identity
/// through its provider pin or launch-measurement policy.
pub async fn request_app_keys(
    url: String,
    request: GetAppKeyRequest,
    client_cert: CertPair,
    attestation_verifier: Arc<AttestationVerifier>,
    trusted_ca: Option<String>,
) -> Result<AppKeyResponse> {
    if request.root_epoch.is_some() && trusted_ca.is_none() {
        bail!("historical key requests require the trusted KMS CA");
    }
    let server_cert = Arc::new(Mutex::new(None));
    let captured = server_cert.clone();
    let client = RaClientConfig::builder()
        .remote_uri(url)
        .tls_client_cert(client_cert.cert_pem)
        .tls_client_key(client_cert.key_pem)
        .tls_skip_ca_verification(trusted_ca.is_none())
        .tls_built_in_root_certs(false)
        .maybe_tls_ca_cert(trusted_ca.clone())
        .attestation_verifier(attestation_verifier)
        .cert_validator(Box::new(move |info| {
            let info = info.context("missing KMS server certificate")?;
            if info.attestation.is_none() {
                bail!("KMS server certificate has no verified attestation");
            }
            let cert_der = info.cert_der.clone();
            validate_kms_rpc_cert(Some(info))?;
            *captured
                .lock()
                .map_err(|_| anyhow::anyhow!("KMS certificate lock poisoned"))? = Some(cert_der);
            Ok(())
        }))
        .build()
        .into_client()?;
    let requested_epoch = request.root_epoch;
    let response = KmsClient::new(client).get_app_key(request).await?;
    if requested_epoch.is_some_and(|epoch| epoch != response.root_epoch) {
        bail!("KMS returned a different root epoch than requested");
    }
    let cert = server_cert
        .lock()
        .map_err(|_| anyhow::anyhow!("KMS certificate lock poisoned"))?;
    validate_kms_root(
        cert.as_deref().context("missing KMS server certificate")?,
        if requested_epoch.is_some() {
            trusted_ca
                .as_deref()
                .context("historical key requests require the trusted KMS CA")?
        } else {
            &response.ca_cert
        },
    )?;
    Ok(response)
}

fn validate_kms_root(server_cert: &[u8], root_ca: &str) -> Result<()> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(root_ca.as_bytes()).context("invalid KMS root CA")?;
    let root = pem.parse_x509().context("invalid KMS root CA")?;
    let (_, leaf) =
        x509_parser::parse_x509_certificate(server_cert).context("invalid KMS RPC certificate")?;
    if !root.is_ca() || !root.validity().is_valid() || !leaf.validity().is_valid() {
        bail!("invalid or expired KMS certificate");
    }
    if leaf.issuer() != root.subject() {
        bail!("KMS RPC certificate issuer does not match the root CA");
    }
    leaf.verify_signature(Some(root.public_key()))
        .context("KMS root CA did not sign the attested RPC certificate")
}

fn kms_client(
    url: String,
    ca_cert: String,
    client_cert_pem: String,
    client_key_pem: String,
    attestation_verifier: Arc<AttestationVerifier>,
) -> Result<KmsClient<RaClient>> {
    let ra_client = RaClientConfig::builder()
        .remote_uri(url)
        .tls_client_cert(client_cert_pem)
        .tls_client_key(client_key_pem)
        .tls_ca_cert(ca_cert)
        .tls_built_in_root_certs(false)
        .attestation_verifier(attestation_verifier)
        // Root pin plus `kms:rpc` already identify the KMS; re-verifying its
        // quote on every `SignCert` would only add a collateral fetch.
        .verify_server_attestation(false)
        .cert_validator(Box::new(validate_kms_rpc_cert))
        .build()
        .into_client()
        .context("Failed to create RA client")?;
    Ok(KmsClient::new(ra_client))
}

impl CertRequestClient {
    pub async fn sign_csr(
        &self,
        csr: &CertSigningRequestV2,
        signature: &[u8],
    ) -> Result<Vec<String>> {
        match self {
            CertRequestClient::Local { ca } => {
                let app_info = local_ca_app_info(&csr.attestation);
                let cert = ca
                    .sign_csr(csr, app_info.as_ref(), "app:custom")
                    .context("Failed to sign certificate")?;
                Ok(vec![cert.pem(), ca.pem_cert.clone()])
            }
            CertRequestClient::Kms { client, vm_config } => {
                let response = client
                    .sign_cert(SignCertRequest {
                        api_version: 2,
                        csr: csr.to_vec(),
                        signature: signature.to_vec(),
                        vm_config: vm_config.clone(),
                    })
                    .await?;
                Ok(response.certificate_chain)
            }
        }
    }

    pub async fn get_root_ca(&self) -> Result<String> {
        match self {
            CertRequestClient::Local { ca } => Ok(ca.pem_cert.clone()),
            CertRequestClient::Kms { client, .. } => Ok(client.get_meta().await?.ca_cert),
        }
    }

    pub async fn create(
        keys: &AppKeys,
        attestation_verifier: Arc<AttestationVerifier>,
        vm_config: String,
    ) -> Result<CertRequestClient> {
        match &keys.key_provider {
            KeyProvider::None { key }
            | KeyProvider::Local { key, .. }
            | KeyProvider::Tpm { key, .. } => {
                let ca = CaCert::new(keys.ca_cert.clone(), key.clone())
                    .context("Failed to create CA")?;
                Ok(CertRequestClient::Local { ca: Box::new(ca) })
            }
            KeyProvider::Kms { url, .. } => {
                // Self-issued: the KMS authenticates the quote inside this certificate,
                // not whoever signed it.
                let client_cert =
                    generate_self_signed_ra_cert(None).context("Failed to generate RA cert")?;
                let client = kms_client(
                    url.clone(),
                    keys.ca_cert.clone(),
                    client_cert.cert_pem,
                    client_cert.key_pem,
                    attestation_verifier,
                )?;
                Ok(CertRequestClient::Kms { client, vm_config })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_tls::{
        attestation::{Attestation, AttestationQuote, StackEvidence, TdxQuote},
        cert::{CertConfigV2, CertRequest, CertSigningRequestV2},
        kdf,
        rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256},
        traits::CertExt,
    };

    /// The guest agent simulator's attestation, the same bytes every gateway
    /// suite runs against. Used rather than a hand-built one because the value
    /// under test is what `decode_app_info` reads out of a real event log --
    /// a synthetic attestation would prove the plumbing and not the decode.
    const SIMULATOR_ATTESTATION: &[u8] = include_bytes!("../../../sdk/simulator/attestation.bin");

    /// The app id `SIMULATOR_ATTESTATION` decodes to. Written out rather than
    /// recomputed, so a change in either the fixture or the decode shows up
    /// here as a failure instead of being silently agreed with.
    const SIMULATOR_APP_ID: &str = "5bb4ff9a3837357f19dc176407a5709c62eb6c56";

    fn simulator_attestation() -> VersionedAttestation {
        VersionedAttestation::from_bytes(SIMULATOR_ATTESTATION).expect("decode fixture")
    }

    /// The simulator's attestation with the app-id event's payload emptied.
    ///
    /// This is the case the empty app id filter in `sign_csr` exists for and the
    /// only one that reaches it: `find_event_payload` returns an empty vec for a
    /// missing or empty payload, so `decode_app_info` SUCCEEDS and hands back an
    /// AppInfo whose app_id is empty. The undecodable attestation below does not
    /// reach the filter at all -- it fails earlier, at `.ok()` -- so it cannot
    /// stand in for this. Only the digest is measured, so clearing the payload
    /// leaves the RTMR replay intact.
    fn attestation_with_empty_app_id() -> VersionedAttestation {
        let mut attestation = simulator_attestation().into_v1();
        let StackEvidence::Dstack {
            ref mut runtime_events,
            ..
        } = attestation.stack
        else {
            panic!("the simulator fixture is expected to carry dstack stack evidence");
        };
        let mut found = false;
        for event in runtime_events.iter_mut() {
            if event.event == "app-id" {
                event.payload = Vec::new();
                found = true;
            }
        }
        assert!(
            found,
            "fixture must carry an app-id event for this to mean anything"
        );
        VersionedAttestation::V1 { attestation }
    }

    /// An attestation carrying nothing decodable: the case where no app id can
    /// be read at all.
    fn undecodable_attestation() -> VersionedAttestation {
        Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote: vec![],
                event_log: vec![],
            }),
            runtime_events: vec![],
            report_data: [0u8; 64],
            config: "".into(),
            report: (),
        }
        .into_versioned()
    }

    fn csr_with(attestation: VersionedAttestation, pubkey: Vec<u8>) -> CertSigningRequestV2 {
        CertSigningRequestV2 {
            confirm: "please sign cert:".to_string(),
            pubkey,
            config: CertConfigV2 {
                org_name: None,
                subject: "local-ca-test".to_string(),
                subject_alt_names: vec![],
                usage_server_auth: true,
                usage_client_auth: true,
                ext_quote: false,
                // Deliberately off. `sign_csr` derives app *info* separately
                // when this is set, and hard fails when it cannot -- which
                // would mask the app *id* path this is about. The gateway does
                // set it, which is why the break showed on the client side
                // only.
                ext_app_info: false,
                not_before: None,
                not_after: None,
            },
            attestation,
        }
    }

    fn local_client() -> CertRequestClient {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec![]).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("ca cert");
        let ca = CaCert::new(cert.pem(), key.serialize_pem()).expect("ca");
        CertRequestClient::Local { ca: Box::new(ca) }
    }

    /// Sign through the real `CertRequestClient::Local` branch and read the
    /// app-id extension back off the leaf, the way a peer does.
    async fn issued_app_id(attestation: VersionedAttestation) -> Option<Vec<u8>> {
        let leaf_key = KeyPair::generate().expect("leaf key");
        let csr = csr_with(attestation, leaf_key.public_key_der());
        let chain = local_client()
            .sign_csr(&csr, &[])
            .await
            .expect("local signing");
        let (_, leaf) = x509_parser::pem::parse_x509_pem(chain[0].as_bytes()).expect("leaf pem");
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf.contents).expect("leaf der");
        leaf.get_app_id().expect("read app id")
    }

    /// The contract dstack-gateway's cluster mTLS rests on.
    ///
    /// `AppIdValidator` (the sync client) and `ensure_from_gateway` (the RPC
    /// handler) read this extension with no fallback, so a locally issued
    /// certificate without it is rejected by every peer. Reverting the stamp to
    /// the `None` it used to pass turns this red.
    #[tokio::test]
    async fn a_locally_issued_certificate_carries_the_attested_app_id() {
        let app_id = issued_app_id(simulator_attestation()).await;
        assert_eq!(
            app_id.as_deref().map(hex::encode).as_deref(),
            Some(SIMULATOR_APP_ID),
            "a peer that pins app_id must be able to read it off a local CA's certificate"
        );
    }

    /// And what must NOT happen: an attestation yielding nothing leaves the
    /// extension absent rather than stamping an empty value.
    ///
    /// An empty app id in the extension is not "unknown", it is a value, and
    /// both consumers compare by equality -- so every app without an app-id
    /// event would have matched every other one. Dropping the empty app id filter
    /// in `CaCert::sign_csr` turns this red.
    #[tokio::test]
    async fn an_attestation_with_no_app_id_leaves_the_extension_absent() {
        assert_eq!(
            issued_app_id(attestation_with_empty_app_id()).await,
            None,
            "an empty app id must be absent, not stamped"
        );
        assert_eq!(issued_app_id(undecodable_attestation()).await, None);
    }

    fn app_info_for(app_id: &[u8]) -> AppInfo {
        AppInfo {
            app_id: app_id.to_vec(),
            instance_id: Vec::new(),
            device_id: Vec::new(),
            mr_system: [0u8; 32],
            mr_aggregated: [0u8; 32],
            key_provider_info: Vec::new(),
            os_image_hash: Vec::new(),
            compose_hash: Vec::new(),
            init_script_hashes: None,
        }
    }

    fn p256_key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key")
    }

    /// The KMS root CA, as `onboard_service::Keys::from_keys` builds it.
    fn kms_root() -> CaCert {
        let key = p256_key();
        let cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack KMS CA")
            .ca_level(1)
            .key(&key)
            .build()
            .self_signed()
            .expect("root cert");
        CaCert::from_parts(key, cert)
    }

    /// The KMS's own RPC certificate chain and key.
    fn kms_rpc_cert(root: &CaCert, domain: &str) -> (String, String) {
        let key = p256_key();
        let cert = root
            .sign(
                CertRequest::builder()
                    .subject(domain)
                    .alt_names(&[domain.to_string()])
                    .special_usage("kms:rpc")
                    .usage_server_auth(true)
                    .key(&key)
                    .build(),
            )
            .expect("rpc cert");
        (
            format!("{}\n{}", cert.pem(), root.pem_cert),
            key.serialize_pem(),
        )
    }

    /// What `SignCert` returns to an app asking for `domain`: a leaf under the
    /// per-app CA `derive_app_ca` builds.
    fn app_cert(root: &CaCert, app_id: &[u8], domain: &str) -> (String, String) {
        let app_key = kdf::derive_p256_key_pair(&root.key, &[app_id, b"app-ca"]).expect("key");
        let app_ca = root
            .sign(
                CertRequest::builder()
                    .key(&app_key)
                    .org_name("Dstack")
                    .subject("Dstack App CA")
                    .ca_level(0)
                    .app_id(app_id)
                    .special_usage("app:ca")
                    .build(),
            )
            .expect("app ca");
        let app_ca = CaCert::from_parts(app_key, app_ca);
        let key = p256_key();
        let mut csr = csr_with(undecodable_attestation(), key.public_key_der());
        csr.config.subject_alt_names = vec![domain.to_string()];
        let leaf = app_ca
            .sign_csr(&csr, Some(&app_info_for(app_id)), "app:custom")
            .expect("sign csr");
        (
            format!("{}\n{}\n{}", leaf.pem(), app_ca.pem_cert, root.pem_cert),
            key.serialize_pem(),
        )
    }

    #[rocket::post("/GetAppKey", data = "<_request>")]
    fn direct_app_keys(
        _request: String,
        state: &rocket::State<(Arc<Mutex<String>>, std::sync::atomic::AtomicUsize)>,
    ) -> rocket::response::content::RawJson<String> {
        state.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        rocket::response::content::RawJson(state.0.lock().unwrap().clone())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_key_fetch_verifies_the_response_connection_without_preflight() {
        use ra_tls::attestation::{
            AttestationVerifierConfig, DstackNitroQuote, QuoteContentType, RootCaPaths,
        };
        let dir = tempfile::tempdir().unwrap();
        let attester = mock_attestation::nsm::NsmGenerator::new().unwrap();
        let attestation_root = dir.path().join("attestation-root.pem");
        std::fs::write(&attestation_root, attester.root_ca_pem()).unwrap();
        let verifier = Arc::new(
            AttestationVerifier::load(&AttestationVerifierConfig {
                insecure_allow_external_trust_anchors: true,
                root_ca: RootCaPaths {
                    aws_nitro_enclave: Some(attestation_root),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let root = kms_root();
        let rpc_key = p256_key();
        let report_data = QuoteContentType::RaTlsCert.to_report_data(&rpc_key.public_key_der());
        let pcrs = [0, 1, 2, 4]
            .into_iter()
            .map(|i| (i, vec![i as u8; 48]))
            .collect();
        let evidence = attester.attest_with_pcrs(&report_data, pcrs).unwrap();
        let attestation = Attestation {
            quote: AttestationQuote::DstackNitroEnclave(DstackNitroQuote {
                nsm_quote: evidence,
            }),
            runtime_events: Vec::new(),
            report_data,
            config: String::new(),
            report: (),
        }
        .into_versioned();
        let rpc_cert = root
            .sign(
                CertRequest::builder()
                    .subject("localhost")
                    .alt_names(&["127.0.0.1".into()])
                    .key(&rpc_key)
                    .special_usage("kms:rpc")
                    .usage_server_auth(true)
                    .attestation(&attestation)
                    .build(),
            )
            .unwrap();
        let cert_path = dir.path().join("rpc.crt");
        let key_path = dir.path().join("rpc.key");
        std::fs::write(&cert_path, rpc_cert.pem()).unwrap();
        std::fs::write(&key_path, rpc_key.serialize_pem()).unwrap();
        let response = AppKeyResponse {
            ca_cert: root.pem_cert.clone(),
            root_epoch: 1,
            ..Default::default()
        };
        let figment = rocket::Config::figment()
            .merge(("port", 0))
            .merge(("address", "127.0.0.1"))
            .merge(("log_level", "off"))
            .merge(("shutdown.ctrlc", false))
            .merge(("tls.certs", cert_path))
            .merge(("tls.key", key_path));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = Mutex::new(Some(tx));
        let response_body = Arc::new(Mutex::new(serde_json::to_string(&response).unwrap()));
        let server = rocket::custom(figment)
            .manage((
                response_body.clone(),
                std::sync::atomic::AtomicUsize::new(0),
            ))
            .mount("/", rocket::routes![direct_app_keys])
            .attach(rocket::fairing::AdHoc::on_liftoff("port", move |rocket| {
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send(rocket.endpoints().find_map(|e| e.port()).unwrap());
                }
                Box::pin(async {})
            }))
            .ignite()
            .await
            .unwrap();
        let shutdown = server.shutdown();
        let task = tokio::spawn(server.launch());
        let url = format!("https://127.0.0.1:{}", rx.await.unwrap());
        let client_cert = || {
            let key = p256_key();
            let cert = CertRequest::builder()
                .subject("guest")
                .key(&key)
                .usage_client_auth(true)
                .build()
                .self_signed()
                .unwrap();
            CertPair {
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
            }
        };
        let request = || GetAppKeyRequest {
            api_version: 1,
            vm_config: String::new(),
            root_epoch: None,
        };
        let result = request_app_keys(
            url.clone(),
            request(),
            client_cert(),
            verifier.clone(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.ca_cert, response.ca_cert);
        assert_eq!(result.root_epoch, 1);

        let wrong_root = AppKeyResponse {
            ca_cert: kms_root().pem_cert,
            ..response.clone()
        };
        *response_body.lock().unwrap() = serde_json::to_string(&wrong_root).unwrap();
        assert!(request_app_keys(
            url.clone(),
            request(),
            client_cert(),
            verifier.clone(),
            None
        )
        .await
        .is_err());
        *response_body.lock().unwrap() = serde_json::to_string(&response).unwrap();

        let mut historical_request = request();
        historical_request.root_epoch = Some(1);
        assert!(request_app_keys(
            url.clone(),
            historical_request,
            client_cert(),
            verifier.clone(),
            Some(root.pem_cert.clone())
        )
        .await
        .is_ok());

        let production = Arc::new(AttestationVerifier::new_prod(None).unwrap());
        assert!(
            request_app_keys(url.clone(), request(), client_cert(), production, None)
                .await
                .is_err()
        );
        let mut historical = request();
        historical.root_epoch = Some(0);
        let err = request_app_keys(url, historical, client_cert(), verifier, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("require the trusted KMS CA"));
        shutdown.notify();
        let server = task.await.unwrap().unwrap();
        assert_eq!(
            server
                .state::<(Arc<Mutex<String>>, std::sync::atomic::AtomicUsize)>()
                .unwrap()
                .1
                .load(std::sync::atomic::Ordering::SeqCst),
            4
        );
    }

    #[test]
    fn the_returned_root_must_sign_the_actual_rpc_certificate() {
        let root = kms_root();
        let (leaf, _) = kms_rpc_cert(&root, "kms.example");
        let (_, leaf) = x509_parser::pem::parse_x509_pem(leaf.as_bytes()).unwrap();
        validate_kms_root(&leaf.contents, &root.pem_cert).unwrap();
        let unrelated = kms_root();
        assert!(validate_kms_root(&leaf.contents, &unrelated.pem_cert).is_err());
        assert!(validate_kms_root(&leaf.contents, "not a certificate").is_err());
        assert!(validate_kms_root(b"not a certificate", &root.pem_cert).is_err());

        let (app_leaf, _) = app_cert(&root, &[0xa1; 20], "kms.example");
        let (_, app_leaf) = x509_parser::pem::parse_x509_pem(app_leaf.as_bytes()).unwrap();
        assert!(validate_kms_root(&app_leaf.contents, &root.pem_cert).is_err());
    }

    #[rocket::post("/GetMeta")]
    fn get_meta() -> &'static str {
        r#"{"ca_cert":"served ca cert"}"#
    }

    /// Serve `GetMeta` over TLS with `(cert, key)` and query it through the
    /// guest's KMS client, pinning `root`.
    async fn get_meta_from(root: &CaCert, (cert, key): (String, String)) -> Result<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, cert).expect("write cert");
        std::fs::write(&key_path, key).expect("write key");
        let figment = rocket::Config::figment()
            .merge(("port", 0))
            .merge(("address", "127.0.0.1"))
            .merge(("log_level", "off"))
            .merge(("shutdown.ctrlc", false))
            .merge(("tls.certs", cert_path))
            .merge(("tls.key", key_path));
        let (port_tx, port_rx) = tokio::sync::oneshot::channel();
        let port_tx = std::sync::Mutex::new(Some(port_tx));
        let rocket = rocket::custom(figment)
            .mount("/", rocket::routes![get_meta])
            .attach(rocket::fairing::AdHoc::on_liftoff("port", move |rocket| {
                let port = rocket.endpoints().find_map(|e| e.port());
                if let Some(tx) = port_tx.lock().unwrap().take() {
                    let _ = tx.send(port);
                }
                Box::pin(async {})
            }))
            .ignite()
            .await
            .expect("ignite");
        let shutdown = rocket.shutdown();
        tokio::spawn(rocket.launch());
        let port = port_rx.await.ok().flatten().expect("bound port");

        let client_key = p256_key();
        let client_cert = CertRequest::builder()
            .subject("guest")
            .key(&client_key)
            .usage_client_auth(true)
            .build()
            .self_signed()
            .expect("client cert");
        let client = kms_client(
            format!("https://127.0.0.1:{port}"),
            root.pem_cert.clone(),
            client_cert.pem(),
            client_key.serialize_pem(),
            Arc::new(AttestationVerifier::new_prod(None).expect("verifier")),
        )?;
        let result = client.get_meta().await.map(|meta| meta.ca_cert);
        shutdown.notify();
        result
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_app_certificate_is_not_accepted_as_the_kms() {
        let root = kms_root();
        let err = get_meta_from(&root, app_cert(&root, &[0xa1; 20], "127.0.0.1"))
            .await
            .expect_err("an app's certificate must not authenticate the KMS");
        assert!(
            format!("{err:#}").contains("invalid server cert usage: app:custom"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_kms_rpc_certificate_is_accepted() {
        let root = kms_root();
        let ca_cert = get_meta_from(&root, kms_rpc_cert(&root, "127.0.0.1"))
            .await
            .expect("the KMS's own certificate must be accepted");
        assert_eq!(ca_cert, "served ca cert");
    }
}
