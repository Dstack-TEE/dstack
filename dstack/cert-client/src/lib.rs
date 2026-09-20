// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{kms_client::KmsClient, SignCertRequest};
use dstack_types::{AppKeys, KeyProvider};
use ra_rpc::client::{CertInfo, RaClient, RaClientConfig};
use ra_tls::{
    attestation::{AttestationVerifier, VersionedAttestation},
    cert::{generate_ra_cert, CaCert, CertSigningRequestV2},
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

/// The app id a locally issued certificate should carry, if any.
///
/// KMS stamps the app_id it verified into the certificate it returns. The local
/// CA branch has the same value available -- the CSR carries the attestation it
/// was derived from -- but used to drop it, so every certificate issued through
/// a local CA came back without the extension. Consumers that read the
/// extension and have no fallback therefore rejected all of them:
/// `AppIdValidator` in dstack-gateway's cluster sync client and the gateway's
/// own `ensure_from_gateway` both do exactly that, which left clustering
/// working under a KMS key provider and broken under every other one. (The
/// gateway's inbound sync routes happen to fall back to the app-info extension,
/// which is why the failure showed up on one side of the connection only.)
///
/// Reading the attestation without verifying it is sound *here and only here*:
/// the sole caller is the guest agent signing a CSR it built itself, from its
/// own `certificate_attestation`, against a CA whose key it already holds. It
/// asserts nothing it could not assert anyway. A remote CSR must go through
/// KMS, which verifies the quote first and stamps `boot_info.app_id`.
///
/// Best effort on purpose: an app whose attestation carries no app-id event
/// decodes to an empty one, and stamping that would make every such peer match
/// every other. Absent stays absent, and the peer rejects it as before.
fn local_ca_app_id(attestation: &VersionedAttestation) -> Option<Vec<u8>> {
    attestation
        .clone()
        .into_v1()
        .decode_app_info(false)
        .ok()
        .map(|info| info.app_id)
        .filter(|app_id| !app_id.is_empty())
}

/// The usage the KMS stamps on its own RPC certificate.
///
/// Every other certificate it signs belongs to an app and carries `app:custom`.
const KMS_RPC_CERT_USAGE: &str = "kms:rpc";

/// Refuse a KMS connection whose server certificate is not the KMS's own.
///
/// The CA pinned for this connection is the KMS root, and the KMS signs a
/// per-app CA under that root for every app it issues a certificate to
/// (`derive_app_ca` in dstack-kms). Those per-app CAs carry no name constraint,
/// and `SignCert` copies the subject alternative names and the `serverAuth`
/// usage straight out of the CSR -- deliberately, because that is what
/// `GetTlsKey` exists to give an app. So a leaf minted for any app the KMS
/// authorized chains to the same root, for any hostname the app asked for:
/// pinning the root alone authenticates "some app this KMS authorized", not
/// "this KMS".
///
/// `PHALA_RATLS_CERT_USAGE` is what separates the two, and an app cannot pick
/// its value: the KMS writes `kms:rpc` on its own RPC certificate
/// (`onboard_service::Keys::from_keys`) and `app:custom` on every certificate it
/// signs for an app. dstack-util has always run this check against the same
/// endpoint before fetching app keys; this is that check, shared, for the
/// clients that call `SignCert` and `GetMeta`.
pub fn validate_kms_rpc_cert(cert: Option<CertInfo>) -> Result<()> {
    let Some(cert) = cert else {
        bail!("missing server cert");
    };
    let Some(usage) = cert.special_usage else {
        bail!("missing server cert usage");
    };
    if usage != KMS_RPC_CERT_USAGE {
        bail!("Invalid server cert usage: {usage}");
    }
    Ok(())
}

/// Build the KMS RPC client with the trust rules a guest applies to a KMS.
///
/// Split out of [`CertRequestClient::create`] so those rules can be driven
/// against a real TLS server by a test that has no TEE to mint the client
/// certificate from.
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
                let app_id = local_ca_app_id(&csr.attestation);
                let cert = ca
                    .sign_csr(csr, app_id.as_deref(), "app:custom")
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
            KeyProvider::Kms {
                url,
                tmp_ca_key,
                tmp_ca_cert,
                ..
            } => {
                let client_cert = generate_ra_cert(tmp_ca_cert.clone(), tmp_ca_key.clone())
                    .context("Failed to generate RA cert")?;
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
    /// This is the case the `.filter()` in `local_ca_app_id` exists for and the
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
                // only; see `local_ca_app_id`.
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
    /// event would have matched every other one. Dropping the `.filter()` in
    /// `local_ca_app_id` turns this red.
    #[tokio::test]
    async fn an_attestation_with_no_app_id_leaves_the_extension_absent() {
        assert_eq!(
            issued_app_id(attestation_with_empty_app_id()).await,
            None,
            "an empty app id must be absent, not stamped"
        );
        assert_eq!(issued_app_id(undecodable_attestation()).await, None);
    }

    /// The same rule at the unit it is decided in, so a failure says which of
    /// the two halves moved.
    #[test]
    fn local_ca_app_id_is_absent_rather_than_empty() {
        assert_eq!(local_ca_app_id(&attestation_with_empty_app_id()), None);
        assert_eq!(local_ca_app_id(&undecodable_attestation()), None);
        assert_eq!(
            local_ca_app_id(&simulator_attestation()).map(hex::encode),
            Some(SIMULATOR_APP_ID.to_string())
        );
    }

    /// The KMS PKI, built with the production primitives.
    ///
    /// A guest pins exactly one thing -- the root CA that came back with its app
    /// keys -- so a root, a `kms:rpc` leaf under it, and the per-app chain
    /// `SignCert` returns are the whole of what these tests need.
    struct KmsPki {
        root: CaCert,
    }

    struct CertPair {
        cert_pem: String,
        key_pem: String,
    }

    impl KmsPki {
        /// The root as `onboard_service::Keys::from_keys` builds it: self-signed,
        /// `ca_level(1)` so it can sign the per-app intermediates.
        fn new() -> Self {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
            let cert = CertRequest::builder()
                .org_name("Dstack")
                .subject("Dstack KMS CA")
                .ca_level(1)
                .key(&key)
                .build()
                .self_signed()
                .expect("root cert");
            Self {
                root: CaCert::from_parts(key, cert),
            }
        }

        /// The KMS's own RPC certificate: `kms:rpc`, signed straight by the root.
        fn rpc_cert(&self, domain: &str) -> CertPair {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rpc key");
            let cert = self
                .root
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
            CertPair {
                cert_pem: format!("{}\n{}", cert.pem(), self.root.pem_cert),
                key_pem: key.serialize_pem(),
            }
        }

        /// What `SignCert` returns to an app: a leaf carrying the alt names and
        /// usages the app asked for, under the per-app CA the KMS derives.
        ///
        /// Both halves are the production ones -- `derive_app_ca`'s builder call
        /// and [`CaCert::sign_csr`] -- so this is the chain a real KMS hands
        /// back, not an approximation of it.
        fn app_cert(&self, app_id: &[u8], alt_name: &str) -> CertPair {
            let app_key = kdf::derive_p256_key_pair(&self.root.key, &[app_id, b"app-ca"])
                .expect("app ca key");
            let app_ca = self
                .root
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

            let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
            let mut csr = csr_with(undecodable_attestation(), leaf_key.public_key_der());
            csr.config.subject = alt_name.to_string();
            csr.config.subject_alt_names = vec![alt_name.to_string()];
            let leaf = app_ca
                .sign_csr(&csr, Some(app_id), "app:custom")
                .expect("sign csr");
            CertPair {
                cert_pem: format!(
                    "{}\n{}\n{}",
                    leaf.pem(),
                    app_ca.pem_cert,
                    self.root.pem_cert
                ),
                key_pem: leaf_key.serialize_pem(),
            }
        }
    }

    /// Stand in for the KMS at `127.0.0.1`, serving `chain` as the server
    /// certificate, and answer `GetMeta` with a CA certificate of our choosing.
    #[rocket::post("/GetMeta")]
    fn get_meta() -> &'static str {
        r#"{"ca_cert":"the ca cert an impostor chose"}"#
    }

    async fn serve(chain: &CertPair) -> (u16, rocket::Shutdown, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, &chain.cert_pem).expect("write cert");
        std::fs::write(&key_path, &chain.key_pem).expect("write key");

        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("bind")
            .local_addr()
            .expect("local addr")
            .port();
        let figment = rocket::Config::figment()
            .merge(("port", port))
            .merge(("address", "127.0.0.1"))
            .merge(("log_level", "off"))
            .merge(("shutdown.ctrlc", false))
            .merge(("tls.certs", cert_path.to_str().expect("cert path")))
            .merge(("tls.key", key_path.to_str().expect("key path")));
        let rocket = rocket::custom(figment)
            .mount("/", rocket::routes![get_meta])
            .ignite()
            .await
            .expect("ignite");
        let shutdown = rocket.shutdown();
        tokio::spawn(rocket.launch());
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        (port, shutdown, dir)
    }

    /// Ask the impostor for the CA certificate, through the client a guest uses.
    async fn get_root_ca_from(port: u16, pinned_ca: &str) -> Result<String> {
        let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("client key");
        let client_cert = CertRequest::builder()
            .subject("a guest")
            .key(&client_key)
            .usage_client_auth(true)
            .build()
            .self_signed()
            .expect("client cert");
        let client = kms_client(
            format!("https://127.0.0.1:{port}"),
            pinned_ca.to_string(),
            client_cert.pem(),
            client_key.serialize_pem(),
            Arc::new(AttestationVerifier::new_prod(None).expect("verifier")),
        )?;
        Ok(client.get_meta().await?.ca_cert)
    }

    /// The severity of `SignCert` copying caller-chosen names and usages: a
    /// certificate minted through it for the KMS's own address chains to the
    /// root every guest pins, so a guest that pins only that root accepts an app
    /// as its KMS.
    ///
    /// The app id here is some *other* app's -- an attacker needs nothing but
    /// authorization for key release, which every deployed app has.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_app_certificate_is_not_accepted_as_the_kms() {
        let pki = KmsPki::new();
        let (port, shutdown, _dir) = serve(&pki.app_cert(&[0xa1; 20], "127.0.0.1")).await;
        let err = get_root_ca_from(port, &pki.root.pem_cert)
            .await
            .expect_err("an app's certificate must not authenticate the KMS");
        assert!(
            format!("{err:#}").contains("Invalid server cert usage: app:custom"),
            "expected the app usage to be refused, got: {err:#}"
        );
        shutdown.notify();
    }

    /// And the check must not cost the real thing: the KMS's own `kms:rpc`
    /// certificate, under the same root, still authenticates it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_kms_rpc_certificate_is_accepted() {
        let pki = KmsPki::new();
        let (port, shutdown, _dir) = serve(&pki.rpc_cert("127.0.0.1")).await;
        assert_eq!(
            get_root_ca_from(port, &pki.root.pem_cert)
                .await
                .expect("the KMS's own certificate must be accepted"),
            "the ca cert an impostor chose"
        );
        shutdown.notify();
    }

    /// The rule at the unit it is decided in, so a failure says which half moved.
    #[test]
    fn only_the_kms_rpc_usage_authenticates_a_kms() {
        let info = |usage: Option<&str>| CertInfo {
            cert_der: vec![],
            attestation: None,
            special_usage: usage.map(str::to_string),
            app_id: None,
        };
        assert!(validate_kms_rpc_cert(Some(info(Some("kms:rpc")))).is_ok());
        assert!(validate_kms_rpc_cert(Some(info(Some("app:custom")))).is_err());
        assert!(validate_kms_rpc_cert(Some(info(Some("app:ca")))).is_err());
        assert!(validate_kms_rpc_cert(Some(info(None))).is_err());
        assert!(validate_kms_rpc_cert(None).is_err());
    }
}
