// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Verify RA-TLS client certificates by attestation instead of by issuer.
//!
//! Rocket configures mutual TLS through rustls' [`WebPkiClientVerifier`], which pins
//! a CA: a presented client certificate must chain to it or the handshake fails.
//! RA-TLS certificates are self-issued and carry their identity in a TEE quote, so
//! there is no CA to pin. dstack worked around that by having the KMS hand every
//! caller a shared "temp CA" private key purely so the minted certificate would
//! chain somewhere — the CA established nothing, and its key was public by design.
//!
//! [`RaTlsClientVerifier`] replaces the chain check with the check that actually
//! carries meaning: the certificate must carry an attestation. Certificates minted
//! from that temp CA — which is what guests and KMS-to-KMS onboarding still send —
//! are accepted for that attestation rather than for their issuer, so nothing has to
//! change on the client side for them to keep working. Verifying that
//! attestation — and deciding whether the app behind it is authorized — needs
//! network I/O (collateral fetch, auth API) and stays where it already is, in
//! [`crate::rocket_helper`] and the service handlers. Keeping the expensive half
//! out of the handshake also keeps unauthenticated peers from driving it.
//!
//! [`WebPkiClientVerifier`]: https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html

use std::sync::Arc;

use rocket::tls::{ClientHello, Resolver, ServerConfig};
use rocket::{Build, Rocket};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tracing::{debug, info, warn};
use x509_parser::prelude::FromDer as _;

/// A rustls client-certificate verifier that accepts any certificate carrying an
/// RA-TLS attestation, whatever signed it.
#[derive(Debug)]
pub struct RaTlsClientVerifier {
    provider: Arc<CryptoProvider>,
}

impl RaTlsClientVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ClientCertVerifier for RaTlsClientVerifier {
    /// Advertise no acceptable CAs, so clients send whatever certificate they hold
    /// rather than filtering against a list we do not have.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Anonymous connections stay allowed, matching the previous
    /// `[rpc.tls.mutual] mandatory = false`. Handlers that need an attested caller
    /// enforce it themselves; the unauthenticated RPCs (`GetMeta`, `GetTempCaCert`)
    /// are reachable without a certificate by design.
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
            .map_err(|err| {
                rustls::Error::General(format!("failed to parse client certificate: {err}"))
            })?;

        // webpki used to enforce the validity window; keep doing so now that it does not.
        let now_secs = now.as_secs();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        if not_before > 0 && now_secs < not_before as u64 {
            return Err(rustls::Error::General(
                "client certificate is not yet valid".into(),
            ));
        }
        if not_after > 0 && now_secs > not_after as u64 {
            return Err(rustls::Error::General(
                "client certificate has expired".into(),
            ));
        }

        // Only presence and decodability are checked here. The quote itself, and its
        // binding to this certificate's public key, are verified asynchronously in
        // `rocket_helper::handle_prpc_impl` before any handler sees the caller.
        match ra_tls::attestation::from_cert(&cert) {
            Ok(Some(_)) => Ok(ClientCertVerified::assertion()),
            Ok(None) => Err(rustls::Error::General(
                "client certificate carries no attestation".into(),
            )),
            Err(err) => Err(rustls::Error::General(format!(
                "failed to decode client attestation: {err}"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A Rocket TLS resolver that serves one [`ServerConfig`] wired to
/// [`RaTlsClientVerifier`].
///
/// Attach it with `rocket.attach(RaTlsClientAuth::fairing())`. It reads the same
/// `tls.certs` / `tls.key` the stock listener uses and replaces only the client
/// verifier, so `[tls.mutual]` becomes inert — rocket still builds a default config
/// from it, but every connection resolves to this one instead.
pub struct RaTlsClientAuth {
    config: Option<Arc<ServerConfig>>,
}

#[rocket::async_trait]
impl Resolver for RaTlsClientAuth {
    async fn init(rocket: &Rocket<Build>) -> rocket::tls::Result<Self> {
        let figment = rocket.figment();
        let certs: Option<String> = figment.extract_inner("tls.certs").ok();
        let key: Option<String> = figment.extract_inner("tls.key").ok();
        let (Some(certs), Some(key)) = (certs, key) else {
            // No TLS configured (plain-HTTP dev servers). Resolving to `None` lets
            // rocket keep whatever it would have done without us.
            warn!("no tls.certs/tls.key configured, RA-TLS client auth is inactive");
            return Ok(Self { config: None });
        };
        let config = build_server_config(&certs, &key)
            .map_err(|err| rocket::figment::Error::from(err.to_string()))?;
        info!("RA-TLS client certificate verification enabled");
        Ok(Self {
            config: Some(Arc::new(config)),
        })
    }

    async fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<ServerConfig>> {
        self.config.clone()
    }
}

fn build_server_config(certs_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    use anyhow::Context as _;
    use rustls::pki_types::pem::PemObject as _;

    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(certs_path)
        .with_context(|| format!("failed to read certs from {certs_path}"))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("failed to parse certs from {certs_path}"))?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to read key from {key_path}"))?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to select TLS protocol versions")?
        .with_client_cert_verifier(Arc::new(RaTlsClientVerifier::new(provider)))
        .with_single_cert(certs, key)
        .context("failed to load server certificate")?;
    // Match rocket's own ALPN so HTTP/2 keeps working.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    debug!("built RA-TLS server config from {certs_path}");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_tls::attestation::{Attestation, AttestationQuote, TdxQuote, VersionedAttestation};
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::time::{Duration, SystemTime};

    fn verifier() -> RaTlsClientVerifier {
        RaTlsClientVerifier::new(Arc::new(rustls::crypto::ring::default_provider()))
    }

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
    }

    fn attestation() -> VersionedAttestation {
        Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote: vec![1, 2, 3],
                event_log: vec![],
            }),
            runtime_events: vec![],
            report_data: [0u8; 64],
            config: "".into(),
            report: (),
        }
        .into_versioned()
    }

    fn leaf(
        att: Option<&VersionedAttestation>,
        not_after: Option<SystemTime>,
        issuer: Option<(&Certificate, &KeyPair)>,
    ) -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let req = CertRequest::builder()
            .subject("test client")
            .key(&key)
            .maybe_attestation(att)
            .maybe_not_after(not_after)
            .usage_client_auth(true)
            .build();
        let cert = match issuer {
            Some((ca_cert, ca_key)) => req.signed_by(ca_cert, ca_key).unwrap(),
            None => req.self_signed().unwrap(),
        };
        cert.der().to_vec()
    }

    fn verify(der: Vec<u8>) -> Result<ClientCertVerified, rustls::Error> {
        verifier().verify_client_cert(&CertificateDer::from(der), &[], now())
    }

    #[test]
    fn accepts_self_signed_cert_carrying_attestation() {
        let att = attestation();
        assert!(verify(leaf(Some(&att), None, None)).is_ok());
    }

    #[test]
    fn accepts_ca_signed_cert() {
        // What guests and KMS-to-KMS onboarding send today: a certificate minted from
        // the KMS temp CA. That chain is no longer pinned, so it is accepted for the
        // attestation it carries instead.
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert = CertRequest::builder()
            .subject("Dstack Client Temp CA")
            .key(&ca_key)
            .ca_level(0)
            .build()
            .self_signed()
            .unwrap();
        let att = attestation();
        assert!(verify(leaf(Some(&att), None, Some((&ca_cert, &ca_key)))).is_ok());
    }

    #[test]
    fn rejects_cert_without_attestation() {
        let err = verify(leaf(None, None, None)).unwrap_err();
        assert!(
            err.to_string().contains("no attestation"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_expired_cert() {
        let att = attestation();
        let expired = SystemTime::now() - Duration::from_secs(3600);
        let err = verify(leaf(Some(&att), Some(expired), None)).unwrap_err();
        assert!(
            err.to_string().contains("expired"),
            "unexpected error: {err}"
        );
    }
}
