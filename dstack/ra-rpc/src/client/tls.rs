// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use super::PinnedIssuer;
use anyhow::{bail, Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

/// Attestation is checked on the response, but TLS must still prove possession
/// of the attested certificate key. Reqwest's no-verifier also skips that proof.
///
/// With `pinned`, the server certificate must also match it, so that nothing
/// is sent to a server that fails the pin.
#[derive(Debug)]
struct AttestedCertVerifier {
    algorithms: WebPkiSupportedAlgorithms,
    pinned: Option<PinnedIssuer>,
}

fn matches_pin(pin: &PinnedIssuer, end_entity: &[u8]) -> bool {
    use ra_tls::traits::CertExt;
    use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};
    let Ok((_, cert)) = X509Certificate::from_der(end_entity) else {
        return false;
    };
    let Ok((_, pubkey)) = SubjectPublicKeyInfo::from_der(&pin.pubkey) else {
        return false;
    };
    !cert.is_ca()
        && cert.validity().is_valid()
        && cert.get_special_usage().ok().flatten().as_deref() == Some(pin.usage.as_str())
        && cert.verify_signature(Some(&pubkey)).is_ok()
}

impl ServerCertVerifier for AttestedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(pin) = &self.pinned {
            if !matches_pin(pin, end_entity) {
                return Err(rustls::Error::General(
                    "server certificate does not match the pinned issuer".into(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

pub(super) fn config_without_ca_verification(
    cert: Option<&str>,
    key: Option<&str>,
    pinned: Option<PinnedIssuer>,
) -> Result<rustls::ClientConfig> {
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let verifier = AttestedCertVerifier {
        algorithms: provider.signature_verification_algorithms,
        pinned,
    };
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    match (cert, key) {
        (Some(cert), Some(key)) => builder
            .with_client_auth_cert(
                CertificateDer::pem_slice_iter(cert.as_bytes()).collect::<Result<Vec<_>, _>>()?,
                PrivateKeyDer::from_pem_slice(key.as_bytes())?,
            )
            .context("invalid RA-TLS client identity"),
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => bail!("RA-TLS client identity requires both certificate and key"),
    }
}
