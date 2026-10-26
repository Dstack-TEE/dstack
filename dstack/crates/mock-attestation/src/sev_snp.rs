// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use p384::ecdsa::{signature::DigestSigner, Signature as P384Signature, SigningKey};
use p384::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedKey, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha384};
use time::{Duration, OffsetDateTime};

pub struct SevSnpGenerator {
    root: Certificate,
    root_key: KeyPair,
    ask: Certificate,
    vcek: Certificate,
    vcek_key: KeyPair,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SevSnpEvidence {
    pub report: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
}

impl SevSnpGenerator {
    pub fn new() -> Result<Self> {
        Self::from_seed(rand::random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let CertifiedKey {
            cert: root,
            key_pair: root_key,
        } = make_ca("Mock AMD Milan ARK", "sev-root", &seed, None)?;
        let CertifiedKey {
            cert: ask,
            key_pair: ask_key,
        } = make_ca(
            "Mock AMD Milan ASK",
            "sev-ask",
            &seed,
            Some((&root, &root_key)),
        )?;
        let vcek_key = crate::p384_key(&seed, "sev-vcek")?;
        let mut params = base_params("Mock AMD VCEK")?;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let vcek = params.signed_by(&vcek_key, &ask, &ask_key)?;
        Ok(Self {
            root,
            root_key,
            ask,
            vcek,
            vcek_key,
        })
    }

    pub fn root_ca_pem(&self) -> String {
        self.root.pem()
    }

    pub fn root_key_pem(&self) -> String {
        self.root_key.serialize_pem()
    }

    pub fn ca_chain_pem(&self) -> Vec<u8> {
        format!("{}{}", self.ask.pem(), self.root.pem()).into_bytes()
    }

    pub fn vcek_der(&self) -> Vec<u8> {
        self.vcek.der().to_vec()
    }

    pub fn attest(&self, report_data: [u8; 64]) -> Result<SevSnpEvidence> {
        self.attest_with_host_data(report_data, [0x22; 32])
    }

    pub fn attest_with_host_data(
        &self,
        report_data: [u8; 64],
        host_data: [u8; 32],
    ) -> Result<SevSnpEvidence> {
        self.attest_with_measurement(report_data, host_data, [0x33; 48])
    }

    pub fn attest_with_measurement(
        &self,
        report_data: [u8; 64],
        host_data: [u8; 32],
        measurement: [u8; 48],
    ) -> Result<SevSnpEvidence> {
        let mut encoded = Vec::new();
        AttestationReport::default().write_bytes(&mut encoded)?;
        encoded[0..4].copy_from_slice(&2u32.to_le_bytes());
        encoded[52..56].copy_from_slice(&1u32.to_le_bytes());
        encoded[0x50..0x90].copy_from_slice(&report_data);
        encoded[0x90..0xc0].copy_from_slice(&measurement);
        encoded[0xc0..0xe0].copy_from_slice(&host_data);
        encoded[0x1a0..0x1e0].fill(0x33);
        let signing_key = SigningKey::from_pkcs8_pem(&self.vcek_key.serialize_pem())?;
        let signature: P384Signature =
            signing_key.sign_digest(Sha384::new_with_prefix(&encoded[..0x2a0]));
        write_amd_signature(&mut encoded[0x2a0..], &signature);
        Ok(SevSnpEvidence {
            report: encoded,
            cert_chain: vec![self.ask.pem().into_bytes(), self.vcek.pem().into_bytes()],
        })
    }
}

fn make_ca(
    name: &str,
    label: &str,
    seed: &[u8; 32],
    issuer: Option<(&Certificate, &KeyPair)>,
) -> Result<CertifiedKey> {
    let key_pair = crate::p384_key(seed, label)?;
    let mut params = base_params(name)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.extend([
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ]);
    let cert = match issuer {
        Some((issuer, issuer_key)) => params.signed_by(&key_pair, issuer, issuer_key)?,
        None => params.self_signed(&key_pair)?,
    };
    Ok(CertifiedKey { cert, key_pair })
}

fn base_params(name: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(30);
    Ok(params)
}

fn write_amd_signature(output: &mut [u8], signature: &P384Signature) {
    let bytes = signature.to_bytes();
    output[..144].fill(0);
    for (dst, src) in output[..48].iter_mut().zip(bytes[..48].iter().rev()) {
        *dst = *src;
    }
    for (dst, src) in output[72..120].iter_mut().zip(bytes[48..].iter().rev()) {
        *dst = *src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_report_passes_real_qvl_and_negative_cases_fail() {
        let generator = SevSnpGenerator::new().unwrap();
        let report_data = [0x42; 64];
        let evidence = generator.attest(report_data).unwrap();
        let verifier = sev_snp_qvl::QuoteVerifier::new(
            generator.root_ca_pem().into_bytes(),
            generator.root_ca_pem().into_bytes(),
            generator.root_ca_pem().into_bytes(),
        );
        verifier
            .verify(&evidence.report, &evidence.cert_chain, &report_data)
            .unwrap();

        let wrong = SevSnpGenerator::new().unwrap();
        let wrong_verifier = sev_snp_qvl::QuoteVerifier::new_with_root(
            sev_snp_qvl::AmdSnpProduct::Milan,
            wrong.root_ca_pem().into_bytes(),
        );
        assert!(wrong_verifier
            .verify(&evidence.report, &evidence.cert_chain, &report_data)
            .is_err());
        let mut tampered = evidence.report.clone();
        tampered[0x100] ^= 1;
        assert!(verifier
            .verify(&tampered, &evidence.cert_chain, &report_data)
            .is_err());
        assert!(verifier
            .verify(&evidence.report, &evidence.cert_chain, &[0x24; 64])
            .is_err());
    }
}
