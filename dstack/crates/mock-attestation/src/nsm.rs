// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p384::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedKey, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use sha2::{Digest, Sha384};
use time::{Duration, OffsetDateTime};

/// In-memory NSM test hierarchy. A fresh leaf is issued so validity follows CI
/// wall-clock time rather than a checked-in fixture.
pub struct NsmGenerator {
    root: Certificate,
    root_key: KeyPair,
    leaf: Certificate,
    leaf_key: KeyPair,
}

#[derive(Serialize)]
struct Document {
    module_id: String,
    digest: String,
    timestamp: u64,
    pcrs: BTreeMap<u16, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct NsmDocumentOptions {
    pub module_id: String,
    pub digest: String,
    pub timestamp_ms: Option<u64>,
}

impl Default for NsmDocumentOptions {
    fn default() -> Self {
        Self {
            module_id: "mock-nsm".into(),
            digest: "SHA384".into(),
            timestamp_ms: None,
        }
    }
}

impl NsmGenerator {
    pub fn new() -> Result<Self> {
        Self::from_seed(rand::random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let CertifiedKey {
            cert: root,
            key_pair: root_key,
        } = make_root(&seed)?;
        let leaf_key = crate::p384_key(&seed, "nsm-leaf")?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, "mock.nsm.dstack");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let (not_before, not_after) = validity();
        params.not_before = not_before;
        params.not_after = not_after;
        let leaf = params.signed_by(&leaf_key, &root, &root_key)?;
        Ok(Self {
            root,
            root_key,
            leaf,
            leaf_key,
        })
    }

    pub fn root_ca_pem(&self) -> String {
        self.root.pem()
    }

    pub fn root_key_pem(&self) -> String {
        self.root_key.serialize_pem()
    }

    pub fn attest(&self, report_data: &[u8]) -> Result<Vec<u8>> {
        let pcrs = (0..=2)
            .map(|index| (index, vec![index as u8; 48]))
            .collect();
        self.attest_with_pcrs(report_data, pcrs)
    }

    pub fn attest_with_pcrs(
        &self,
        report_data: &[u8],
        pcrs: BTreeMap<u16, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.attest_with_claims(Some(report_data), None, None, pcrs)
    }

    pub fn attest_with_claims(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
        pcrs: BTreeMap<u16, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.attest_with_options(
            user_data,
            nonce,
            public_key,
            pcrs,
            NsmDocumentOptions::default(),
        )
    }

    /// Sign a document with explicit claims used by policy and time tests.
    pub fn attest_with_options(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
        pcrs: BTreeMap<u16, Vec<u8>>,
        options: NsmDocumentOptions,
    ) -> Result<Vec<u8>> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_millis() as u64;
        let document = Document {
            module_id: options.module_id,
            digest: options.digest,
            timestamp: options.timestamp_ms.unwrap_or(current_timestamp),
            pcrs,
            certificate: self.leaf.der().to_vec(),
            cabundle: vec![self.root.der().to_vec()],
            public_key: public_key.map(ToOwned::to_owned),
            user_data: user_data.map(ToOwned::to_owned),
            nonce: nonce.map(ToOwned::to_owned),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&document, &mut payload)?;

        let mut protected = Vec::new();
        let protected_map = BTreeMap::from([(1i64, ciborium::Value::Integer((-35).into()))]);
        ciborium::into_writer(&protected_map, &mut protected)?;
        let sig_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".into()),
            ciborium::Value::Bytes(protected.clone()),
            ciborium::Value::Bytes(Vec::new()),
            ciborium::Value::Bytes(payload.clone()),
        ]);
        let mut to_sign = Vec::new();
        ciborium::into_writer(&sig_structure, &mut to_sign)?;
        let digest = Sha384::digest(to_sign);
        let signing_key = SigningKey::from_pkcs8_pem(&self.leaf_key.serialize_pem())?;
        let signature: Signature = signing_key.sign_prehash(&digest)?;

        let cose = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected),
            ciborium::Value::Map(Vec::new()),
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(signature.to_bytes().to_vec()),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&cose, &mut encoded)?;
        Ok(encoded)
    }
}

fn make_root(seed: &[u8; 32]) -> Result<CertifiedKey> {
    let key_pair = crate::p384_key(seed, "nsm-root")?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Mock AWS Nitro Enclaves Root CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.extend([
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ]);
    let (not_before, not_after) = validity();
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.self_signed(&key_pair)?;
    Ok(CertifiedKey { cert, key_pair })
}

fn validity() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now - Duration::days(1), now + Duration::days(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_document_passes_real_qvl_and_negative_cases_fail() {
        let generator = NsmGenerator::new().unwrap();
        let report_data = [0x42; 64];
        let evidence = generator.attest(&report_data).unwrap();
        let verifier = nsm_qvl::QuoteVerifier::new(generator.root_ca_pem());
        let verified = verifier.verify(&evidence, None, None).unwrap();
        assert_eq!(verified.user_data.as_deref(), Some(report_data.as_slice()));

        let wrong = NsmGenerator::new().unwrap();
        assert!(nsm_qvl::QuoteVerifier::new(wrong.root_ca_pem())
            .verify(&evidence, None, None)
            .is_err());

        let mut tampered = evidence;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verifier.verify(&tampered, None, None).is_err());
        assert!(
            crate::ensure_report_data(verified.user_data.as_deref().unwrap(), &[0x24; 64]).is_err()
        );
    }
}
