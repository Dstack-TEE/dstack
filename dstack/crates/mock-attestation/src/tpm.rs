// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use dstack_types::Platform;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CrlDistributionPoint, CustomExtension, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    SerialNumber,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tpm_qvl::QuoteCollateral;
use tpm_types::{PcrValue, TpmQuote};

pub struct TpmGenerator {
    root: Certificate,
    root_key: KeyPair,
    intermediate: Certificate,
    ak: Certificate,
    ak_key: KeyPair,
    intermediate_crl: Vec<u8>,
    root_crl: Vec<u8>,
}

impl TpmGenerator {
    pub fn new() -> Result<Self> {
        Self::with_base_url("http://127.0.0.1:8088")
    }

    pub fn with_base_url(base_url: &str) -> Result<Self> {
        Self::from_seed(rand::random(), base_url)
    }

    pub fn from_seed(seed: [u8; 32], base_url: &str) -> Result<Self> {
        let root_key = crate::p256_key(&seed, "tpm-root")?;
        let mut root_params = params("Mock TPM Root CA")?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages.extend([
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ]);
        root_params
            .crl_distribution_points
            .push(CrlDistributionPoint {
                uris: vec![format!("{base_url}/tpm/crl/root.crl")],
            });
        let root = root_params.self_signed(&root_key)?;

        let intermediate_key = crate::p256_key(&seed, "tpm-intermediate")?;
        let mut intermediate_params = params("Mock TPM Attestation Intermediate CA")?;
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        intermediate_params.key_usages.extend([
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ]);
        intermediate_params
            .custom_extensions
            .push(aia(&format!("{base_url}/tpm/aia/root.pem")));
        intermediate_params
            .crl_distribution_points
            .push(CrlDistributionPoint {
                uris: vec![format!("{base_url}/tpm/crl/root.crl")],
            });
        let intermediate = intermediate_params.signed_by(&intermediate_key, &root, &root_key)?;
        let ak_key = crate::p256_key(&seed, "tpm-ak")?;
        let mut ak_params = params("Mock TPM Attestation Key")?;
        ak_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ak_params
            .custom_extensions
            .push(aia(&format!("{base_url}/tpm/aia/intermediate.der")));
        ak_params
            .crl_distribution_points
            .push(CrlDistributionPoint {
                uris: vec![format!("{base_url}/tpm/crl/intermediate.crl")],
            });
        let ak = ak_params.signed_by(&ak_key, &intermediate, &intermediate_key)?;
        let now = OffsetDateTime::now_utc();
        let crl = |issuer: &Certificate, key: &KeyPair, number| -> Result<Vec<u8>> {
            Ok(CertificateRevocationListParams {
                this_update: now - Duration::days(1),
                next_update: now + Duration::days(30),
                crl_number: SerialNumber::from(number),
                issuing_distribution_point: None,
                revoked_certs: Vec::new(),
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(issuer, key)?
            .der()
            .to_vec())
        };
        let root_crl = crl(&root, &root_key, 1)?;
        let intermediate_crl = crl(&intermediate, &intermediate_key, 2)?;
        Ok(Self {
            root,
            root_key,
            intermediate,
            ak,
            ak_key,
            intermediate_crl,
            root_crl,
        })
    }

    pub fn root_ca_pem(&self) -> String {
        self.root.pem()
    }

    pub fn root_ca_der(&self) -> Vec<u8> {
        self.root.der().to_vec()
    }

    pub fn root_key_pem(&self) -> String {
        self.root_key.serialize_pem()
    }

    pub fn collateral(&self) -> QuoteCollateral {
        QuoteCollateral {
            cert_chain_pem: self.intermediate.pem(),
            crls: vec![self.intermediate_crl.clone()],
            root_ca_crl: Some(self.root_crl.clone()),
        }
    }

    pub fn intermediate_der(&self) -> Vec<u8> {
        self.intermediate.der().to_vec()
    }

    /// Return the deterministic leaf certificate for simulator TPM fixtures.
    pub fn leaf_cert_der(&self) -> Vec<u8> {
        self.ak.der().to_vec()
    }
    pub fn intermediate_crl_der(&self) -> Vec<u8> {
        self.intermediate_crl.clone()
    }
    pub fn root_crl_der(&self) -> Vec<u8> {
        self.root_crl.clone()
    }

    pub fn attest(&self, qualifying_data: &[u8]) -> Result<TpmQuote> {
        let pcr = PcrValue {
            index: 14,
            algorithm: "sha256".into(),
            value: vec![0x11; 32],
        };
        let pcr_digest = Sha256::digest(&pcr.value);
        let mut message = Vec::new();
        message.extend_from_slice(&0xff54_4347u32.to_be_bytes());
        message.extend_from_slice(&0x8018u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes()); // qualified signer
        message.extend_from_slice(&(qualifying_data.len() as u16).to_be_bytes());
        message.extend_from_slice(qualifying_data);
        message.extend_from_slice(&0u64.to_be_bytes()); // clock
        message.extend_from_slice(&0u32.to_be_bytes()); // reset count
        message.extend_from_slice(&0u32.to_be_bytes()); // restart count
        message.push(1); // safe
        message.extend_from_slice(&0u64.to_be_bytes()); // firmware
        message.extend_from_slice(&1u32.to_be_bytes()); // selection count
        message.extend_from_slice(&0x000bu16.to_be_bytes());
        message.push(3);
        message.extend_from_slice(&[0, 0x40, 0]); // PCR14
        message.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        message.extend_from_slice(&pcr_digest);

        let digest = Sha256::digest(&message);
        let key = SigningKey::from_pkcs8_pem(&self.ak_key.serialize_pem())?;
        let signature: Signature = key.sign_prehash(&digest)?;
        let bytes = signature.to_bytes();
        let mut tpm_signature = Vec::with_capacity(72);
        tpm_signature.extend_from_slice(&0x0018u16.to_be_bytes());
        tpm_signature.extend_from_slice(&0x000bu16.to_be_bytes());
        tpm_signature.extend_from_slice(&32u16.to_be_bytes());
        tpm_signature.extend_from_slice(&bytes[..32]);
        tpm_signature.extend_from_slice(&32u16.to_be_bytes());
        tpm_signature.extend_from_slice(&bytes[32..]);

        Ok(TpmQuote {
            message,
            signature: tpm_signature,
            pcr_values: vec![pcr],
            ak_cert: self.ak.der().to_vec(),
            platform: Platform::Gcp,
            event_log: Vec::new(),
        })
    }
}

fn aia(url: &str) -> CustomExtension {
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                        1, 3, 6, 1, 5, 5, 7, 48, 2,
                    ]));
                writer
                    .next()
                    .write_tagged_implicit(yasna::Tag::context(6), |writer| {
                        writer.write_ia5_string(url)
                    });
            });
        })
    });
    CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], der)
}

fn params(name: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(30);
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_quote_passes_real_qvl_and_negative_cases_fail() {
        let generator = TpmGenerator::new().unwrap();
        let qualifying_data = [0x42; 32];
        let quote = generator.attest(&qualifying_data).unwrap();
        let verifier = tpm_qvl::QuoteVerifier::new(generator.root_ca_pem());
        verifier.verify(&quote, &generator.collateral()).unwrap();

        let wrong = TpmGenerator::new().unwrap();
        assert!(tpm_qvl::QuoteVerifier::new(wrong.root_ca_pem())
            .verify(&quote, &generator.collateral())
            .is_err());
        let mut tampered = quote.clone();
        tampered.message[10] ^= 1;
        assert!(verifier.verify(&tampered, &generator.collateral()).is_err());
        let verified = verifier.verify(&quote, &generator.collateral()).unwrap();
        assert!(crate::ensure_report_data(&verified.attest.qualified_data, &[0x24; 32]).is_err());
    }
}
