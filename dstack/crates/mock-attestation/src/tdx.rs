// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use dcap_qvl::quote::{
    AuthData, AuthDataV4, CertificationData, Data, EnclaveReport, Header,
    QEReportCertificationData, Quote, Report, TDReport10,
};
use dcap_qvl::QuoteCollateralV3;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CertifiedKey, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RemoteKeyPair, SerialNumber, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
};
use scale::Encode;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const MOCK_PKI_NOT_BEFORE: i64 = 1_577_836_800; // 2020-01-01T00:00:00Z
const MOCK_PKI_NOT_AFTER: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

pub struct TdxGenerator {
    root: Certificate,
    root_signing_key: SigningKey,
    pck_ca: Certificate,
    pck: Certificate,
    pck_key: SigningKey,
    pck_crl: Vec<u8>,
    tcb_signer: Certificate,
    tcb_signer_key: SigningKey,
    qe_signer: Certificate,
    qe_signer_key: SigningKey,
    root_crl: Vec<u8>,
}

struct DeterministicP256KeyPair {
    key: SigningKey,
    public_key: Vec<u8>,
}

impl DeterministicP256KeyPair {
    fn new(key: SigningKey) -> Self {
        let public_key = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { key, public_key }
    }
}

impl RemoteKeyPair for DeterministicP256KeyPair {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: Signature = self.key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

pub struct TdxEvidence {
    pub quote: Vec<u8>,
    pub collateral: QuoteCollateralV3,
}

impl TdxGenerator {
    pub fn new() -> Result<Self> {
        Self::from_seed(rand::random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let (
            CertifiedKey {
                cert: root,
                key_pair: root_key,
            },
            root_signing_key,
        ) = make_root(&seed)?;
        let (pck_ca, pck_ca_key) = make_ca(
            "Mock Intel SGX PCK Platform CA",
            "tdx-pck-ca",
            &seed,
            &root,
            &root_key,
        )?;
        let (pck, pck_key) = make_leaf(
            "Mock Intel SGX PCK Certificate",
            "tdx-pck",
            &seed,
            &pck_ca,
            &pck_ca_key,
            true,
        )?;
        let (tcb_signer, tcb_signer_key) = make_leaf(
            "Mock Intel SGX TCB Signing",
            "tdx-tcb",
            &seed,
            &root,
            &root_key,
            false,
        )?;
        let (qe_signer, qe_signer_key) = make_leaf(
            "Mock Intel SGX QE Identity Signing",
            "tdx-qe",
            &seed,
            &root,
            &root_key,
            false,
        )?;
        let pck_crl = CertificateRevocationListParams {
            this_update: fixed_time(MOCK_PKI_NOT_BEFORE)?,
            next_update: fixed_time(MOCK_PKI_NOT_AFTER)?,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&pck_ca, &pck_ca_key)?
        .der()
        .to_vec();
        let root_crl = CertificateRevocationListParams {
            this_update: fixed_time(MOCK_PKI_NOT_BEFORE)?,
            next_update: fixed_time(MOCK_PKI_NOT_AFTER)?,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&root, &root_key)?
        .der()
        .to_vec();
        Ok(Self {
            root,
            root_signing_key,
            pck_ca,
            pck,
            pck_key,
            pck_crl,
            tcb_signer,
            tcb_signer_key,
            qe_signer,
            qe_signer_key,
            root_crl,
        })
    }

    pub fn root_ca_der(&self) -> Vec<u8> {
        self.root.der().to_vec()
    }
    pub fn root_ca_pem(&self) -> String {
        self.root.pem()
    }
    pub fn root_key_pem(&self) -> Result<String> {
        Ok(self
            .root_signing_key
            .to_pkcs8_pem(Default::default())?
            .to_string())
    }

    pub fn sample_collateral(&self) -> Result<QuoteCollateralV3> {
        self.collateral()
    }

    #[cfg(test)]
    pub(crate) fn sample_collateral_with_tcb_status(
        &self,
        tcb_status: &str,
    ) -> Result<QuoteCollateralV3> {
        self.collateral_with_tcb_status(tcb_status)
    }

    pub fn root_crl_der(&self) -> Vec<u8> {
        self.root_crl.clone()
    }

    pub fn pck_crl_der(&self) -> Vec<u8> {
        self.pck_crl.clone()
    }

    pub fn attest(&self, report_data: [u8; 64]) -> Result<TdxEvidence> {
        self.attest_with_rtmrs(
            report_data,
            [[0x20; 48], [0x21; 48], [0x22; 48], [0x23; 48]],
        )
    }

    pub fn attest_with_rtmrs(
        &self,
        report_data: [u8; 64],
        rtmrs: [[u8; 48]; 4],
    ) -> Result<TdxEvidence> {
        self.attest_with_measurements(report_data, [0x11; 48], rtmrs)
    }

    pub fn attest_with_measurements(
        &self,
        report_data: [u8; 64],
        mrtd: [u8; 48],
        rtmrs: [[u8; 48]; 4],
    ) -> Result<TdxEvidence> {
        let auth_key = SigningKey::random(&mut rand::thread_rng());
        let auth_pub = auth_key.verifying_key().to_encoded_point(false);
        let auth_pub: [u8; 64] = auth_pub.as_bytes()[1..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid P-256 public key length"))?;
        let qe_auth = vec![0u8; 32];
        let mut qe_hash_input = Vec::from(auth_pub);
        qe_hash_input.extend_from_slice(&qe_auth);
        let mut qe_report = EnclaveReport {
            cpu_svn: [0; 16],
            misc_select: 0,
            reserved1: [0; 28],
            attributes: [0; 16],
            mr_enclave: [0; 32],
            reserved2: [0; 32],
            mr_signer: [0x44; 32],
            reserved3: [0; 96],
            isv_prod_id: 1,
            isv_svn: 1,
            reserved4: [0; 60],
            report_data: [0; 64],
        };
        qe_report.report_data[..32].copy_from_slice(&Sha256::digest(qe_hash_input));
        let qe_report_bytes: [u8; 384] = qe_report
            .encode()
            .try_into()
            .map_err(|bytes: Vec<u8>| anyhow::anyhow!("invalid QE report size {}", bytes.len()))?;
        let qe_sig: Signature = self.pck_key.sign(&qe_report_bytes);

        let pck_chain =
            format!("{}{}{}", self.pck.pem(), self.pck_ca.pem(), self.root.pem()).into_bytes();
        let qe_certification = QEReportCertificationData {
            qe_report: qe_report_bytes,
            qe_report_signature: qe_sig.to_bytes().into(),
            qe_auth_data: Data::new(qe_auth),
            certification_data: CertificationData {
                cert_type: 5,
                body: Data::new(pck_chain),
            },
        };
        let td_report = TDReport10 {
            tee_tcb_svn: [0; 16],
            mr_seam: [0; 48],
            mr_signer_seam: [0; 48],
            seam_attributes: [0; 8],
            td_attributes: [0, 0, 0, 0x10, 0, 0, 0, 0],
            xfam: [0; 8],
            mr_td: mrtd,
            mr_config_id: [0; 48],
            mr_owner: [0; 48],
            mr_owner_config: [0; 48],
            rt_mr0: rtmrs[0],
            rt_mr1: rtmrs[1],
            rt_mr2: rtmrs[2],
            rt_mr3: rtmrs[3],
            report_data,
        };
        let header = Header {
            version: 4,
            attestation_key_type: 2,
            tee_type: 0x81,
            qe_svn: 1,
            pce_svn: 0,
            qe_vendor_id: INTEL_QE_VENDOR_ID,
            user_data: [0; 20],
        };
        let mut auth = AuthDataV4 {
            ecdsa_signature: [0; 64],
            ecdsa_attestation_key: auth_pub,
            certification_data: CertificationData {
                cert_type: 6,
                body: Data::new(qe_certification.encode()),
            },
            qe_report_data: qe_certification,
        };
        let mut quote = Quote {
            header,
            report: Report::TD10(td_report),
            auth_data: AuthData::V4(auth.clone()),
        };
        let raw = quote.encode();
        let quote_sig: Signature = auth_key.sign(&raw[..quote.signed_length()]);
        auth.ecdsa_signature = quote_sig.to_bytes().into();
        quote.auth_data = AuthData::V4(auth);

        Ok(TdxEvidence {
            quote: quote.encode(),
            collateral: self.collateral()?,
        })
    }

    fn collateral(&self) -> Result<QuoteCollateralV3> {
        self.collateral_with_tcb_status("UpToDate")
    }

    fn collateral_with_tcb_status(&self, tcb_status: &str) -> Result<QuoteCollateralV3> {
        let now = chrono::Utc::now();
        let issue =
            (now - chrono::Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let next =
            (now + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let tcb_info = json!({
            "id":"TDX", "version":3, "issueDate":issue, "nextUpdate":next,
            "fmspc":"000000000000", "pceId":"0000", "tcbType":0, "tcbEvaluationDataNumber":1,
            "tdxModule":{"mrsigner":"00".repeat(48),"attributes":"00".repeat(8),"attributesMask":"00".repeat(8)},
            "tcbLevels":[{"tcb":{"sgxtcbcomponents":vec![json!({"svn":0});16],"pcesvn":0,"tdxtcbcomponents":vec![json!({"svn":0});16]},"tcbDate":issue,"tcbStatus":tcb_status}]
        }).to_string();
        let qe_identity = json!({
            "id":"TD_QE", "version":2, "issueDate":issue, "nextUpdate":next,
            "tcbEvaluationDataNumber":1, "miscselect":"00000000", "miscselectMask":"00000000",
            "attributes":"00".repeat(16), "attributesMask":"00".repeat(16), "mrsigner":"44".repeat(32),
            "isvprodid":1, "tcbLevels":[{"tcb":{"isvsvn":1},"tcbDate":issue,"tcbStatus":"UpToDate"}]
        }).to_string();
        Ok(QuoteCollateralV3 {
            pck_crl_issuer_chain: format!("{}{}", self.pck_ca.pem(), self.root.pem()),
            root_ca_crl: self.root_crl.clone(),
            pck_crl: self.pck_crl.clone(),
            tcb_info_issuer_chain: format!("{}{}", self.tcb_signer.pem(), self.root.pem()),
            tcb_info_signature: sign_raw(&self.tcb_signer_key, tcb_info.as_bytes())?,
            tcb_info,
            qe_identity_issuer_chain: format!("{}{}", self.qe_signer.pem(), self.root.pem()),
            qe_identity_signature: sign_raw(&self.qe_signer_key, qe_identity.as_bytes())?,
            qe_identity,
            pck_certificate_chain: None,
        })
    }
}

fn deterministic_key_pair(seed: &[u8; 32], label: &str) -> Result<(KeyPair, SigningKey)> {
    let serialized = crate::p256_key(seed, label)?;
    let signing_key = SigningKey::from_pkcs8_pem(&serialized.serialize_pem())?;
    let key_pair =
        KeyPair::from_remote(Box::new(DeterministicP256KeyPair::new(signing_key.clone())))?;
    Ok((key_pair, signing_key))
}

fn make_root(seed: &[u8; 32]) -> Result<(CertifiedKey, SigningKey)> {
    let (key_pair, signing_key) = deterministic_key_pair(seed, "tdx-root")?;
    let mut params = cert_params("Mock Intel SGX Root CA")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.extend([
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ]);
    let cert = params.self_signed(&key_pair)?;
    Ok((CertifiedKey { cert, key_pair }, signing_key))
}

fn make_ca(
    name: &str,
    label: &str,
    seed: &[u8; 32],
    issuer: &Certificate,
    issuer_key: &KeyPair,
) -> Result<(Certificate, KeyPair)> {
    let (key, _) = deterministic_key_pair(seed, label)?;
    let mut params = cert_params(name)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.extend([
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ]);
    let cert = params.signed_by(&key, issuer, issuer_key)?;
    Ok((cert, key))
}

fn make_leaf(
    name: &str,
    label: &str,
    seed: &[u8; 32],
    root: &Certificate,
    root_key: &KeyPair,
    pck: bool,
) -> Result<(Certificate, SigningKey)> {
    let (key, signing_key) = deterministic_key_pair(seed, label)?;
    let mut params = cert_params(name)?;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    if pck {
        params.custom_extensions.push(pck_extension());
    }
    let cert = params.signed_by(&key, root, root_key)?;
    Ok((cert, signing_key))
}

fn cert_params(name: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec!["mock.dstack.invalid".into()])?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.serial_number = Some(SerialNumber::from(42u64));
    params.not_before = fixed_time(MOCK_PKI_NOT_BEFORE)?;
    params.not_after = fixed_time(MOCK_PKI_NOT_AFTER)?;
    Ok(params)
}

fn fixed_time(timestamp: i64) -> Result<OffsetDateTime> {
    Ok(OffsetDateTime::from_unix_timestamp(timestamp)?)
}

fn pck_extension() -> CustomExtension {
    fn oid(writer: yasna::DERWriter, oid: &[u64]) {
        writer.write_oid(&yasna::models::ObjectIdentifier::from_slice(oid));
    }
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            let entries: Vec<(&[u64], Vec<u8>, u8)> = vec![
                (&[1, 2, 840, 113741, 1, 13, 1, 1], vec![0; 16], 0),
                (&[1, 2, 840, 113741, 1, 13, 1, 3], vec![0; 2], 0),
                (&[1, 2, 840, 113741, 1, 13, 1, 4], vec![0; 6], 0),
                (&[1, 2, 840, 113741, 1, 13, 1, 5], vec![0], 2),
            ];
            for (entry_oid, value, kind) in entries {
                writer.next().write_sequence(|w| {
                    oid(w.next(), entry_oid);
                    if kind == 2 {
                        w.next().write_enum(0)
                    } else {
                        w.next().write_bytes(&value)
                    }
                });
            }
            writer.next().write_sequence(|w| {
                oid(w.next(), &[1, 2, 840, 113741, 1, 13, 1, 2]);
                w.next().write_sequence(|w| {
                    w.next().write_sequence(|w| {
                        oid(w.next(), &[1, 2, 840, 113741, 1, 13, 1, 2, 17]);
                        w.next().write_u8(0);
                    });
                    w.next().write_sequence(|w| {
                        oid(w.next(), &[1, 2, 840, 113741, 1, 13, 1, 2, 18]);
                        w.next().write_bytes(&[0; 16]);
                    });
                });
            });
        })
    });
    CustomExtension::from_oid_content(&[1, 2, 840, 113741, 1, 13, 1], der)
}

fn sign_raw(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>> {
    let sig: Signature = key.sign(message);
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_hierarchies_are_cross_process_compatible() {
        let first = TdxGenerator::from_seed([0x31; 32]).unwrap();
        let second = TdxGenerator::from_seed([0x31; 32]).unwrap();
        assert_eq!(first.root_ca_der(), second.root_ca_der());
        assert_eq!(first.root_crl_der(), second.root_crl_der());

        let evidence = first.attest([0x42; 64]).unwrap();
        let collateral = second.sample_collateral().unwrap();
        assert_eq!(evidence.collateral, collateral);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        dcap_qvl::verify::QuoteVerifier::new(second.root_ca_der())
            .verify(&evidence.quote, &collateral, now)
            .unwrap();
    }

    #[test]
    fn generated_quote_passes_real_qvl_and_negative_cases_fail() {
        let generator = TdxGenerator::new().unwrap();
        let report_data = [0x42; 64];
        let evidence = generator.attest(report_data).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let verifier = dcap_qvl::verify::QuoteVerifier::new(generator.root_ca_der());
        let verified = verifier
            .verify(&evidence.quote, &evidence.collateral, now)
            .unwrap();
        assert_eq!(verified.report.as_td10().unwrap().report_data, report_data);
        assert!(
            dcap_qvl::verify::QuoteVerifier::new(TdxGenerator::new().unwrap().root_ca_der())
                .verify(&evidence.quote, &evidence.collateral, now)
                .is_err()
        );
        let mut tampered = evidence.quote.clone();
        tampered[100] ^= 1;
        assert!(verifier
            .verify(&tampered, &evidence.collateral, now)
            .is_err());
        assert!(crate::ensure_report_data(
            &verified.report.as_td10().unwrap().report_data,
            &[0x24; 64]
        )
        .is_err());
    }
}
