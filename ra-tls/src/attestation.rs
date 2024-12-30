//! Attestation functions

use anyhow::{anyhow, Context, Result};
use dcap_qvl::quote::Quote;
use qvl::{quote::Report, verify::VerifiedReport};
use sha2::{Digest as _, Sha384};

use crate::{oids, traits::CertExt};
use cc_eventlog::TdxEventLog as EventLog;

/// The content type of a quote. A CVM should only generate quotes for these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContentType<'a> {
    /// The public key of KMS root CA
    KmsRootCa,
    /// The public key of the RA-TLS certificate
    RaTlsCert,
    /// App defined data
    AppData,
    /// The custom content type
    Custom(&'a str),
}

/// The default hash algorithm used to hash the report data.
pub const DEFAULT_HASH_ALGORITHM: &str = "sha512";

impl QuoteContentType<'_> {
    /// The tag of the content type used in the report data.
    pub fn tag(&self) -> &str {
        match self {
            Self::KmsRootCa => "kms-root-ca",
            Self::RaTlsCert => "ratls-cert",
            Self::AppData => "app-data",
            Self::Custom(tag) => tag,
        }
    }

    /// Convert the content to the report data.
    pub fn to_report_data(&self, content: &[u8]) -> [u8; 64] {
        self.to_report_data_with_hash(content, "")
            .expect("sha512 hash should not fail")
    }

    /// Convert the content to the report data with a specific hash algorithm.
    pub fn to_report_data_with_hash(&self, content: &[u8], hash: &str) -> Result<[u8; 64]> {
        macro_rules! do_hash {
            ($hash: ty) => {{
                // The format is:
                // hash(<tag>:<content>)
                let mut hasher = <$hash>::new();
                hasher.update(self.tag().as_bytes());
                hasher.update(b":");
                hasher.update(content);
                let output = hasher.finalize();

                let mut padded = [0u8; 64];
                padded[..output.len()].copy_from_slice(&output);
                padded
            }};
        }
        let hash = if hash.is_empty() {
            DEFAULT_HASH_ALGORITHM
        } else {
            hash
        };
        let output = match hash {
            "sha256" => do_hash!(sha2::Sha256),
            "sha384" => do_hash!(sha2::Sha384),
            "sha512" => do_hash!(sha2::Sha512),
            "sha3-256" => do_hash!(sha3::Sha3_256),
            "sha3-384" => do_hash!(sha3::Sha3_384),
            "sha3-512" => do_hash!(sha3::Sha3_512),
            "keccak256" => do_hash!(sha3::Keccak256),
            "keccak384" => do_hash!(sha3::Keccak384),
            "keccak512" => do_hash!(sha3::Keccak512),
            "raw" => content.try_into().ok().context("invalid content length")?,
            _ => anyhow::bail!("invalid hash algorithm"),
        };
        Ok(output)
    }
}

/// Attestation data
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Quote
    pub quote: Vec<u8>,
    /// Raw event log
    pub raw_event_log: Vec<u8>,
    /// Event log
    pub event_log: Vec<EventLog>,
    /// Verified report
    pub verified_report: Option<VerifiedReport>,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(quote: Vec<u8>, raw_event_log: Vec<u8>) -> Result<Self> {
        let event_log: Vec<EventLog> = if !raw_event_log.is_empty() {
            serde_json::from_slice(&raw_event_log).context("invalid event log")?
        } else {
            vec![]
        };
        Ok(Self {
            quote,
            raw_event_log,
            event_log,
            verified_report: None,
        })
    }

    /// Extract attestation data from a certificate
    pub fn from_cert(cert: &impl CertExt) -> Result<Option<Self>> {
        Self::from_ext_getter(|oid| cert.get_extension(oid))
    }

    /// From an extension getter
    pub fn from_ext_getter(
        get_ext: impl Fn(&[u64]) -> Result<Option<Vec<u8>>>,
    ) -> Result<Option<Self>> {
        macro_rules! read_ext_bytes {
            ($oid:expr) => {
                get_ext($oid)?
                    .map(|v| yasna::parse_der(&v, |reader| reader.read_bytes()))
                    .transpose()?
            };
        }

        let quote = match read_ext_bytes!(oids::PHALA_RATLS_QUOTE) {
            Some(v) => v,
            None => return Ok(None),
        };
        let raw_event_log = read_ext_bytes!(oids::PHALA_RATLS_EVENT_LOG).unwrap_or_default();
        Self::new(quote, raw_event_log).map(Some)
    }

    /// Decode the quote
    pub fn decode_quote(&self) -> Result<Quote> {
        Quote::parse(&self.quote)
    }

    fn find_event(&self, imr: u32, ad: &str) -> Result<EventLog> {
        for event in &self.event_log {
            if event.imr == imr && event.event == ad {
                return Ok(event.clone());
            }
        }
        Err(anyhow!("event {ad} not found"))
    }

    /// Replay event logs
    pub fn replay_event_logs(&self) -> Result<[[u8; 48]; 4]> {
        replay_event_logs(&self.event_log)
    }

    /// Return true if the quote is verified
    pub fn is_verified(&self) -> bool {
        self.verified_report.is_some()
    }

    fn find_event_payload(&self, event: &str) -> Result<Vec<u8>> {
        self.find_event(3, event).map(|event| event.event_payload)
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event(3, "app-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event(3, "instance-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_compose_hash(&self) -> Result<String> {
        let event = self.find_event(3, "compose-hash").or_else(|_| {
            // Old images use this event name
            self.find_event(3, "upgraded-app-id")
        })?;
        Ok(hex::encode(&event.event_payload))
    }

    /// Decode the app info from the event log
    pub fn decode_app_info(&self) -> Result<AppInfo> {
        Ok(AppInfo {
            app_id: self.find_event_payload("app-id")?,
            compose_hash: self.find_event_payload("compose-hash")?,
            instance_id: self.find_event_payload("instance-id")?,
            device_id: self.find_event_payload("device-id")?,
            rootfs_hash: self.find_event_payload("rootfs-hash")?,
        })
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event(3, "rootfs-hash")
            .map(|event| hex::encode(event.digest))
    }

    /// Decode the report data in the quote
    pub fn decode_report_data(&self) -> Result<[u8; 64]> {
        match self.decode_quote()?.report {
            Report::SgxEnclave(report) => Ok(report.report_data),
            Report::TD10(report) => Ok(report.report_data),
            Report::TD15(report) => Ok(report.base.report_data),
        }
    }

    /// Ensure the quote is for the RA-TLS public key
    pub fn ensure_quote_for_ra_tls_pubkey(&self, pubkey: &[u8]) -> Result<()> {
        let report_data = self.decode_report_data()?;
        let expected_report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
        if report_data != expected_report_data {
            return Err(anyhow!("report data mismatch"));
        }
        Ok(())
    }
}

/// Information about the app extracted from event log
pub struct AppInfo {
    /// App ID
    pub app_id: Vec<u8>,
    /// SHA256 of the app compose file
    pub compose_hash: Vec<u8>,
    /// ID of the CVM instance
    pub instance_id: Vec<u8>,
    /// ID of the device
    pub device_id: Vec<u8>,
    /// Rootfs hash
    pub rootfs_hash: Vec<u8>,
}

/// Replay event logs
pub fn replay_event_logs(eventlog: &[EventLog]) -> Result<[[u8; 48]; 4]> {
    let mut rtmrs = [[0u8; 48]; 4];
    for idx in 0..4 {
        let mut mr = [0u8; 48];

        for event in eventlog.iter() {
            if event.imr == idx {
                let mut hasher = Sha384::new();
                hasher.update(mr);
                hasher.update(event.digest);
                mr = hasher.finalize().into();
            }
        }

        rtmrs[idx as usize] = mr;
    }

    Ok(rtmrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_report_data_with_hash() {
        let content_type = QuoteContentType::AppData;
        let content = b"test content";

        let report_data = content_type.to_report_data(content);
        assert_eq!(hex::encode(report_data), "7ea0b744ed5e9c0c83ff9f575668e1697652cd349f2027cdf26f918d4c53e8cd50b5ea9b449b4c3d50e20ae00ec29688d5a214e8daff8a10041f5d624dae8a01");

        // Test SHA-256
        let result = content_type
            .to_report_data_with_hash(content, "sha256")
            .unwrap();
        assert_eq!(result[32..], [0u8; 32]); // Check padding
        assert_ne!(result[..32], [0u8; 32]); // Check hash is non-zero

        // Test SHA-384
        let result = content_type
            .to_report_data_with_hash(content, "sha384")
            .unwrap();
        assert_eq!(result[48..], [0u8; 16]); // Check padding
        assert_ne!(result[..48], [0u8; 48]); // Check hash is non-zero

        // Test default
        let result = content_type.to_report_data_with_hash(content, "").unwrap();
        assert_ne!(result, [0u8; 64]); // Should fill entire buffer

        // Test raw content
        let exact_content = [42u8; 64];
        let result = content_type
            .to_report_data_with_hash(&exact_content, "raw")
            .unwrap();
        assert_eq!(result, exact_content);

        // Test invalid raw content length
        let invalid_content = [42u8; 65];
        assert!(content_type
            .to_report_data_with_hash(&invalid_content, "raw")
            .is_err());

        // Test invalid hash algorithm
        assert!(content_type
            .to_report_data_with_hash(content, "invalid")
            .is_err());
    }
}
