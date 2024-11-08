//! Attestation functions

use anyhow::{anyhow, Context, Result};
use dcap_qvl::quote::Quote;
use qvl::{quote::Report, verify::VerifiedReport};

use crate::{event_log::EventLog, oids, traits::CertExt};

/// The content type of a quote. A CVM should only generate quotes for these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContentType {
    /// The public key of KMS root CA
    KmsRootCa,
    /// The public key of the RA-TLS certificate
    RaTlsCert,
}

impl QuoteContentType {
    /// The tag of the content type used in the report data.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::KmsRootCa => "kms-root-ca",
            Self::RaTlsCert => "ratls-cert",
        }
    }

    /// Convert the content to the report data.
    pub fn to_report_data(&self, content: &[u8]) -> [u8; 64] {
        use sha2::Digest;
        // The format is:
        // sha2_512(<tag>:<content>)
        let mut hasher = sha2::Sha512::new();
        hasher.update(self.tag().as_bytes());
        hasher.update(b":");
        hasher.update(content);
        hasher.finalize().into()
    }
}

/// Attestation data
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Quote
    pub quote: Vec<u8>,
    /// Event log
    pub event_log: Vec<u8>,
    /// Verified report
    pub verified_report: Option<VerifiedReport>,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(quote: Vec<u8>, event_log: Vec<u8>) -> Self {
        Self {
            quote,
            event_log,
            verified_report: None,
        }
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
        let event_log = read_ext_bytes!(oids::PHALA_RATLS_EVENT_LOG).unwrap_or_default();

        Ok(Some(Self {
            quote,
            event_log,
            verified_report: None,
        }))
    }

    /// Decode the quote
    pub fn decode_quote(&self) -> Result<Quote> {
        Quote::parse(&self.quote)
    }

    fn find_event(&self, imr: u32, ad: &str) -> Result<EventLog> {
        let event_log = String::from_utf8(self.event_log.clone()).context("invalid event log")?;
        for line in event_log.lines() {
            let event = serde_json::from_str::<EventLog>(line)?;
            if event.imr == imr && event.associated_data == ad {
                return Ok(event);
            }
        }
        Err(anyhow!("event {ad} not found"))
    }

    /// Return true if the quote is verified
    pub fn is_verified(&self) -> bool {
        self.verified_report.is_some()
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event(3, "app-id")
            .map(|event| truncate(&event.digest, 40).to_string())
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event(3, "instance-id")
            .map(|event| truncate(&event.digest, 40).to_string())
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_upgraded_app_id(&self) -> Result<String> {
        self.find_event(3, "upgraded-app-id")
            .map(|event| truncate(&event.digest, 40).to_string())
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event(3, "rootfs-hash")
            .map(|event| truncate(&event.digest, 64).to_string())
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
            return Err(anyhow!("invalid quote"));
        }
        Ok(())
    }
}

fn truncate(s: &str, len: usize) -> &str {
    if s.len() > len {
        &s[..len]
    } else {
        s
    }
}
