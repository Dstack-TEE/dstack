//! Attestation functions

use anyhow::{anyhow, Context, Result};
use dcap_qvl::quote::Quote;

use crate::{event_log::EventLog, oids, traits::CertExt};

/// Attestation data
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Quote
    pub quote: Vec<u8>,
    /// Event log
    pub event_log: Vec<u8>,
    /// Application info
    pub app_info: Vec<u8>,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(quote: Vec<u8>, event_log: Vec<u8>, app_info: Vec<u8>) -> Self {
        Self {
            quote,
            event_log,
            app_info,
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
        let app_info = read_ext_bytes!(oids::PHALA_RATLS_APP_INFO).unwrap_or_default();

        Ok(Some(Self {
            quote,
            event_log,
            app_info,
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

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event(3, "app-id")
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
}

fn truncate(s: &str, len: usize) -> &str {
    if s.len() > len {
        &s[..len]
    } else {
        s
    }
}
