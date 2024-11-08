use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ra_tls::{
    attestation::Attestation,
    qvl::{self, verify::VerifiedReport},
};
use rocket::{
    data::{ByteUnit, Limits, ToByteUnit},
    http::{ContentType, Status},
    mtls::{oid::Oid, Certificate},
    response::status::Custom,
    Data,
};
use tracing::info;

use crate::RpcCall;

#[derive(Debug, Clone)]
pub struct QuoteVerifier {
    pccs_url: String,
    timeout: Duration,
}

impl QuoteVerifier {
    pub fn new(pccs_url: String) -> Self {
        Self {
            pccs_url,
            timeout: Duration::from_secs(60),
        }
    }

    pub async fn verify_quote(&self, quote: &[u8]) -> Result<VerifiedReport> {
        let collateral = qvl::collateral::get_collateral(&self.pccs_url, quote, self.timeout)
            .await
            .context("failed to get collateral")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("failed to get current time")?
            .as_secs();
        qvl::verify::verify(quote, &collateral, now)
            .ok()
            .context("invalid quote")
    }
}

async fn read_data(data: Data<'_>, limit: ByteUnit) -> Result<Vec<u8>> {
    let stream = data.open(limit);
    let data = stream.into_bytes().await.context("failed to read data")?;
    if !data.is_complete() {
        anyhow::bail!("payload too large");
    }
    Ok(data.into_inner())
}

fn limit_for_method(method: &str, limits: &Limits) -> ByteUnit {
    if let Some(v) = limits.get(method) {
        return v;
    }
    10.mebibytes()
}

pub async fn handle_prpc<S, Call: RpcCall<S>>(
    state: &S,
    certificate: Option<Certificate<'_>>,
    quote_verifier: Option<&QuoteVerifier>,
    method: &str,
    data: Option<Data<'_>>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>> {
    let mut attestation = certificate.map(extract_attestation).transpose()?.flatten();
    let todo = "verified attestation needs to be a distinct type";
    if let (Some(quote_verifier), Some(attestation)) = (quote_verifier, &mut attestation) {
        let verified_report = quote_verifier
            .verify_quote(&attestation.quote)
            .await
            .context("invalid quote")?;
        attestation.verified_report = Some(verified_report);
        info!("the ra quote is verified");
    } else if attestation.is_some() {
        info!("the ra quote is not verified");
    }
    let data = match data {
        Some(data) => {
            let limit = limit_for_method(method, limits);
            let todo = "confirm this would not truncate the data";
            read_data(data, limit)
                .await
                .context("failed to read data")?
        }
        None => vec![],
    };
    let json = json || content_type.map(|t| t.is_json()).unwrap_or(false);
    let call = Call::construct(state, attestation).context("failed to construct call")?;
    let data = data.to_vec();
    let (status_code, output) = call.call(method.to_string(), data, json).await;
    Ok(Custom(Status::new(status_code), output))
}

pub fn extract_attestation(cert: Certificate<'_>) -> Result<Option<Attestation>> {
    let attestation = Attestation::from_ext_getter(|oid| {
        let oid = Oid::from(oid).ok().context("Invalid OID")?;
        let Some(ext) = cert
            .get_extension_unique(&oid)
            .context("Extension not found")?
        else {
            return Ok(None);
        };
        Ok(Some(ext.value.to_vec()))
    })?;
    let todo = "verify the attestation";
    let Some(attestation) = attestation else {
        return Ok(None);
    };
    let pubkey = cert.public_key().raw;
    attestation
        .ensure_quote_for_ra_tls_pubkey(pubkey)
        .context("invalid quote")?;
    Ok(Some(attestation))
}
