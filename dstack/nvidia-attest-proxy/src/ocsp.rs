// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponseValidity {
    this_update: i64,
    next_update: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

/// Derive a cache key from the request's CertID list, excluding the request
/// extensions where the per-request OCSP nonce is encoded.
pub(crate) fn request_cache_key(request: &[u8]) -> Result<String> {
    let outer = parse_single(request, 0x30).context("invalid OCSPRequest")?;
    let mut outer_fields = outer.value;
    let tbs = take_expected(&mut outer_fields, 0x30).context("missing tbsRequest")?;

    let mut tbs_fields = tbs.value;
    while !tbs_fields.is_empty() {
        let field = take_tlv(&mut tbs_fields)?;
        match field.tag {
            // version and requestorName
            0xa0 | 0xa1 => continue,
            // requestList is the first untagged SEQUENCE in TBSRequest.
            0x30 => {
                validate_request_list(field.value)?;
                return Ok(hex::encode(Sha256::digest(field.raw)));
            }
            _ => bail!("unexpected field in OCSP tbsRequest"),
        }
    }
    bail!("OCSP request has no requestList")
}

/// Calculate the deadline for a cache entry. The signed `nextUpdate` value is
/// authoritative; `max_ttl_seconds` can only shorten it. NVIDIA's verifier
/// treats a response without nextUpdate as valid for one hour from thisUpdate,
/// so the proxy mirrors that behavior through `default_ttl_seconds`.
pub(crate) fn response_cache_expiry(
    response: &[u8],
    now: i64,
    max_ttl_seconds: u64,
    default_ttl_seconds: u64,
) -> Result<i64> {
    let validity = response_validity(response)?;
    let default_ttl =
        i64::try_from(default_ttl_seconds).context("default OCSP TTL is too large")?;
    let max_ttl = i64::try_from(max_ttl_seconds).context("maximum OCSP TTL is too large")?;
    let mut expires_at = now.checked_add(max_ttl).context("OCSP TTL overflow")?;
    for item in validity {
        // Do not cache a response which claims to have been produced in the
        // future. The guest performs the authoritative freshness check.
        if item.this_update > now {
            bail!("OCSP response thisUpdate is in the future");
        }
        let signed_expiry = item
            .next_update
            .unwrap_or_else(|| item.this_update.saturating_add(default_ttl));
        expires_at = expires_at.min(signed_expiry);
    }
    if expires_at <= now {
        bail!("OCSP response has expired");
    }
    Ok(expires_at)
}

fn validate_request_list(mut request_list: &[u8]) -> Result<()> {
    if request_list.is_empty() {
        bail!("OCSP requestList is empty");
    }
    while !request_list.is_empty() {
        let request = take_expected(&mut request_list, 0x30)?;
        let mut fields = request.value;
        take_expected(&mut fields, 0x30).context("OCSP Request has no CertID")?;
        // A SingleRequest extension is allowed, but no other trailing fields.
        if !fields.is_empty() {
            take_expected(&mut fields, 0xa0)?;
        }
        if !fields.is_empty() {
            bail!("unexpected field in OCSP Request");
        }
    }
    Ok(())
}

fn response_validity(response: &[u8]) -> Result<Vec<ResponseValidity>> {
    let outer = parse_single(response, 0x30).context("invalid OCSPResponse")?;
    let mut fields = outer.value;
    let status = take_expected(&mut fields, 0x0a).context("missing OCSP responseStatus")?;
    if status.value != [0] {
        bail!("OCSP response is not successful");
    }
    let response_bytes = take_expected(&mut fields, 0xa0).context("missing responseBytes")?;
    let response_bytes = parse_single(response_bytes.value, 0x30)?;
    let mut fields = response_bytes.value;
    take_expected(&mut fields, 0x06).context("missing OCSP responseType")?;
    let basic_der = take_expected(&mut fields, 0x04).context("missing BasicOCSPResponse")?;

    let basic = parse_single(basic_der.value, 0x30).context("invalid BasicOCSPResponse")?;
    let mut fields = basic.value;
    let response_data = take_expected(&mut fields, 0x30).context("missing ResponseData")?;
    let mut fields = response_data.value;

    // Optional version.
    if peek_tag(fields) == Some(0xa0) {
        take_expected(&mut fields, 0xa0)?;
    }
    // responderID is CHOICE [1] Name / [2] KeyHash. It may be encoded as a
    // primitive or constructed context-specific value.
    let responder_id = take_tlv(&mut fields).context("missing responderID")?;
    let responder_id_tag = responder_id.tag & 0x1f;
    if responder_id.tag & 0xc0 != 0x80 || !matches!(responder_id_tag, 1 | 2) {
        bail!("invalid OCSP responderID");
    }
    take_expected(&mut fields, 0x18).context("missing producedAt")?;
    let responses = take_expected(&mut fields, 0x30).context("missing SingleResponses")?;

    let mut single_responses = responses.value;
    let mut validity = Vec::new();
    while !single_responses.is_empty() {
        let single = take_expected(&mut single_responses, 0x30)?;
        let mut fields = single.value;
        take_expected(&mut fields, 0x30).context("SingleResponse has no CertID")?;
        let cert_status = take_tlv(&mut fields).context("SingleResponse has no certStatus")?;
        if cert_status.tag & 0xc0 != 0x80 {
            bail!("invalid OCSP certStatus");
        }
        let this_update = take_expected(&mut fields, 0x18).context("missing thisUpdate")?;
        let this_update = parse_generalized_time(this_update.value)?;
        let next_update = if peek_tag(fields) == Some(0xa0) {
            let explicit = take_expected(&mut fields, 0xa0)?;
            let value = parse_single(explicit.value, 0x18).context("invalid nextUpdate")?;
            Some(parse_generalized_time(value.value)?)
        } else {
            None
        };
        // singleExtensions may follow nextUpdate.
        if !fields.is_empty() {
            take_expected(&mut fields, 0xa1)?;
        }
        if !fields.is_empty() {
            bail!("unexpected field in SingleResponse");
        }
        validity.push(ResponseValidity {
            this_update,
            next_update,
        });
    }
    if validity.is_empty() {
        bail!("OCSP response has no SingleResponse")
    }
    Ok(validity)
}

fn parse_generalized_time(value: &[u8]) -> Result<i64> {
    let value = std::str::from_utf8(value).context("GeneralizedTime is not ASCII")?;
    for format in ["%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S%.fZ"] {
        if let Ok(time) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(time.and_utc().timestamp());
        }
    }
    for format in ["%Y%m%d%H%M%S%z", "%Y%m%d%H%M%S%.f%z"] {
        if let Ok(time) = DateTime::parse_from_str(value, format) {
            return Ok(time.timestamp());
        }
    }
    bail!("unsupported GeneralizedTime: {value}")
}

fn parse_single(input: &[u8], expected_tag: u8) -> Result<Tlv<'_>> {
    let mut input_ref = input;
    let tlv = take_expected(&mut input_ref, expected_tag)?;
    if !input_ref.is_empty() {
        bail!("trailing DER data");
    }
    Ok(tlv)
}

fn peek_tag(input: &[u8]) -> Option<u8> {
    input.first().copied()
}

fn take_expected<'a>(input: &mut &'a [u8], expected_tag: u8) -> Result<Tlv<'a>> {
    let tlv = take_tlv(input)?;
    if tlv.tag != expected_tag {
        bail!(
            "unexpected DER tag: expected {expected_tag:#04x}, got {:#04x}",
            tlv.tag
        );
    }
    Ok(tlv)
}

fn take_tlv<'a>(input: &mut &'a [u8]) -> Result<Tlv<'a>> {
    let original = *input;
    if original.len() < 2 {
        bail!("truncated DER value");
    }
    let tag = original[0];
    if tag & 0x1f == 0x1f {
        bail!("high-tag-number DER values are unsupported");
    }
    let first_len = original[1];
    let (header_len, value_len) = if first_len & 0x80 == 0 {
        (2usize, usize::from(first_len))
    } else {
        let count = usize::from(first_len & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || original.len() < 2 + count {
            bail!("invalid DER length");
        }
        if original[2] == 0 {
            bail!("non-canonical DER length");
        }
        let mut value_len = 0usize;
        for byte in &original[2..2 + count] {
            value_len = value_len
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .context("DER length overflow")?;
        }
        if value_len < 128 {
            bail!("non-canonical DER length");
        }
        (2 + count, value_len)
    };
    let total_len = header_len
        .checked_add(value_len)
        .context("DER value length overflow")?;
    if original.len() < total_len {
        bail!("truncated DER value");
    }
    let raw = &original[..total_len];
    let value = &raw[header_len..];
    *input = &original[total_len..];
    Ok(Tlv { tag, value, raw })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap();
            result.push(0x80 | (bytes.len() - first) as u8);
            result.extend_from_slice(&bytes[first..]);
        }
        result.extend_from_slice(value);
        result
    }

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    fn request(nonce: u8) -> Vec<u8> {
        let algorithm = sequence(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a])]);
        let cert_id = sequence(&[
            algorithm,
            der(0x04, &[1; 20]),
            der(0x04, &[2; 20]),
            der(0x02, &[3]),
        ]);
        let request = sequence(&[cert_id]);
        let list = sequence(&[request]);
        // The exact extension contents do not matter to the cache key. They
        // model requestExtensions [2], where the OCSP nonce lives.
        let extensions = der(0xa2, &sequence(&[der(0x04, &[nonce; 16])]));
        sequence(&[sequence(&[list, extensions])])
    }

    fn response(this_update: &str, next_update: Option<&str>) -> Vec<u8> {
        let cert_id = sequence(&[der(0x02, &[1])]);
        let mut single = vec![cert_id, der(0x80, &[]), der(0x18, this_update.as_bytes())];
        if let Some(next_update) = next_update {
            single.push(der(0xa0, &der(0x18, next_update.as_bytes())));
        }
        let responses = sequence(&[sequence(&single)]);
        let response_data = sequence(&[
            der(0x82, &[7; 20]),
            der(0x18, b"20260716120000Z"),
            responses,
        ]);
        let basic = sequence(&[
            response_data,
            sequence(&[der(0x06, &[0x2a, 0x03])]),
            der(0x03, &[0]),
        ]);
        let response_bytes = sequence(&[
            der(
                0x06,
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
            ),
            der(0x04, &basic),
        ]);
        sequence(&[der(0x0a, &[0]), der(0xa0, &response_bytes)])
    }

    #[test]
    fn cache_key_ignores_ocsp_nonce() {
        let nonce = std::process::id() as u8;
        assert_eq!(
            request_cache_key(&request(nonce)).unwrap(),
            request_cache_key(&request(nonce.wrapping_add(1))).unwrap()
        );
    }

    #[test]
    fn cache_key_rejects_malformed_requests() {
        assert!(request_cache_key(&[0x30, 0x01, 0]).is_err());
    }

    #[test]
    fn expiry_honors_next_update_and_max_ttl() {
        let now = 1_784_202_600; // 2026-07-16T11:50:00Z
        let response = response("20260716114500Z", Some("20260716123000Z"));
        assert_eq!(
            response_cache_expiry(&response, now, 86_400, 3_600).unwrap(),
            1_784_205_000
        );
        assert_eq!(
            response_cache_expiry(&response, now, 600, 3_600).unwrap(),
            now + 600
        );
    }

    #[test]
    fn expiry_without_next_update_uses_default_ttl() {
        let now = 1_784_202_600;
        let response = response("20260716114500Z", None);
        assert_eq!(
            response_cache_expiry(&response, now, 86_400, 3_600).unwrap(),
            1_784_205_900
        );
    }

    #[test]
    fn expired_response_is_not_cacheable() {
        let response = response("20260716100000Z", Some("20260716110000Z"));
        assert!(response_cache_expiry(&response, 1_784_202_600, 86_400, 3_600).is_err());
    }
}
