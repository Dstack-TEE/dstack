// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal DER walking for the two OCSP structures the proxy needs:
//! extracting CertIDs from a request (cache key) and the
//! thisUpdate/nextUpdate window from a response (cache expiry). Only
//! low-tag-number, definite-length DER is accepted, which covers everything
//! an OCSP responder is allowed to send.

use anyhow::{bail, Context, Result};

pub const TAG_ENUMERATED: u8 = 0x0a;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_OCTET_STRING: u8 = 0x04;

/// One parsed TLV element. `raw` covers the full TLV, `content` only the V.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        read_all(self.content)
    }
}

/// Read one TLV element, returning it and the remaining bytes.
pub fn read_tlv(buf: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = buf.split_first().context("truncated DER: missing tag")?;
    if tag & 0x1f == 0x1f {
        bail!("multi-byte DER tags are not supported");
    }
    let (&len0, mut rest) = rest
        .split_first()
        .context("truncated DER: missing length")?;
    let len = if len0 & 0x80 == 0 {
        len0 as usize
    } else {
        let n = (len0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            bail!("invalid DER long-form length");
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = len
                .checked_mul(256)
                .and_then(|l| l.checked_add(b as usize))
                .context("DER length overflow")?;
        }
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        bail!("truncated DER: content shorter than declared length");
    }
    let header_len = buf.len() - rest.len();
    let tlv = Tlv {
        tag,
        content: &rest[..len],
        raw: &buf[..header_len + len],
    };
    Ok((tlv, &rest[len..]))
}

fn read_all(mut buf: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (tlv, rest) = read_tlv(buf)?;
        out.push(tlv);
        buf = rest;
    }
    Ok(out)
}

fn expect_tag(tlv: &Tlv, tag: u8, what: &str) -> Result<()> {
    if tlv.tag != tag {
        bail!(
            "expected {what} (tag 0x{tag:02x}), got tag 0x{:02x}",
            tlv.tag
        );
    }
    Ok(())
}

/// Extract the raw CertID TLVs from a DER OCSP request. They fully determine
/// the revocation query (issuer name/key hashes + serial), so they are the
/// cache key; the per-request nonce in requestExtensions is ignored.
pub fn ocsp_request_cert_ids(request_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (outer, rest) = read_tlv(request_der).context("invalid OCSP request")?;
    if !rest.is_empty() {
        bail!("trailing bytes after OCSP request");
    }
    expect_tag(&outer, TAG_SEQUENCE, "OCSPRequest")?;
    let tbs = outer
        .children()?
        .into_iter()
        .next()
        .context("OCSPRequest has no tbsRequest")?;
    expect_tag(&tbs, TAG_SEQUENCE, "tbsRequest")?;
    // Skip optional [0] version and [1] requestorName; requestList is the
    // first SEQUENCE child.
    let request_list = tbs
        .children()?
        .into_iter()
        .find(|child| child.tag == TAG_SEQUENCE)
        .context("tbsRequest has no requestList")?;
    let mut cert_ids = Vec::new();
    for request in request_list.children()? {
        expect_tag(&request, TAG_SEQUENCE, "Request")?;
        let cert_id = request
            .children()?
            .into_iter()
            .next()
            .context("Request has no reqCert")?;
        expect_tag(&cert_id, TAG_SEQUENCE, "reqCert")?;
        cert_ids.push(cert_id.raw.to_vec());
    }
    if cert_ids.is_empty() {
        bail!("OCSP request carries no CertID");
    }
    Ok(cert_ids)
}

/// The validity window (thisUpdate, nextUpdate) the response asserts for
/// `cert_id`. Returns Ok(None) when the responder signalled a non-successful
/// status or the response cannot be parsed — callers must then skip caching
/// but still relay the body.
pub fn ocsp_response_validity(
    response_der: &[u8],
    cert_id: &[u8],
) -> Result<Option<(i64, Option<i64>)>> {
    match response_validity_inner(response_der, cert_id) {
        Ok(window) => Ok(Some(window)),
        Err(err) => {
            tracing::debug!("not caching unparseable OCSP response: {err:#}");
            Ok(None)
        }
    }
}

fn response_validity_inner(response_der: &[u8], cert_id: &[u8]) -> Result<(i64, Option<i64>)> {
    let (outer, rest) = read_tlv(response_der).context("invalid OCSP response")?;
    if !rest.is_empty() {
        bail!("trailing bytes after OCSP response");
    }
    expect_tag(&outer, TAG_SEQUENCE, "OCSPResponse")?;
    let mut parts = outer.children()?.into_iter();
    let status = parts.next().context("OCSPResponse has no status")?;
    expect_tag(&status, TAG_ENUMERATED, "responseStatus")?;
    if status.content != [0] {
        bail!("OCSP responder status is not successful");
    }
    let response_bytes = parts.next().context("OCSPResponse has no responseBytes")?;
    expect_tag(&response_bytes, 0xa0, "responseBytes")?;
    let rb = response_bytes
        .children()?
        .into_iter()
        .next()
        .context("empty responseBytes")?;
    expect_tag(&rb, TAG_SEQUENCE, "ResponseBytes")?;
    let mut rb_parts = rb.children()?.into_iter();
    rb_parts.next(); // responseType OID
    let basic = rb_parts.next().context("ResponseBytes has no response")?;
    expect_tag(&basic, TAG_OCTET_STRING, "BasicOCSPResponse wrapper")?;

    let (basic, _) = read_tlv(basic.content).context("invalid BasicOCSPResponse")?;
    expect_tag(&basic, TAG_SEQUENCE, "BasicOCSPResponse")?;
    let tbs = basic
        .children()?
        .into_iter()
        .next()
        .context("BasicOCSPResponse has no tbsResponseData")?;
    expect_tag(&tbs, TAG_SEQUENCE, "tbsResponseData")?;
    // Skip optional [0] version, responderID ([1]/[2]) and producedAt;
    // responses is the first SEQUENCE child.
    let responses = tbs
        .children()?
        .into_iter()
        .find(|child| child.tag == TAG_SEQUENCE)
        .context("tbsResponseData has no responses")?;
    for single in responses.children()? {
        expect_tag(&single, TAG_SEQUENCE, "SingleResponse")?;
        let fields = single.children()?;
        let Some(id) = fields.first() else { continue };
        expect_tag(id, TAG_SEQUENCE, "certID")?;
        if id.raw != cert_id {
            continue;
        }
        let this_update = fields
            .iter()
            .find(|field| field.tag == TAG_GENERALIZED_TIME)
            .context("SingleResponse has no thisUpdate")?;
        let next_update = fields
            .iter()
            .find(|field| field.tag == 0xa0)
            .map(|ext| -> Result<i64> {
                let inner = ext
                    .children()?
                    .into_iter()
                    .next()
                    .context("empty nextUpdate")?;
                expect_tag(&inner, TAG_GENERALIZED_TIME, "nextUpdate")?;
                parse_generalized_time(inner.content)
            })
            .transpose()?;
        return Ok((parse_generalized_time(this_update.content)?, next_update));
    }
    bail!("response contains no SingleResponse for the requested CertID")
}

/// Parse `YYYYMMDDHHMMSSZ` (GeneralizedTime as OCSP responders emit it).
pub fn parse_generalized_time(bytes: &[u8]) -> Result<i64> {
    let text = std::str::from_utf8(bytes).context("GeneralizedTime is not ASCII")?;
    let digits = text.strip_suffix('Z').unwrap_or(text);
    if digits.len() != 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        bail!("unsupported GeneralizedTime format: {text}");
    }
    let num = |range: std::ops::Range<usize>| digits[range].parse::<i64>();
    let (Ok(year), Ok(month), Ok(day), Ok(hour), Ok(min), Ok(sec)) = (
        num(0..4),
        num(4..6),
        num(6..8),
        num(8..10),
        num(10..12),
        num(12..14),
    ) else {
        bail!("unparseable GeneralizedTime: {text}");
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        bail!("out-of-range GeneralizedTime: {text}");
    }
    // days-from-civil (Howard Hinnant's algorithm), no leap seconds.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(days * 86400 + hour * 3600 + min * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a tiny synthetic OCSP request/response pair with a hand-rolled
    // DER writer; the structures mirror RFC 6960.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            out.push(0x81);
            out.push(content.len() as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn cert_id(serial: u8) -> Vec<u8> {
        let mut content = tlv(0x30, &[]); // hashAlgorithm
        content.extend(tlv(0x04, b"issuer-name-hash"));
        content.extend(tlv(0x04, b"issuer-key-hash"));
        content.extend(tlv(0x02, &[serial]));
        tlv(0x30, &content)
    }

    fn ocsp_request(cert_ids: &[Vec<u8>]) -> Vec<u8> {
        let requests = cert_ids
            .iter()
            .map(|id| tlv(0x30, id))
            .flatten()
            .collect::<Vec<_>>();
        let mut tbs = tlv(0xa0, &tlv(0x02, &[1])); // version [0]
        tbs.extend(tlv(0x30, &requests));
        tbs.extend(tlv(0xa2, &[])); // requestExtensions [2] (nonce would live here)
        tlv(0x30, &tlv(0x30, &tbs))
    }

    fn single_response(id: &[u8], this: &[u8], next: Option<&[u8]>) -> Vec<u8> {
        let mut fields = id.to_vec();
        fields.extend(tlv(0x80, &[])); // certStatus good
        fields.extend(tlv(TAG_GENERALIZED_TIME, this));
        if let Some(next) = next {
            fields.extend(tlv(0xa0, &tlv(TAG_GENERALIZED_TIME, next)));
        }
        tlv(0x30, &fields)
    }

    fn ocsp_response(singles: &[Vec<u8>]) -> Vec<u8> {
        let responses = singles.iter().flatten().copied().collect::<Vec<_>>();
        let mut tbs_data = tlv(0xa1, &tlv(0x04, b"responder")); // responderID byName
        tbs_data.extend(tlv(TAG_GENERALIZED_TIME, b"20260701000000Z"));
        tbs_data.extend(tlv(0x30, &responses));
        let mut basic = tlv(0x30, &tbs_data);
        basic.extend(tlv(0x30, &[])); // signatureAlgorithm
        basic.extend(tlv(0x03, &[0])); // signature BIT STRING
        let mut response_bytes = tlv(
            0x06,
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
        );
        response_bytes.extend(tlv(0x04, &tlv(0x30, &basic)));
        let mut body = tlv(TAG_ENUMERATED, &[0]);
        body.extend(tlv(0xa0, &tlv(0x30, &response_bytes)));
        tlv(0x30, &body)
    }

    #[test]
    fn extracts_cert_ids_from_request() {
        let ids = vec![cert_id(7), cert_id(8)];
        let parsed = ocsp_request_cert_ids(&ocsp_request(&ids)).unwrap();
        assert_eq!(parsed, ids);
    }

    #[test]
    fn extracts_validity_window_for_matching_cert_id() {
        let (wanted, other) = (cert_id(1), cert_id(2));
        let response = ocsp_response(&[
            single_response(&other, b"20260701000000Z", None),
            single_response(&wanted, b"20260701120000Z", Some(b"20260708120000Z")),
        ]);
        let (this, next) = ocsp_response_validity(&response, &wanted).unwrap().unwrap();
        assert_eq!(this, 1782907200); // 2026-07-01 12:00:00Z
        assert_eq!(next, Some(1783512000)); // 2026-07-08 12:00:00Z
    }

    #[test]
    fn absent_next_update_is_none_not_an_error() {
        let id = cert_id(1);
        let response = ocsp_response(&[single_response(&id, b"20260701120000Z", None)]);
        let (_, next) = ocsp_response_validity(&response, &id).unwrap().unwrap();
        assert_eq!(next, None);
    }

    #[test]
    fn non_successful_responses_are_not_cached() {
        let mut body = tlv(TAG_ENUMERATED, &[3]); // tryLater
        let response = tlv(0x30, &body);
        body.clear();
        assert_eq!(
            ocsp_response_validity(&response, &cert_id(1)).unwrap(),
            None
        );
    }

    #[test]
    fn generalized_time_conversion_matches_known_epoch() {
        assert_eq!(parse_generalized_time(b"19700101000000Z").unwrap(), 0);
        assert_eq!(
            parse_generalized_time(b"20260701120000Z").unwrap(),
            1782907200
        );
        // Leap year boundary: 2024-03-01 is one day after 2024-02-29.
        let feb29 = parse_generalized_time(b"20240229000000Z").unwrap();
        let mar01 = parse_generalized_time(b"20240301000000Z").unwrap();
        assert_eq!(mar01 - feb29, 86400);
    }
}
