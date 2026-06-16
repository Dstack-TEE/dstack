// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP attestation verification helpers.
//!
//! This module implements the hardware report verification slice: certificate
//! normalization, AMD ARK/ASK/VCEK chain verification, report signature checks,
//! report_data binding, and invariant SNP policy checks. KMS/app authorization
//! must still bind the verified measurement to app/config identity before
//! production key release.

use anyhow::{bail, Context, Result};
use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::{guest::AttestationReport, host::TcbVersion};

const ASK_CERT_GUID: [u8; 16] = [
    0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82,
];
const VCEK_CERT_GUID: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
const VLEK_CERT_GUID: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];
const CERT_TABLE_ENTRY_SIZE: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdSnpProduct {
    Milan,
    Genoa,
    Turin,
}

impl AmdSnpProduct {
    fn kds_name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            // AMD KDS canonicalizes Genoa-family parts such as Bergamo and
            // Siena under the Genoa endpoint.
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }

    fn builtin_ark(self) -> CertBytes {
        let bytes = match self {
            Self::Milan => builtin::milan::ARK,
            Self::Genoa => builtin::genoa::ARK,
            Self::Turin => builtin::turin::ARK,
        };
        CertBytes {
            bytes: bytes.to_vec(),
            encoding: CertEncoding::Pem,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AmdSnpTcbVersion {
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl From<TcbVersion> for AmdSnpTcbVersion {
    fn from(value: TcbVersion) -> Self {
        Self {
            fmc: value.fmc,
            bootloader: value.bootloader,
            tee: value.tee,
            snp: value.snp,
            microcode: value.microcode,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AmdSnpTcbInfo {
    pub current: AmdSnpTcbVersion,
    pub reported: AmdSnpTcbVersion,
    pub committed: AmdSnpTcbVersion,
    pub launch: AmdSnpTcbVersion,
}

impl AmdSnpTcbInfo {
    pub fn from_report(report: &AttestationReport) -> Self {
        Self {
            current: report.current_tcb.into(),
            reported: report.reported_tcb.into(),
            committed: report.committed_tcb.into(),
            launch: report.launch_tcb.into(),
        }
    }

    pub fn tcb_status(&self) -> &'static str {
        if self.current == self.reported
            && self.committed == self.reported
            && self.launch == self.reported
        {
            "UpToDate"
        } else {
            "OutOfDate"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAmdSnpReport {
    pub measurement: [u8; 48],
    pub report_data: [u8; 64],
    pub host_data: [u8; 32],
    pub chip_id: [u8; 64],
    pub tcb_info: AmdSnpTcbInfo,
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedAmdSnpReport {
    pub measurement: [u8; 48],
    pub report_data: [u8; 64],
    pub host_data: [u8; 32],
    pub chip_id: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertEncoding {
    Pem,
    Der,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertBytes {
    bytes: Vec<u8>,
    encoding: CertEncoding,
}

pub struct AmdSnpAttestationInput<'a> {
    pub report: &'a [u8],
    pub ask_pem: &'a [u8],
    pub vcek_pem: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmdKdsCollateral {
    ark: CertBytes,
    ask: CertBytes,
    vcek: CertBytes,
}

pub fn verify_amd_snp_attestation(
    input: &AmdSnpAttestationInput<'_>,
) -> Result<VerifiedAmdSnpReport> {
    verify_amd_snp_attestation_with_certs(
        input.report,
        CertBytes {
            bytes: input.ask_pem.to_vec(),
            encoding: CertEncoding::Pem,
        },
        CertBytes {
            bytes: input.vcek_pem.to_vec(),
            encoding: CertEncoding::Pem,
        },
    )
}

pub fn parse_amd_snp_report(report_bytes: &[u8]) -> Result<ParsedAmdSnpReport> {
    if report_bytes.len() != 1184 {
        bail!(
            "invalid amd sev-snp report length: expected 1184 bytes, got {}",
            report_bytes.len()
        );
    }
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|err| anyhow::anyhow!("failed to parse amd sev-snp report: {err}"))?;
    parsed_amd_snp_report_from_report(&report)
}

fn parsed_amd_snp_report_from_report(report: &AttestationReport) -> Result<ParsedAmdSnpReport> {
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(
        report
            .measurement
            .as_ref()
            .get(..48)
            .context("amd sev-snp measurement too short")?,
    );
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(
        report
            .report_data
            .as_ref()
            .get(..64)
            .context("amd sev-snp report_data too short")?,
    );
    let mut host_data = [0u8; 32];
    host_data.copy_from_slice(
        report
            .host_data
            .as_ref()
            .get(..32)
            .context("amd sev-snp host_data too short")?,
    );
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(
        report
            .chip_id
            .as_ref()
            .get(..64)
            .context("amd sev-snp chip_id too short")?,
    );

    Ok(ParsedAmdSnpReport {
        measurement,
        report_data,
        host_data,
        chip_id,
    })
}

fn verify_amd_snp_attestation_with_certs(
    report_bytes: &[u8],
    ask_bytes: CertBytes,
    vcek_bytes: CertBytes,
) -> Result<VerifiedAmdSnpReport> {
    if report_bytes.len() != 1184 {
        bail!(
            "invalid amd sev-snp report length: expected 1184 bytes, got {}",
            report_bytes.len()
        );
    }
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|err| anyhow::anyhow!("failed to parse amd sev-snp report: {err}"))?;
    let mut errors = Vec::new();
    for product in amd_snp_product_candidates_for_report(&report)? {
        match verify_amd_snp_attestation_with_cert_chain(
            report_bytes,
            product.builtin_ark(),
            ask_bytes.clone(),
            vcek_bytes.clone(),
        ) {
            Ok(verified) => return Ok(verified),
            Err(err) => errors.push(format!("{}: {err:#}", product.kds_name())),
        }
    }
    bail!(
        "amd sev-snp report verification failed for supported products: {}",
        errors.join("; ")
    )
}

fn verify_amd_snp_attestation_with_cert_chain(
    report_bytes: &[u8],
    ark_bytes: CertBytes,
    ask_bytes: CertBytes,
    vcek_bytes: CertBytes,
) -> Result<VerifiedAmdSnpReport> {
    if report_bytes.len() != 1184 {
        bail!(
            "invalid amd sev-snp report length: expected 1184 bytes, got {}",
            report_bytes.len()
        );
    }
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|err| anyhow::anyhow!("failed to parse amd sev-snp report: {err}"))?;

    let ark = parse_certificate(&ark_bytes, "ark")?;
    let ask = parse_certificate(&ask_bytes, "ask")?;
    let vcek = parse_certificate(&vcek_bytes, "vcek")?;

    let chain = Chain {
        ca: ca::Chain { ark, ask },
        vek: vcek.clone(),
    };
    chain
        .verify()
        .map_err(|err| anyhow::anyhow!("amd cert chain verification failed: {err:?}"))?;
    (&vcek, &report).verify().map_err(|err| {
        anyhow::anyhow!("amd sev-snp report signature verification failed: {err:?}")
    })?;
    validate_amd_snp_report_policy(&report)?;

    let parsed = parsed_amd_snp_report_from_report(&report)?;

    Ok(VerifiedAmdSnpReport {
        measurement: parsed.measurement,
        report_data: parsed.report_data,
        host_data: parsed.host_data,
        chip_id: parsed.chip_id,
        tcb_info: AmdSnpTcbInfo::from_report(&report),
        // AMD SEV-SNP attestation reports and VCEKs do not carry a direct
        // advisory list. Keep this explicit and empty so downstream auth stays
        // fail-closed if a future verifier adds advisories from revocation or
        // external policy collateral.
        advisory_ids: Vec::new(),
    })
}

pub fn verify_amd_snp_evidence(
    report: &[u8],
    cert_chain: &[Vec<u8>],
    expected_report_data: &[u8; 64],
) -> Result<VerifiedAmdSnpReport> {
    let (ask, vcek) = normalize_ask_vcek_certs(cert_chain)?;
    let verified = verify_amd_snp_attestation_with_certs(report, ask, vcek)?;
    if &verified.report_data != expected_report_data {
        bail!("amd sev-snp report_data mismatch");
    }
    Ok(verified)
}

pub fn verify_amd_snp_evidence_with_kds_fallback(
    report: &[u8],
    cert_chain: &[Vec<u8>],
    expected_report_data: &[u8; 64],
) -> Result<VerifiedAmdSnpReport> {
    if !cert_chain.is_empty() {
        return verify_amd_snp_evidence(report, cert_chain, expected_report_data);
    }
    if report.len() != 1184 {
        bail!(
            "invalid amd sev-snp report length: expected 1184 bytes, got {}",
            report.len()
        );
    }
    let report_obj = AttestationReport::from_bytes(report)
        .map_err(|err| anyhow::anyhow!("failed to parse amd sev-snp report: {err}"))?;
    let collateral = fetch_amd_kds_collateral_for_report(&report_obj)
        .context("failed to fetch amd sev-snp KDS collateral for empty cert_chain")?;
    let verified = verify_amd_snp_attestation_with_cert_chain(
        report,
        collateral.ark,
        collateral.ask,
        collateral.vcek,
    )?;
    if &verified.report_data != expected_report_data {
        bail!("amd sev-snp report_data mismatch");
    }
    Ok(verified)
}

fn fetch_amd_kds_collateral_for_report(report: &AttestationReport) -> Result<AmdKdsCollateral> {
    let mut errors = Vec::new();
    for product in amd_snp_product_candidates_for_report(report)? {
        match fetch_amd_kds_collateral_for_product(product, report) {
            Ok(collateral) => return Ok(collateral),
            Err(err) => errors.push(format!("{}: {err:#}", product.kds_name())),
        }
    }
    bail!(
        "amd sev-snp KDS collateral unavailable for supported products: {}",
        errors.join("; ")
    )
}

fn fetch_amd_kds_collateral_for_product(
    product: AmdSnpProduct,
    report: &AttestationReport,
) -> Result<AmdKdsCollateral> {
    let (ark, ask) = fetch_amd_kds_ca_chain(product)?;
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(
        report
            .chip_id
            .as_ref()
            .get(..64)
            .context("amd sev-snp chip_id too short")?,
    );
    let vcek_url = amd_kds_vcek_url(product, &chip_id, report.reported_tcb.into())?;
    let vcek_request_url = amd_kds_request_url(&vcek_url);
    let vcek = reqwest::blocking::Client::new()
        .get(&vcek_request_url)
        .send()
        .with_context(|| format!("failed to request amd sev-snp vcek from {vcek_request_url}"))?
        .error_for_status()
        .with_context(|| {
            format!("amd sev-snp vcek request failed for {vcek_url} via {vcek_request_url}")
        })?
        .bytes()
        .context("failed to read amd sev-snp vcek response")?
        .to_vec();
    Ok(AmdKdsCollateral {
        ark,
        ask,
        vcek: CertBytes {
            bytes: vcek,
            encoding: CertEncoding::Der,
        },
    })
}

fn fetch_amd_kds_ca_chain(product: AmdSnpProduct) -> Result<(CertBytes, CertBytes)> {
    let url = format!(
        "https://kdsintf.amd.com/vcek/v1/{}/cert_chain",
        product.kds_name()
    );
    let request_url = amd_kds_request_url(&url);
    let chain = reqwest::blocking::Client::new()
        .get(&request_url)
        .send()
        .with_context(|| format!("failed to request amd sev-snp cert_chain from {request_url}"))?
        .error_for_status()
        .with_context(|| format!("amd sev-snp cert_chain request failed for {request_url}"))?
        .bytes()
        .context("failed to read amd sev-snp cert_chain response")?;
    let (_fetched_ark, ask) = extract_ark_ask_from_amd_kds_cert_chain(&chain)?;
    Ok((product.builtin_ark(), ask))
}

fn amd_kds_request_url(amd_url: &str) -> String {
    match std::env::var("DSTACK_AMD_KDS_PROXY_URL") {
        Ok(proxy) if !proxy.trim().is_empty() => format!("{}{}", proxy.trim(), amd_url),
        _ => amd_url.to_string(),
    }
}

fn amd_snp_product_candidates_for_report(report: &AttestationReport) -> Result<Vec<AmdSnpProduct>> {
    if let Some(product) = amd_snp_product_from_report(report)? {
        return Ok(vec![product]);
    }

    // SNP report v2 predates the CPUID family/model fields. In that case the
    // product cannot be derived from the signed report, so keep a small
    // fail-closed compatibility fallback. Bergamo and Siena deliberately do
    // not appear here because their KDS endpoint is the canonical Genoa one.
    Ok(vec![
        AmdSnpProduct::Genoa,
        AmdSnpProduct::Milan,
        AmdSnpProduct::Turin,
    ])
}

fn amd_snp_product_from_report(report: &AttestationReport) -> Result<Option<AmdSnpProduct>> {
    match report.version {
        2 => return Ok(None),
        3 => {}
        version => bail!("unsupported amd sev-snp report version: {version}"),
    }

    let family = report
        .cpuid_fam_id
        .context("amd sev-snp report v3+ is missing CPUID family")?;
    let model = report
        .cpuid_mod_id
        .context("amd sev-snp report v3+ is missing CPUID model")?;

    let product = match family {
        0x19 => match model {
            0x00..=0x0f => AmdSnpProduct::Milan,
            0x10..=0x1f | 0xa0..=0xaf => AmdSnpProduct::Genoa,
            _ => bail!("unsupported amd sev-snp CPUID model for family 19h: {model:#04x}"),
        },
        0x1a => match model {
            0x00..=0x11 => AmdSnpProduct::Turin,
            _ => bail!("unsupported amd sev-snp CPUID model for family 1Ah: {model:#04x}"),
        },
        _ => bail!("unsupported amd sev-snp CPUID family: {family:#04x}"),
    };

    Ok(Some(product))
}

fn amd_kds_vcek_url(
    product: AmdSnpProduct,
    chip_id: &[u8; 64],
    tcb: AmdSnpTcbVersion,
) -> Result<String> {
    let url = match product {
        AmdSnpProduct::Turin => {
            let fmc = tcb
                .fmc
                .context("amd sev-snp Turin VCEK request requires reported FMC TCB")?;
            format!(
                "https://kdsintf.amd.com/vcek/v1/{}/{}?fmcSPL={}&blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                product.kds_name(),
                hex::encode(&chip_id[..8]),
                fmc,
                tcb.bootloader,
                tcb.tee,
                tcb.snp,
                tcb.microcode
            )
        }
        AmdSnpProduct::Milan | AmdSnpProduct::Genoa => format!(
            "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            product.kds_name(),
            hex::encode(chip_id),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        ),
    };
    Ok(url)
}

fn extract_ark_ask_from_amd_kds_cert_chain(chain: &[u8]) -> Result<(CertBytes, CertBytes)> {
    let certs = extract_pem_certs(chain)?;
    if certs.len() < 2 {
        bail!("amd sev-snp cert_chain must contain ASK and ARK certificates");
    }
    Ok((
        CertBytes {
            bytes: certs[1].clone(),
            encoding: CertEncoding::Pem,
        },
        CertBytes {
            bytes: certs[0].clone(),
            encoding: CertEncoding::Pem,
        },
    ))
}

fn extract_pem_certs(chain: &[u8]) -> Result<Vec<Vec<u8>>> {
    let chain = std::str::from_utf8(chain).context("amd sev-snp cert_chain is not utf-8 pem")?;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let mut rest = chain;
    let mut certs = Vec::new();
    while let Some(start) = rest.find(begin) {
        let after_start = &rest[start..];
        let cert_end = after_start
            .find(end)
            .map(|idx| idx + end.len())
            .context("amd sev-snp cert_chain has unterminated certificate")?;
        let mut cert = after_start.as_bytes()[..cert_end].to_vec();
        cert.push(b'\n');
        certs.push(cert);
        rest = &after_start[cert_end..];
    }
    if certs.is_empty() {
        bail!("amd sev-snp cert_chain missing certificates");
    }
    Ok(certs)
}

fn parse_certificate(cert: &CertBytes, name: &str) -> Result<Certificate> {
    match cert.encoding {
        CertEncoding::Pem => Certificate::from_pem(&cert.bytes)
            .map_err(|err| anyhow::anyhow!("failed to parse amd {name} certificate: {err:?}")),
        CertEncoding::Der => Certificate::from_der(&cert.bytes)
            .map_err(|err| anyhow::anyhow!("failed to parse amd {name} certificate: {err:?}")),
    }
}

fn validate_amd_snp_report_policy(report: &AttestationReport) -> Result<()> {
    if !matches!(report.version, 2 | 3) {
        bail!("unsupported amd sev-snp report version: {}", report.version);
    }
    if report.vmpl != 0 {
        bail!("amd sev-snp report must be generated at vmpl0");
    }
    if report.policy.debug_allowed() {
        bail!("amd sev-snp guest policy allows debug");
    }
    if report.policy.migrate_ma_allowed() {
        bail!("amd sev-snp guest policy allows migration agent");
    }
    if report.key_info.mask_chip_key() {
        bail!("amd sev-snp report masks the chip signing key");
    }
    if report.key_info.signing_key() != 0 {
        bail!(
            "unsupported amd sev-snp signing key: expected vcek, got {}",
            report.key_info.signing_key()
        );
    }
    if !report.policy.smt_allowed() && report.plat_info.smt_enabled() {
        bail!("amd sev-snp platform has smt enabled but guest policy does not allow smt");
    }
    if report.policy.rapl_dis() && !report.plat_info.rapl_disabled() {
        bail!("amd sev-snp guest policy requires rapl disabled, but platform reports rapl enabled");
    }
    if report.policy.ciphertext_hiding() && !report.plat_info.ciphertext_hiding_enabled() {
        bail!(
            "amd sev-snp guest policy requires ciphertext hiding, but platform does not report it"
        );
    }
    Ok(())
}

fn normalize_ask_vcek_certs(cert_chain: &[Vec<u8>]) -> Result<(CertBytes, CertBytes)> {
    match cert_chain {
        [ask, vcek] => Ok((cert_bytes_from_blob(ask), cert_bytes_from_blob(vcek))),
        [auxblob] => normalize_kernel_cert_table(auxblob),
        _ => bail!(
            "amd sev-snp cert_chain must contain either ASK and VCEK certificates or one kernel certificate table auxblob"
        ),
    }
}

fn cert_bytes_from_blob(blob: &[u8]) -> CertBytes {
    let encoding = if blob.starts_with(b"-----BEGIN CERTIFICATE-----") {
        CertEncoding::Pem
    } else {
        CertEncoding::Der
    };
    CertBytes {
        bytes: blob.to_vec(),
        encoding,
    }
}

fn normalize_kernel_cert_table(auxblob: &[u8]) -> Result<(CertBytes, CertBytes)> {
    let mut ask = None;
    let mut vcek = None;
    for (guid, data) in parse_kernel_cert_table(auxblob)? {
        match guid {
            ASK_CERT_GUID => ask = Some(data),
            VCEK_CERT_GUID => vcek = Some(data),
            VLEK_CERT_GUID => bail!("amd sev-snp vlek certificates are not supported yet"),
            _ => {}
        }
    }
    let ask = ask.context("amd sev-snp certificate table missing ASK certificate")?;
    let vcek = vcek.context("amd sev-snp certificate table missing VCEK certificate")?;
    Ok((
        CertBytes {
            bytes: ask,
            encoding: CertEncoding::Der,
        },
        CertBytes {
            bytes: vcek,
            encoding: CertEncoding::Der,
        },
    ))
}

fn parse_kernel_cert_table(auxblob: &[u8]) -> Result<Vec<([u8; 16], Vec<u8>)>> {
    if auxblob.len() < CERT_TABLE_ENTRY_SIZE {
        bail!("amd sev-snp certificate table is too short");
    }
    let mut entries = Vec::new();
    let mut pos = 0usize;
    loop {
        let entry = auxblob
            .get(pos..pos + CERT_TABLE_ENTRY_SIZE)
            .context("amd sev-snp certificate table is missing terminator")?;
        let guid: [u8; 16] = entry[..16]
            .try_into()
            .context("amd sev-snp certificate table entry guid has invalid length")?;
        let offset = u32::from_le_bytes(
            entry[16..20]
                .try_into()
                .context("amd sev-snp certificate table entry offset has invalid length")?,
        ) as usize;
        let length = u32::from_le_bytes(
            entry[20..24]
                .try_into()
                .context("amd sev-snp certificate table entry length has invalid length")?,
        ) as usize;
        if guid == [0u8; 16] && offset == 0 && length == 0 {
            break;
        }
        let end = offset
            .checked_add(length)
            .context("amd sev-snp certificate table entry length overflows")?;
        if offset < CERT_TABLE_ENTRY_SIZE || end > auxblob.len() || length == 0 {
            bail!("amd sev-snp certificate table entry has invalid bounds");
        }
        entries.push((guid, auxblob[offset..end].to_vec()));
        pos = pos
            .checked_add(CERT_TABLE_ENTRY_SIZE)
            .context("amd sev-snp certificate table entry count overflows")?;
        if pos >= auxblob.len() {
            bail!("amd sev-snp certificate table is missing terminator");
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcb(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> AmdSnpTcbVersion {
        AmdSnpTcbVersion {
            fmc: None,
            bootloader,
            tee,
            snp,
            microcode,
        }
    }

    #[test]
    fn tcb_status_is_up_to_date_only_when_all_reported_versions_match() {
        let up_to_date = AmdSnpTcbInfo {
            current: tcb(1, 2, 3, 4),
            reported: tcb(1, 2, 3, 4),
            committed: tcb(1, 2, 3, 4),
            launch: tcb(1, 2, 3, 4),
        };
        assert_eq!(up_to_date.tcb_status(), "UpToDate");

        let stale_launch = AmdSnpTcbInfo {
            launch: tcb(1, 2, 3, 3),
            ..up_to_date
        };
        assert_eq!(stale_launch.tcb_status(), "OutOfDate");

        let stale_vcek_reported = AmdSnpTcbInfo {
            reported: tcb(1, 2, 3, 3),
            ..up_to_date
        };
        assert_eq!(stale_vcek_reported.tcb_status(), "OutOfDate");
    }

    #[test]
    fn missing_cert_chain_fails_closed() {
        let report = vec![0u8; 1184];
        let expected_report_data = [0u8; 64];
        let err = verify_amd_snp_evidence(&report, &[], &expected_report_data).unwrap_err();
        assert!(
            err.to_string()
                .contains("cert_chain must contain either ASK and VCEK certificates or one kernel certificate table auxblob"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn amd_kds_vcek_url_binds_chip_id_and_reported_tcb() {
        let chip_id = [0xab; 64];
        let tcb = AmdSnpTcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };

        let url = amd_kds_vcek_url(AmdSnpProduct::Genoa, &chip_id, tcb).unwrap();

        assert_eq!(
            url,
            format!(
                "https://kdsintf.amd.com/vcek/v1/Genoa/{}?blSPL=1&teeSPL=2&snpSPL=3&ucodeSPL=4",
                hex::encode(chip_id)
            )
        );
    }

    #[test]
    fn amd_kds_vcek_url_for_turin_uses_short_chip_id_and_fmc() {
        let chip_id = [0xab; 64];
        let tcb = AmdSnpTcbVersion {
            fmc: Some(5),
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };

        let url = amd_kds_vcek_url(AmdSnpProduct::Turin, &chip_id, tcb).unwrap();

        assert_eq!(
            url,
            "https://kdsintf.amd.com/vcek/v1/Turin/abababababababab?fmcSPL=5&blSPL=1&teeSPL=2&snpSPL=3&ucodeSPL=4"
        );
    }

    #[test]
    fn report_v3_cpuid_selects_kds_product_without_enumeration() {
        let mut report = base_report();
        report.version = 3;
        report.cpuid_fam_id = Some(0x19);
        report.cpuid_mod_id = Some(0x10);

        assert_eq!(
            amd_snp_product_candidates_for_report(&report).unwrap(),
            vec![AmdSnpProduct::Genoa]
        );

        report.cpuid_mod_id = Some(0x0f);
        assert_eq!(
            amd_snp_product_candidates_for_report(&report).unwrap(),
            vec![AmdSnpProduct::Milan]
        );

        report.cpuid_fam_id = Some(0x1a);
        report.cpuid_mod_id = Some(0x00);
        assert_eq!(
            amd_snp_product_candidates_for_report(&report).unwrap(),
            vec![AmdSnpProduct::Turin]
        );
    }

    #[test]
    fn report_v2_keeps_canonical_compatibility_product_candidates() {
        let report = base_report();

        assert_eq!(
            amd_snp_product_candidates_for_report(&report).unwrap(),
            vec![
                AmdSnpProduct::Genoa,
                AmdSnpProduct::Milan,
                AmdSnpProduct::Turin
            ]
        );
    }

    #[test]
    fn amd_kds_proxy_url_wraps_amd_urls_when_configured() {
        const ENV_KEY: &str = "DSTACK_AMD_KDS_PROXY_URL";
        let old = std::env::var(ENV_KEY).ok();
        std::env::set_var(ENV_KEY, "https://cors.litgateway.com/");

        let wrapped = amd_kds_request_url("https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain");

        assert_eq!(
            wrapped,
            "https://cors.litgateway.com/https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
        );
        if let Some(old) = old {
            std::env::set_var(ENV_KEY, old);
        } else {
            std::env::remove_var(ENV_KEY);
        }
    }

    #[test]
    fn amd_kds_cert_chain_extracts_ask_pem_and_ark_pem() {
        let chain = b"-----BEGIN CERTIFICATE-----\nASK\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nARK\n-----END CERTIFICATE-----\n";

        let (ark_cert, ask_cert) = extract_ark_ask_from_amd_kds_cert_chain(chain).unwrap();

        assert_eq!(
            ask_cert.bytes,
            b"-----BEGIN CERTIFICATE-----\nASK\n-----END CERTIFICATE-----\n".to_vec()
        );
        assert_eq!(ask_cert.encoding, CertEncoding::Pem);
        assert_eq!(
            ark_cert.bytes,
            b"-----BEGIN CERTIFICATE-----\nARK\n-----END CERTIFICATE-----\n".to_vec()
        );
        assert_eq!(ark_cert.encoding, CertEncoding::Pem);
    }

    #[test]
    fn malformed_report_fails_closed_before_success() {
        let cert_chain = vec![b"not ask".to_vec(), b"not vcek".to_vec()];
        let expected_report_data = [0u8; 64];
        let err =
            verify_amd_snp_evidence(b"too short", &cert_chain, &expected_report_data).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid amd sev-snp report length"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn normalizes_kernel_cert_table_auxblob_to_ask_and_vcek_der() {
        use sev::firmware::host::{CertTableEntry, CertType};

        let auxblob = CertTableEntry::cert_table_to_vec_bytes(&[
            CertTableEntry::new(CertType::VCEK, b"vcek-der".to_vec()),
            CertTableEntry::new(CertType::ASK, b"ask-der".to_vec()),
        ])
        .unwrap();

        let (ask, vcek) = normalize_ask_vcek_certs(&[auxblob]).unwrap();

        assert_eq!(ask.bytes, b"ask-der");
        assert_eq!(ask.encoding, CertEncoding::Der);
        assert_eq!(vcek.bytes, b"vcek-der");
        assert_eq!(vcek.encoding, CertEncoding::Der);
    }

    #[test]
    fn malformed_single_auxblob_fails_closed_without_panic() {
        let err = normalize_ask_vcek_certs(&[vec![0xff; 23]]).unwrap_err();

        assert!(
            err.to_string().contains("certificate table"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn normalizes_existing_two_item_pem_chain_without_reordering() {
        let ask = b"-----BEGIN CERTIFICATE-----\nask\n-----END CERTIFICATE-----\n".to_vec();
        let vcek = b"-----BEGIN CERTIFICATE-----\nvcek\n-----END CERTIFICATE-----\n".to_vec();

        let (normalized_ask, normalized_vcek) =
            normalize_ask_vcek_certs(&[ask.clone(), vcek.clone()]).unwrap();

        assert_eq!(normalized_ask.bytes, ask);
        assert_eq!(normalized_ask.encoding, CertEncoding::Pem);
        assert_eq!(normalized_vcek.bytes, vcek);
        assert_eq!(normalized_vcek.encoding, CertEncoding::Pem);
    }

    #[test]
    fn report_policy_rejects_debug_allowed() {
        let mut report = base_report();
        report.policy.set_debug_allowed(true);

        let err = validate_amd_snp_report_policy(&report).unwrap_err();

        assert!(
            err.to_string().contains("debug"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn report_policy_rejects_non_vmpl0() {
        let mut report = base_report();
        report.vmpl = 1;

        let err = validate_amd_snp_report_policy(&report).unwrap_err();

        assert!(
            err.to_string().contains("vmpl0"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn report_policy_accepts_strict_vcek_vmpl0_report() {
        let report = base_report();

        validate_amd_snp_report_policy(&report).unwrap();
    }

    fn base_report() -> AttestationReport {
        AttestationReport {
            version: 2,
            ..Default::default()
        }
    }
}
