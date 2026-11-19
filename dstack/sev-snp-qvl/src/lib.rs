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

use std::{fmt, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use moka::future::Cache;
use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::{guest::AttestationReport, host::TcbVersion};

#[cfg(test)]
mod kds_tests;

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
/// Size of an AMD SEV-SNP attestation report, for every version the `sev`
/// crate decodes.
const AMD_SNP_REPORT_LEN: usize = 1184;
pub const AMD_KDS_DEFAULT_BASE_URL: &str = "https://kdsintf.amd.com/vcek/v1";
const AMD_KDS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const AMD_KDS_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const AMD_KDS_CA_CACHE_CAPACITY: u64 = 16;
const AMD_KDS_VCEK_CACHE_CAPACITY: u64 = 1024;
/// AMD reissues each CRL every few weeks; refetch well within that.
const AMD_KDS_CRL_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Verification could not obtain its required AMD endorsement collateral.
/// This is not evidence that a quote is cryptographically invalid.
#[derive(Debug)]
pub struct CollateralUnavailable(anyhow::Error);

impl fmt::Display for CollateralUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AMD endorsement collateral unavailable: {:#}", self.0)
    }
}

impl std::error::Error for CollateralUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Preserve typed causes when a coalesced cache initialization fails.
#[derive(Debug)]
struct SharedFetchError(Arc<anyhow::Error>);

impl fmt::Display for SharedFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for SharedFetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

pub fn collateral_unavailable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<CollateralUnavailable>())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmdSnpProduct {
    Milan,
    Genoa,
    Turin,
}

/// AMD SEV-SNP quote verifier with caller-owned ARK trust anchors.
///
/// One ARK is required per supported processor family because AMD operates a
/// separate hierarchy for each family. `new_prod` uses the ARKs shipped by the
/// `sev` crate; `new` accepts PEM encoded ARKs from the caller.
#[derive(Debug, Clone)]
pub struct QuoteVerifier {
    milan_ark_pem: Vec<u8>,
    genoa_ark_pem: Vec<u8>,
    turin_ark_pem: Vec<u8>,
    external_roots: [bool; 3],
    tcb_requirements: Vec<AmdSnpTcbRequirement>,
}

/// The minimum TCB that fixes an AMD security bulletin on one product family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdSnpTcbRequirement {
    pub product: AmdSnpProduct,
    pub advisory_id: String,
    pub min_tcb: AmdSnpTcbVersion,
}

impl QuoteVerifier {
    pub fn new(milan_ark_pem: Vec<u8>, genoa_ark_pem: Vec<u8>, turin_ark_pem: Vec<u8>) -> Self {
        Self {
            milan_ark_pem,
            genoa_ark_pem,
            turin_ark_pem,
            external_roots: [true; 3],
            tcb_requirements: Vec::new(),
        }
    }

    pub fn new_prod() -> Self {
        Self {
            milan_ark_pem: builtin::milan::ARK.to_vec(),
            genoa_ark_pem: builtin::genoa::ARK.to_vec(),
            turin_ark_pem: builtin::turin::ARK.to_vec(),
            external_roots: [false; 3],
            tcb_requirements: Vec::new(),
        }
    }

    /// Judge `tcb_status` and `advisory_ids` against these requirements. A
    /// product without any requirement reports an empty status.
    pub fn with_tcb_requirements(mut self, requirements: Vec<AmdSnpTcbRequirement>) -> Self {
        self.tcb_requirements = requirements;
        self
    }

    /// Create a production verifier overriding one product-family ARK.
    pub fn new_with_root(product: AmdSnpProduct, ark_pem: Vec<u8>) -> Self {
        Self::new_prod().with_root(product, ark_pem)
    }

    /// Override one product-family ARK.
    pub fn with_root(mut self, product: AmdSnpProduct, ark_pem: Vec<u8>) -> Self {
        match product {
            AmdSnpProduct::Milan => {
                self.milan_ark_pem = ark_pem;
                self.external_roots[0] = true;
            }
            AmdSnpProduct::Genoa => {
                self.genoa_ark_pem = ark_pem;
                self.external_roots[1] = true;
            }
            AmdSnpProduct::Turin => {
                self.turin_ark_pem = ark_pem;
                self.external_roots[2] = true;
            }
        }
        self
    }

    fn ark(&self, product: AmdSnpProduct) -> CertBytes {
        CertBytes {
            bytes: match product {
                AmdSnpProduct::Milan => self.milan_ark_pem.clone(),
                AmdSnpProduct::Genoa => self.genoa_ark_pem.clone(),
                AmdSnpProduct::Turin => self.turin_ark_pem.clone(),
            },
            encoding: CertEncoding::Pem,
        }
    }

    fn uses_external_root(&self, product: AmdSnpProduct) -> bool {
        self.external_roots[match product {
            AmdSnpProduct::Milan => 0,
            AmdSnpProduct::Genoa => 1,
            AmdSnpProduct::Turin => 2,
        }]
    }

    /// Verify offline. This does not check AMD's CRL; `fetch_and_verify` does.
    pub fn verify(
        &self,
        report: &[u8],
        cert_chain: &[Vec<u8>],
        expected_report_data: &[u8; 64],
    ) -> Result<VerifiedAmdSnpReport> {
        let (_, _, verified) = self.verify_supplied(report, cert_chain, expected_report_data)?;
        Ok(verified)
    }

    fn verify_supplied(
        &self,
        report: &[u8],
        cert_chain: &[Vec<u8>],
        expected_report_data: &[u8; 64],
    ) -> Result<(AmdSnpProduct, CertBytes, VerifiedAmdSnpReport)> {
        let (ask, vcek) = normalize_ask_vcek_certs(cert_chain)?;
        let (product, verified) = verify_amd_snp_attestation_with_certs_and_arks(
            report,
            ask.clone(),
            vcek,
            |product| (self.ark(product), self.uses_external_root(product)),
            &self.tcb_requirements,
        )?;
        if &verified.report_data != expected_report_data {
            bail!("amd sev-snp report_data mismatch");
        }
        Ok((product, ask, verified))
    }

    /// Reject an ASK that the product's CRL, signed by its pinned ARK, revokes.
    /// A CRL that cannot be used (stale, corrupt, wrongly signed) is
    /// unavailable collateral, not evidence against the quote, and is dropped
    /// from the cache.
    async fn check_ask_not_revoked(
        &self,
        kds_client: &AmdKdsClient,
        product: AmdSnpProduct,
        ask: &CertBytes,
    ) -> Result<()> {
        let crl = kds_client.fetch_crl(product).await?;
        let now = x509_parser::time::ASN1Time::now();
        match crl_revokes_ask(&self.ark(product), ask, &crl, now) {
            Ok(false) => Ok(()),
            Ok(true) => bail!("amd sev-snp {} ASK is revoked", product.kds_name()),
            Err(err) => {
                kds_client
                    .crl_cache
                    .invalidate(&AmdKdsCaCacheKey { product })
                    .await;
                let err = err.context(format!("unusable amd sev-snp {} crl", product.kds_name()));
                Err(CollateralUnavailable(err).into())
            }
        }
    }

    pub async fn fetch_and_verify(
        &self,
        kds_client: &AmdKdsClient,
        report: &[u8],
        cert_chain: &[Vec<u8>],
        expected_report_data: &[u8; 64],
    ) -> Result<VerifiedAmdSnpReport> {
        if !cert_chain.is_empty() {
            let (product, ask, verified) =
                self.verify_supplied(report, cert_chain, expected_report_data)?;
            self.check_ask_not_revoked(kds_client, product, &ask)
                .await?;
            return Ok(verified);
        }
        let report_obj = decode_amd_snp_report(report)?;
        let mut errors = Vec::new();
        let mut unavailable = None;
        for product in amd_snp_product_candidates_for_report(&report_obj)? {
            match kds_client
                .fetch_collateral_for_product(product, &report_obj)
                .await
            {
                Ok(collateral) => match verify_amd_snp_attestation_with_cert_chain(
                    report,
                    product,
                    self.ark(product),
                    collateral.ask.clone(),
                    collateral.vcek,
                    self.uses_external_root(product),
                    &self.tcb_requirements,
                ) {
                    Ok(verified) if &verified.report_data == expected_report_data => {
                        self.check_ask_not_revoked(kds_client, product, &collateral.ask)
                            .await?;
                        return Ok(verified);
                    }
                    Ok(_) => bail!("amd sev-snp report_data mismatch"),
                    Err(err) => errors.push(format!("{}: {err:#}", product.kds_name())),
                },
                Err(err) => {
                    errors.push(format!("{}: {err:#}", product.kds_name()));
                    if collateral_unavailable(&err) {
                        unavailable = Some(err);
                    }
                }
            }
        }
        let reason = format!("amd sev-snp verification failed: {}", errors.join("; "));
        if let Some(err) = unavailable {
            return Err(err.context(reason));
        }
        bail!(reason)
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
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

impl AmdSnpTcbVersion {
    /// Whether every SVN is at least the one in `min`.
    fn meets(&self, min: &AmdSnpTcbVersion) -> bool {
        self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
            && min
                .fmc
                .is_none_or(|fmc| self.fmc.is_some_and(|own| own >= fmc))
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

    /// Assess the reported, committed and launch TCBs against `requirements`
    /// for `product`. The reported TCB is the one the VCEK certifies; the
    /// committed one bounds firmware rollback; the launch one is what the guest
    /// first ran under.
    fn assess(
        &self,
        product: AmdSnpProduct,
        requirements: &[AmdSnpTcbRequirement],
    ) -> (String, Vec<String>) {
        let mut configured = false;
        let mut advisory_ids = Vec::new();
        for requirement in requirements.iter().filter(|r| r.product == product) {
            configured = true;
            if ![self.reported, self.committed, self.launch]
                .iter()
                .all(|tcb| tcb.meets(&requirement.min_tcb))
            {
                advisory_ids.push(requirement.advisory_id.clone());
            }
        }
        let status = match (configured, advisory_ids.is_empty()) {
            (false, _) => "",
            (true, true) => "UpToDate",
            (true, false) => "OutOfDate",
        };
        (status.to_string(), advisory_ids)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAmdSnpReport {
    pub measurement: [u8; 48],
    pub report_data: [u8; 64],
    pub host_data: [u8; 32],
    pub chip_id: [u8; 64],
    pub tcb_info: AmdSnpTcbInfo,
    /// `UpToDate` or `OutOfDate` against the verifier's TCB requirements, or
    /// empty when none is configured for the product.
    pub tcb_status: String,
    /// The bulletins whose minimum TCB the report does not meet.
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AmdKdsCaCacheKey {
    product: AmdSnpProduct,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AmdKdsVcekCacheKey {
    product: AmdSnpProduct,
    chip_id: [u8; 64],
    tcb: AmdSnpTcbVersion,
}

#[derive(Clone)]
pub struct AmdKdsClient {
    base_url: String,
    http_client: reqwest::Client,
    ca_cache: Cache<AmdKdsCaCacheKey, (CertBytes, CertBytes)>,
    vcek_cache: Cache<AmdKdsVcekCacheKey, CertBytes>,
    crl_cache: Cache<AmdKdsCaCacheKey, Vec<u8>>,
}

impl AmdKdsClient {
    pub fn new() -> Result<Self> {
        Self::with_base_url(AMD_KDS_DEFAULT_BASE_URL)
    }

    pub fn with_base_url(base_url: impl AsRef<str>) -> Result<Self> {
        let base_url = normalize_amd_kds_base_url(base_url.as_ref())?;
        let http_client = reqwest::Client::builder()
            .connect_timeout(AMD_KDS_CONNECT_TIMEOUT)
            .timeout(AMD_KDS_REQUEST_TIMEOUT)
            .build()
            .context("failed to create amd sev-snp KDS HTTP client")?;
        Ok(Self {
            base_url,
            http_client,
            ca_cache: Cache::new(AMD_KDS_CA_CACHE_CAPACITY),
            vcek_cache: Cache::new(AMD_KDS_VCEK_CACHE_CAPACITY),
            crl_cache: Cache::builder()
                .max_capacity(AMD_KDS_CA_CACHE_CAPACITY)
                .time_to_live(AMD_KDS_CRL_CACHE_TTL)
                .build(),
        })
    }

    async fn fetch_collateral_for_product(
        &self,
        product: AmdSnpProduct,
        report: &AttestationReport,
    ) -> Result<AmdKdsCollateral> {
        let (ark, ask) = self.fetch_ca_chain(product).await?;
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(
            report
                .chip_id
                .as_ref()
                .get(..64)
                .context("amd sev-snp chip_id too short")?,
        );
        let vcek = self
            .fetch_vcek(product, &chip_id, report.reported_tcb.into())
            .await?;
        Ok(AmdKdsCollateral { ark, ask, vcek })
    }

    async fn fetch_ca_chain(&self, product: AmdSnpProduct) -> Result<(CertBytes, CertBytes)> {
        let key = AmdKdsCaCacheKey { product };
        self.ca_cache
            .try_get_with(key, async {
                let url = join_amd_kds_url(
                    &self.base_url,
                    &format!("{}/cert_chain", product.kds_name()),
                );
                let chain = self.fetch_url(&url, "cert_chain").await?;
                let (_fetched_ark, ask) = extract_ark_ask_from_amd_kds_cert_chain(&chain)?;
                Ok::<_, anyhow::Error>((product.builtin_ark(), ask))
            })
            .await
            .map_err(|err| SharedFetchError(err).into())
    }

    async fn fetch_crl(&self, product: AmdSnpProduct) -> Result<Vec<u8>> {
        self.crl_cache
            .try_get_with(AmdKdsCaCacheKey { product }, async {
                let url = join_amd_kds_url(&self.base_url, &format!("{}/crl", product.kds_name()));
                self.fetch_url(&url, "crl").await
            })
            .await
            .map_err(|err| SharedFetchError(err).into())
    }

    async fn fetch_vcek(
        &self,
        product: AmdSnpProduct,
        chip_id: &[u8; 64],
        tcb: AmdSnpTcbVersion,
    ) -> Result<CertBytes> {
        let key = AmdKdsVcekCacheKey {
            product,
            chip_id: *chip_id,
            tcb,
        };
        self.vcek_cache
            .try_get_with(key, async {
                let vcek_url = amd_kds_vcek_url_with_base(&self.base_url, product, chip_id, tcb)?;
                Ok::<_, anyhow::Error>(CertBytes {
                    bytes: self.fetch_url(&vcek_url, "vcek").await?,
                    encoding: CertEncoding::Der,
                })
            })
            .await
            .map_err(|err| SharedFetchError(err).into())
    }

    async fn fetch_url(&self, url: &str, label: &str) -> Result<Vec<u8>> {
        let result = async {
            Ok(self
                .http_client
                .get(url)
                .send()
                .await
                .with_context(|| format!("failed to request amd sev-snp {label} from {url}"))?
                .error_for_status()
                .with_context(|| format!("amd sev-snp {label} request failed for {url}"))?
                .bytes()
                .await
                .with_context(|| format!("failed to read amd sev-snp {label} response"))?
                .to_vec())
        }
        .await;
        result.map_err(|err| CollateralUnavailable(err).into())
    }
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

/// Decode an attestation report, rejecting anything that is not report-sized
/// first.
///
/// `AttestationReport::from_bytes` indexes `bytes[0..4]` and, for a version it
/// does not know, `bytes[392]`, without looking at the length: a report shorter
/// than that aborts the process, because release builds are `panic = "abort"`
/// (`dstack/Cargo.toml`). The report arrives in an unverified attestation blob,
/// so the length has to be checked on every path that reaches this parser, not
/// on the three that happened to.
fn decode_amd_snp_report(report_bytes: &[u8]) -> Result<AttestationReport> {
    if report_bytes.len() != AMD_SNP_REPORT_LEN {
        bail!(
            "invalid amd sev-snp report length: expected {AMD_SNP_REPORT_LEN} bytes, got {}",
            report_bytes.len()
        );
    }
    AttestationReport::from_bytes(report_bytes)
        .map_err(|err| anyhow!("failed to parse amd sev-snp report: {err}"))
}

/// Decode an attestation report's fields without checking its authenticity.
///
/// This does not verify the report signature or the AMD certificate chain.
/// Use [`verify_amd_snp_attestation`] when authenticity is in question; use
/// this only where the signature is established elsewhere, or for the guest's
/// own report.
pub fn parse_unverified_amd_snp_report(report_bytes: &[u8]) -> Result<ParsedAmdSnpReport> {
    let report = decode_amd_snp_report(report_bytes)?;
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
    verify_amd_snp_attestation_with_certs_and_arks(
        report_bytes,
        ask_bytes,
        vcek_bytes,
        |product| (product.builtin_ark(), false),
        &[],
    )
    .map(|(_, verified)| verified)
}

fn verify_amd_snp_attestation_with_certs_and_arks(
    report_bytes: &[u8],
    ask_bytes: CertBytes,
    vcek_bytes: CertBytes,
    ark_for_product: impl Fn(AmdSnpProduct) -> (CertBytes, bool),
    tcb_requirements: &[AmdSnpTcbRequirement],
) -> Result<(AmdSnpProduct, VerifiedAmdSnpReport)> {
    let report = decode_amd_snp_report(report_bytes)?;
    let mut errors = Vec::new();
    for product in amd_snp_product_candidates_for_report(&report)? {
        let (ark, external_root) = ark_for_product(product);
        match verify_amd_snp_attestation_with_cert_chain(
            report_bytes,
            product,
            ark,
            ask_bytes.clone(),
            vcek_bytes.clone(),
            external_root,
            tcb_requirements,
        ) {
            Ok(verified) => return Ok((product, verified)),
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
    product: AmdSnpProduct,
    ark_bytes: CertBytes,
    ask_bytes: CertBytes,
    vcek_bytes: CertBytes,
    external_root: bool,
    tcb_requirements: &[AmdSnpTcbRequirement],
) -> Result<VerifiedAmdSnpReport> {
    let report = decode_amd_snp_report(report_bytes)?;

    let ark = parse_certificate(&ark_bytes, "ark")?;
    let ask = parse_certificate(&ask_bytes, "ask")?;
    let vcek = parse_certificate(&vcek_bytes, "vcek")?;
    if external_root {
        verify_x509_chain(&ark_bytes, &ask_bytes, &vcek_bytes)?;
    } else {
        Chain {
            ca: ca::Chain { ark, ask },
            vek: vcek.clone(),
        }
        .verify()
        .map_err(|err| anyhow::anyhow!("amd cert chain verification failed: {err:?}"))?;
    }
    (&vcek, &report).verify().map_err(|err| {
        anyhow::anyhow!("amd sev-snp report signature verification failed: {err:?}")
    })?;
    verify_vcek_binds_report(&vcek, &report, product)?;
    validate_amd_snp_report_policy(&report)?;

    let parsed = parsed_amd_snp_report_from_report(&report)?;
    let tcb_info = AmdSnpTcbInfo::from_report(&report);
    let (tcb_status, advisory_ids) = tcb_info.assess(product, tcb_requirements);

    Ok(VerifiedAmdSnpReport {
        measurement: parsed.measurement,
        report_data: parsed.report_data,
        host_data: parsed.host_data,
        chip_id: parsed.chip_id,
        tcb_info,
        tcb_status,
        advisory_ids,
    })
}

/// The VCEK is derived per chip and per TCB, so its hwID and SPL extensions
/// must match the report's CHIP_ID and REPORTED_TCB. Otherwise a VCEK key from
/// one chip or an old TCB could sign a report claiming another chip or a newer
/// TCB.
fn verify_vcek_binds_report(
    vcek: &Certificate,
    report: &AttestationReport,
    product: AmdSnpProduct,
) -> Result<()> {
    use x509_parser::der_parser::der::{parse_der_integer, parse_der_octetstring};
    use x509_parser::prelude::{FromDer, X509Certificate};

    // Read the extensions from the certificate whose signature was verified.
    let vcek_der = vcek
        .to_der()
        .map_err(|err| anyhow!("failed to encode VCEK: {err}"))?;
    let (_, vcek) = X509Certificate::from_der(&vcek_der).context("failed to parse VCEK X.509")?;
    let extension = |oid: &str| -> Result<&[u8]> {
        let mut values = vcek
            .extensions()
            .iter()
            .filter(|ext| ext.oid.to_id_string() == oid)
            .map(|ext| ext.value);
        match (values.next(), values.next()) {
            (Some(value), None) => Ok(value),
            (None, _) => bail!("VCEK is missing extension {oid}"),
            _ => bail!("VCEK has duplicate extension {oid}"),
        }
    };
    let spl = |oid: &str, name: &str| -> Result<u8> {
        let parsed = parse_der_integer(extension(oid)?)
            .ok()
            .filter(|(rest, _)| rest.is_empty())
            .and_then(|(_, value)| u8::try_from(value.as_u32().ok()?).ok());
        parsed.with_context(|| format!("invalid VCEK {name} extension"))
    };

    if report.chip_id.0 == [0; 64] {
        bail!("amd sev-snp report masks CHIP_ID, so it cannot be bound to its VCEK");
    }
    // Turin VCEKs may carry only the first 8 bytes of CHIP_ID, as in the KDS
    // URL. Older VCEKs store the raw hwID; newer ones wrap it in a DER OCTET
    // STRING.
    let hw_id_lens: &[usize] = match product {
        AmdSnpProduct::Turin => &[8, 64],
        AmdSnpProduct::Milan | AmdSnpProduct::Genoa => &[64],
    };
    let hw_id = match extension("1.3.6.1.4.1.3704.1.4")? {
        raw if hw_id_lens.contains(&raw.len()) => raw,
        der => match parse_der_octetstring(der) {
            Ok(([], value)) => value.as_slice()?,
            _ => bail!("invalid VCEK hwID extension"),
        },
    };
    if !hw_id_lens.contains(&hw_id.len()) || report.chip_id.0[..hw_id.len()] != *hw_id {
        bail!("VCEK hwID does not match the report chip_id");
    }

    let tcb = report.reported_tcb;
    let mut expected = vec![
        ("1.3.6.1.4.1.3704.1.3.1", "blSPL", tcb.bootloader),
        ("1.3.6.1.4.1.3704.1.3.2", "teeSPL", tcb.tee),
        ("1.3.6.1.4.1.3704.1.3.3", "snpSPL", tcb.snp),
        ("1.3.6.1.4.1.3704.1.3.8", "ucodeSPL", tcb.microcode),
    ];
    if product == AmdSnpProduct::Turin {
        let fmc = tcb
            .fmc
            .context("amd sev-snp Turin report is missing reported FMC TCB")?;
        expected.push(("1.3.6.1.4.1.3704.1.3.9", "fmcSPL", fmc));
    }
    for (oid, name, reported) in expected {
        let certified = spl(oid, name)?;
        if certified != reported {
            bail!("VCEK {name} {certified} does not match the report reported_tcb {reported}");
        }
    }
    Ok(())
}

fn verify_x509_chain(ark: &CertBytes, ask: &CertBytes, vcek: &CertBytes) -> Result<()> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let ark_der = certificate_der(ark)?;
    let ask_der = certificate_der(ask)?;
    let vcek_der = certificate_der(vcek)?;
    let (_, ark) = X509Certificate::from_der(&ark_der).context("failed to parse ARK X.509")?;
    let (_, ask) = X509Certificate::from_der(&ask_der).context("failed to parse ASK X.509")?;
    let (_, vcek) = X509Certificate::from_der(&vcek_der).context("failed to parse VCEK X.509")?;
    if !ark.is_ca() || !ask.is_ca() {
        bail!("AMD ARK and ASK certificates must be certificate authorities");
    }
    if ark.subject() != ark.issuer()
        || ask.issuer() != ark.subject()
        || vcek.issuer() != ask.subject()
    {
        bail!("AMD certificate issuer/subject chain mismatch");
    }
    verify_certificate_signature(&ark_der, &ark)
        .context("ARK self-signature verification failed")?;
    verify_certificate_signature(&ark_der, &ask).context("ASK signature verification failed")?;
    verify_certificate_signature(&ask_der, &vcek).context("VCEK signature verification failed")?;
    Ok(())
}

fn verify_certificate_signature(
    issuer_der: &[u8],
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<()> {
    verify_signed_data(
        issuer_der,
        &certificate.signature_algorithm,
        &certificate.tbs_certificate.signature,
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
}

fn verify_signed_data(
    issuer_der: &[u8],
    signature_algorithm: &x509_parser::x509::AlgorithmIdentifier<'_>,
    tbs_signature_algorithm: &x509_parser::x509::AlgorithmIdentifier<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use rustls_pki_types::CertificateDer;
    const RSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
    const ECDSA_SHA384_OID: &str = "1.2.840.10045.4.3.3";
    const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";
    const MGF1_OID: &str = "1.2.840.113549.1.1.8";

    anyhow::ensure!(
        signature_algorithm == tbs_signature_algorithm,
        "outer signatureAlgorithm does not match the signed one"
    );
    let oid = signature_algorithm.algorithm.to_id_string();
    let algorithm = match oid.as_str() {
        RSA_PSS_OID => {
            use x509_parser::signature_algorithm::SignatureAlgorithm;
            let SignatureAlgorithm::RSASSA_PSS(params) =
                SignatureAlgorithm::try_from(signature_algorithm)
                    .context("invalid RSA-PSS signature parameters")?
            else {
                bail!("invalid RSA-PSS signature parameters");
            };
            let mask = params
                .mask_gen_algorithm()
                .context("invalid RSA-PSS mask generation parameters")?;
            anyhow::ensure!(
                params.hash_algorithm_oid().to_id_string() == SHA384_OID
                    && mask.mgf.to_id_string() == MGF1_OID
                    && mask.hash.to_id_string() == SHA384_OID
                    && params.salt_length() == 48
                    && params.trailer_field() == 1,
                "RSA-PSS signature must use SHA-384, MGF1-SHA384, and a 48-byte salt"
            );
            webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
        }
        ECDSA_SHA384_OID => {
            anyhow::ensure!(
                signature_algorithm.parameters.is_none(),
                "ECDSA-SHA384 signature parameters must be absent"
            );
            webpki::ring::ECDSA_P384_SHA384
        }
        _ => bail!("unsupported signature algorithm: {oid}"),
    };
    let issuer_der = CertificateDer::from(issuer_der);
    let issuer = webpki::EndEntityCert::try_from(&issuer_der)
        .context("failed to parse certificate issuer")?;
    issuer
        .verify_signature(algorithm, message, signature)
        .context("invalid signature")?;
    Ok(())
}

/// Whether the product CRL revokes the ASK. The CRL must be signed by the
/// pinned ARK, current at `now` and carry no critical extension. AMD's CRL
/// revokes ASKs; VCEKs are retired through TCB updates.
fn crl_revokes_ask(
    ark: &CertBytes,
    ask: &CertBytes,
    crl_der: &[u8],
    now: x509_parser::time::ASN1Time,
) -> Result<bool> {
    use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

    let ark_der = certificate_der(ark)?;
    let ask_der = certificate_der(ask)?;
    let (_, ark) = X509Certificate::from_der(&ark_der).context("failed to parse ARK X.509")?;
    let (_, ask) = X509Certificate::from_der(&ask_der).context("failed to parse ASK X.509")?;
    let (rest, crl) =
        CertificateRevocationList::from_der(crl_der).context("failed to parse CRL")?;
    anyhow::ensure!(rest.is_empty(), "trailing data after CRL");
    anyhow::ensure!(
        crl.issuer() == ark.subject(),
        "CRL is not issued by the ARK"
    );
    verify_signed_data(
        &ark_der,
        &crl.signature_algorithm,
        &crl.tbs_cert_list.signature,
        crl.tbs_cert_list.as_ref(),
        crl.signature_value.data.as_ref(),
    )
    .context("CRL signature verification failed")?;
    let next_update = crl.next_update().context("CRL has no nextUpdate")?;
    anyhow::ensure!(
        crl.last_update() <= now && now < next_update,
        "CRL is not current: valid from {} to {next_update}",
        crl.last_update()
    );
    anyhow::ensure!(
        !crl.extensions().iter().any(|ext| ext.critical)
            && !crl
                .iter_revoked_certificates()
                .any(|revoked| revoked.extensions().iter().any(|ext| ext.critical)),
        "CRL has a critical extension"
    );
    let revoked = crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.serial() == &ask.tbs_certificate.serial);
    Ok(revoked)
}

fn certificate_der(cert: &CertBytes) -> Result<Vec<u8>> {
    match cert.encoding {
        CertEncoding::Der => Ok(cert.bytes.clone()),
        CertEncoding::Pem => Ok(::pem::parse(&cert.bytes)
            .context("failed to parse certificate PEM")?
            .into_contents()),
    }
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

fn normalize_amd_kds_base_url(base_url: &str) -> Result<String> {
    let base_url = base_url.trim().trim_end_matches('/').to_string();
    if base_url.is_empty() {
        bail!("amd sev-snp KDS base URL is empty");
    }
    Ok(base_url)
}

fn join_amd_kds_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim().trim_end_matches('/'),
        path.trim_start_matches('/')
    )
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

fn amd_kds_vcek_url_with_base(
    base_url: &str,
    product: AmdSnpProduct,
    chip_id: &[u8; 64],
    tcb: AmdSnpTcbVersion,
) -> Result<String> {
    let url = match product {
        AmdSnpProduct::Turin => {
            let fmc = tcb
                .fmc
                .context("amd sev-snp Turin VCEK request requires reported FMC TCB")?;
            join_amd_kds_url(
                base_url,
                &format!(
                    "{}/{}?fmcSPL={}&blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                    product.kds_name(),
                    hex::encode(&chip_id[..8]),
                    fmc,
                    tcb.bootloader,
                    tcb.tee,
                    tcb.snp,
                    tcb.microcode
                ),
            )
        }
        AmdSnpProduct::Milan | AmdSnpProduct::Genoa => join_amd_kds_url(
            base_url,
            &format!(
                "{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                product.kds_name(),
                hex::encode(chip_id),
                tcb.bootloader,
                tcb.tee,
                tcb.snp,
                tcb.microcode
            ),
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
            bytes: ask.to_vec(),
            encoding: CertEncoding::Der,
        },
        CertBytes {
            bytes: vcek.to_vec(),
            encoding: CertEncoding::Der,
        },
    ))
}

// Entries may overlap, so borrow them: copying each one lets a small blob decode to gigabytes.
fn parse_kernel_cert_table(auxblob: &[u8]) -> Result<Vec<([u8; 16], &[u8])>> {
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
        entries.push((guid, &auxblob[offset..end]));
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

    mod vcek_binding {
        use super::*;
        use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P384_SHA384};

        const CHIP_ID: [u8; 64] = [0xab; 64];

        /// A DER INTEGER, as AMD encodes SPLs.
        fn spl(value: u8) -> Vec<u8> {
            match value {
                0..0x80 => vec![0x02, 0x01, value],
                _ => vec![0x02, 0x02, 0x00, value],
            }
        }

        /// A VCEK with these (OID suffix, value) extensions under 1.3.6.1.4.1.3704.1.
        fn vcek(extensions: &[(&[u64], Vec<u8>)]) -> Certificate {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            for (suffix, value) in extensions {
                let oid = [&[1, 3, 6, 1, 4, 1, 3704, 1][..], suffix].concat();
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(&oid, value.clone()));
            }
            let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            Certificate::from_der(params.self_signed(&key).unwrap().der()).unwrap()
        }

        fn turin_vcek(hw_id: Vec<u8>, fmc: Option<u8>) -> Certificate {
            let mut extensions: Vec<(&[u64], Vec<u8>)> = vec![
                (&[4], hw_id),
                (&[3, 1], spl(1)),
                (&[3, 2], spl(2)),
                (&[3, 3], spl(3)),
                (&[3, 8], spl(200)),
            ];
            extensions.extend(fmc.map(|fmc| (&[3, 9][..], spl(fmc))));
            vcek(&extensions)
        }

        fn turin_report() -> AttestationReport {
            let mut report = AttestationReport {
                reported_tcb: TcbVersion {
                    fmc: Some(5),
                    bootloader: 1,
                    tee: 2,
                    snp: 3,
                    microcode: 200,
                },
                ..Default::default()
            };
            report.chip_id.0 = CHIP_ID;
            report
        }

        fn check(vcek: &Certificate, report: &AttestationReport) -> String {
            match verify_vcek_binds_report(vcek, report, AmdSnpProduct::Turin) {
                Ok(()) => String::new(),
                Err(err) => format!("{err:#}"),
            }
        }

        #[test]
        fn turin_accepts_an_8_or_64_byte_hw_id_in_either_encoding() {
            let report = turin_report();
            for hw_id in [
                CHIP_ID[..8].to_vec(),
                [&[0x04, 0x08][..], &CHIP_ID[..8]].concat(),
                CHIP_ID.to_vec(),
                [&[0x04, 0x40][..], &CHIP_ID].concat(),
            ] {
                assert_eq!(check(&turin_vcek(hw_id, Some(5)), &report), "");
            }
        }

        #[test]
        fn turin_rejects_a_mismatched_or_incomplete_vcek() {
            let report = turin_report();
            let other_chip = [0xcd; 8].to_vec();
            for (vcek, expected) in [
                (turin_vcek(other_chip, Some(5)), "hwID does not match"),
                (
                    turin_vcek(CHIP_ID[..4].to_vec(), Some(5)),
                    "invalid VCEK hwID",
                ),
                (
                    turin_vcek(CHIP_ID[..8].to_vec(), Some(6)),
                    "fmcSPL 6 does not match",
                ),
                (
                    turin_vcek(CHIP_ID[..8].to_vec(), None),
                    "missing extension 1.3.6.1.4.1.3704.1.3.9",
                ),
                (vcek(&[(&[4], CHIP_ID[..8].to_vec())]), "missing extension"),
            ] {
                let err = check(&vcek, &report);
                assert!(err.contains(expected), "{err}");
            }

            let mut masked = report;
            masked.chip_id.0 = [0; 64];
            assert!(check(&turin_vcek(vec![0; 8], Some(5)), &masked).contains("masks CHIP_ID"));
            let no_fmc = AttestationReport {
                reported_tcb: TcbVersion {
                    fmc: None,
                    ..report.reported_tcb
                },
                ..report
            };
            let err = check(&turin_vcek(CHIP_ID[..8].to_vec(), Some(5)), &no_fmc);
            assert!(err.contains("missing reported FMC"), "{err}");
        }
    }

    mod crl {
        use super::*;
        use rcgen::{
            BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa,
            KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber,
            PKCS_ECDSA_P384_SHA384,
        };
        use time::{Duration, OffsetDateTime};
        use x509_parser::time::ASN1Time;

        /// From https://kdsintf.amd.com/vcek/v1/Milan/crl, fetched 2026-11-18;
        /// valid from 2026-10-27 to 2026-12-09.
        const AMD_MILAN_CRL: &[u8] = include_bytes!("../testdata/amd-milan.crl");

        fn pem(bytes: &[u8]) -> CertBytes {
            CertBytes {
                bytes: bytes.to_vec(),
                encoding: CertEncoding::Pem,
            }
        }

        fn at(timestamp: i64) -> ASN1Time {
            ASN1Time::from_timestamp(timestamp).unwrap()
        }

        #[test]
        fn amd_crl_verifies_against_the_builtin_ark() {
            let ark = pem(builtin::milan::ARK);
            let ask = pem(builtin::milan::ASK);
            let current = at(1_794_000_000); // 2026-11-07
            assert!(!crl_revokes_ask(&ark, &ask, AMD_MILAN_CRL, current).unwrap());

            let expired = at(1_797_000_000); // 2026-12-11
            let err = crl_revokes_ask(&ark, &ask, AMD_MILAN_CRL, expired).unwrap_err();
            assert!(format!("{err:#}").contains("not current"), "{err:#}");

            let genoa = pem(builtin::genoa::ARK);
            let err = crl_revokes_ask(&genoa, &ask, AMD_MILAN_CRL, current).unwrap_err();
            assert!(
                format!("{err:#}").contains("not issued by the ARK"),
                "{err:#}"
            );

            let mut tampered = AMD_MILAN_CRL.to_vec();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            let err = crl_revokes_ask(&ark, &ask, &tampered, current).unwrap_err();
            assert!(format!("{err:#}").contains("signature"), "{err:#}");
        }

        #[test]
        fn a_revoked_ask_is_rejected() {
            let ca = |name: &str| {
                let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
                params.distinguished_name.push(DnType::CommonName, name);
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
                params.serial_number = Some(SerialNumber::from(7));
                (
                    params,
                    KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
                )
            };
            let (ark_params, ark_key) = ca("ARK");
            let ark = ark_params.self_signed(&ark_key).unwrap();
            let (ask_params, ask_key) = ca("ASK");
            let ask = ask_params.signed_by(&ask_key, &ark, &ark_key).unwrap();
            let now = OffsetDateTime::now_utc();
            let crl = |revoked_certs| {
                CertificateRevocationListParams {
                    this_update: now - Duration::days(1),
                    next_update: now + Duration::days(1),
                    crl_number: SerialNumber::from(1),
                    issuing_distribution_point: None,
                    revoked_certs,
                    key_identifier_method: KeyIdMethod::Sha256,
                }
                .signed_by(&ark, &ark_key)
                .unwrap()
                .der()
                .to_vec()
            };
            let (ark, ask) = (pem(ark.pem().as_bytes()), pem(ask.pem().as_bytes()));
            let now = ASN1Time::now();

            assert!(!crl_revokes_ask(&ark, &ask, &crl(vec![]), now).unwrap());
            let revoked = crl(vec![RevokedCertParams {
                serial_number: SerialNumber::from(7),
                revocation_time: OffsetDateTime::now_utc(),
                reason_code: None,
                invalidity_date: None,
            }]);
            assert!(crl_revokes_ask(&ark, &ask, &revoked, now).unwrap());
        }
    }

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
    fn tcb_status_is_judged_against_the_requirements_of_the_product() {
        let info = AmdSnpTcbInfo {
            current: tcb(1, 2, 3, 5),
            reported: tcb(1, 2, 3, 4),
            committed: tcb(1, 2, 3, 4),
            launch: tcb(1, 2, 3, 4),
        };
        let requirement = |product, advisory_id: &str, min_tcb| AmdSnpTcbRequirement {
            product,
            advisory_id: advisory_id.into(),
            min_tcb,
        };
        let met = requirement(AmdSnpProduct::Milan, "AMD-SB-1", tcb(1, 2, 3, 4));
        let unmet = requirement(AmdSnpProduct::Milan, "AMD-SB-2", tcb(1, 2, 3, 5));
        let other = requirement(AmdSnpProduct::Genoa, "AMD-SB-3", tcb(9, 9, 9, 9));

        let assess =
            |requirements: &[AmdSnpTcbRequirement]| info.assess(AmdSnpProduct::Milan, requirements);
        assert_eq!(assess(&[]), (String::new(), vec![]));
        assert_eq!(
            assess(std::slice::from_ref(&other)),
            (String::new(), vec![])
        );
        assert_eq!(assess(&[met.clone(), other]), ("UpToDate".into(), vec![]));
        assert_eq!(
            assess(&[met, unmet]),
            ("OutOfDate".into(), vec!["AMD-SB-2".to_string()])
        );

        let old_launch = AmdSnpTcbInfo {
            launch: tcb(1, 2, 3, 3),
            ..info
        };
        let req = [requirement(
            AmdSnpProduct::Milan,
            "AMD-SB-1",
            tcb(1, 2, 3, 4),
        )];
        assert_eq!(old_launch.assess(AmdSnpProduct::Milan, &req).0, "OutOfDate");
    }

    #[test]
    fn fmc_is_required_only_when_the_minimum_sets_it() {
        let with_fmc = |fmc| AmdSnpTcbVersion {
            fmc,
            ..tcb(1, 1, 1, 1)
        };
        assert!(with_fmc(None).meets(&with_fmc(None)));
        assert!(with_fmc(Some(2)).meets(&with_fmc(Some(2))));
        assert!(!with_fmc(Some(1)).meets(&with_fmc(Some(2))));
        assert!(!with_fmc(None).meets(&with_fmc(Some(2))));
    }

    /// `fetch_and_verify` takes the KDS branch whenever `cert_chain` is empty,
    /// and that branch reached `AttestationReport::from_bytes` with whatever
    /// the requester sent. `from_bytes` reads `bytes[0..4]` and, for an unknown
    /// version, `bytes[392]`, unguarded — so an empty report is an abort, not a
    /// rejected request. Both shapes come straight out of a `POST /verify`
    /// body.
    #[test]
    fn a_short_report_without_a_cert_chain_is_rejected_rather_than_parsed() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build a test runtime");
        let verifier = QuoteVerifier::new_prod();
        let kds = AmdKdsClient::new().expect("failed to build a KDS client");

        // Empty: `&bytes[0..4]` is out of range.
        // Four bytes of version 3: `bytes[392]` is out of range.
        for report in [vec![], vec![0x03, 0x00, 0x00, 0x00], vec![0u8; 1183]] {
            let err = runtime
                .block_on(verifier.fetch_and_verify(&kds, &report, &[], &[0u8; 64]))
                .expect_err("a short report must be rejected");
            assert!(
                err.to_string()
                    .contains("invalid amd sev-snp report length"),
                "unexpected error for a {}-byte report: {err:#}",
                report.len()
            );
        }
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

        let url = amd_kds_vcek_url_with_base(
            AMD_KDS_DEFAULT_BASE_URL,
            AmdSnpProduct::Genoa,
            &chip_id,
            tcb,
        )
        .unwrap();

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

        let url = amd_kds_vcek_url_with_base(
            AMD_KDS_DEFAULT_BASE_URL,
            AmdSnpProduct::Turin,
            &chip_id,
            tcb,
        )
        .unwrap();

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
    fn amd_kds_endpoint_joins_base_url_and_relative_path() {
        assert_eq!(
            join_amd_kds_url("https://mirror.example.com/vcek/v1/", "/Genoa/cert_chain"),
            "https://mirror.example.com/vcek/v1/Genoa/cert_chain"
        );
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

    /// Each entry names the whole blob; copying them would need about 46 GiB.
    #[test]
    fn overlapping_certificate_table_entries_are_not_copied() {
        const LEN: usize = CERT_TABLE_ENTRY_SIZE * 43_690;

        let mut auxblob = vec![0u8; LEN];
        for at in (0..LEN - CERT_TABLE_ENTRY_SIZE).step_by(CERT_TABLE_ENTRY_SIZE) {
            auxblob[at..at + 16].copy_from_slice(&[0x11u8; 16]);
            auxblob[at + 16..at + 20]
                .copy_from_slice(&(CERT_TABLE_ENTRY_SIZE as u32).to_le_bytes());
            auxblob[at + 20..at + 24]
                .copy_from_slice(&((LEN - CERT_TABLE_ENTRY_SIZE) as u32).to_le_bytes());
        }

        let err = normalize_kernel_cert_table(&auxblob).unwrap_err();
        assert!(err.to_string().contains("missing ASK"), "{err:#}");
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
