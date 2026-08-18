// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    body::Body,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderValue, Response, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use serde_json::json;

use crate::{nsm::NsmGenerator, sev_snp::SevSnpGenerator, tdx::TdxGenerator, tpm::TpmGenerator};

pub struct MockCollateralState {
    pub tdx: Arc<TdxGenerator>,
    pub sev_snp: Arc<SevSnpGenerator>,
    pub tpm: Arc<TpmGenerator>,
    pub nsm: Arc<NsmGenerator>,
}

impl MockCollateralState {
    pub fn new() -> Result<Self> {
        Self::with_base_url("http://127.0.0.1:8088")
    }

    pub fn with_base_url(base_url: &str) -> Result<Self> {
        Self::from_seed(rand::random(), base_url)
    }

    pub fn from_seed(seed: [u8; 32], base_url: &str) -> Result<Self> {
        Ok(Self {
            tdx: Arc::new(TdxGenerator::from_seed(seed)?),
            sev_snp: Arc::new(SevSnpGenerator::from_seed(seed)?),
            tpm: Arc::new(TpmGenerator::from_seed(seed, base_url)?),
            nsm: Arc::new(NsmGenerator::from_seed(seed)?),
        })
    }

    pub fn write_roots(&self, output: &std::path::Path) -> Result<()> {
        fs_err::create_dir_all(output)?;
        fs_err::write(output.join("tdx-root-ca.pem"), self.tdx.root_ca_pem())?;
        fs_err::write(
            output.join("sev-snp-root-ca.pem"),
            self.sev_snp.root_ca_pem(),
        )?;
        fs_err::write(output.join("tpm-root-ca.pem"), self.tpm.root_ca_pem())?;
        fs_err::write(output.join("nsm-root-ca.pem"), self.nsm.root_ca_pem())?;
        Ok(())
    }
}

pub fn router(state: Arc<MockCollateralState>) -> Router {
    Router::new()
        .route("/sgx/certification/v4/pckcrl", get(pck_crl))
        .route("/sgx/certification/v4/rootcacrl", get(pccs_root_crl))
        // Older guest images use the SGX PCS prefix for shared DCAP collateral.
        // Serve both spellings so simulated TDX evidence remains compatible.
        .route("/sgx/certification/v4/tcb", get(tcb_info))
        .route("/sgx/certification/v4/qe/identity", get(qe_identity))
        .route("/tdx/certification/v4/tcb", get(tcb_info))
        .route("/tdx/certification/v4/qe/identity", get(qe_identity))
        .route("/vcek/v1/Milan/cert_chain", get(sev_ca_chain))
        .route("/vcek/v1/Milan/{chip_id}", get(sev_vcek))
        .route("/tpm/aia/root.pem", get(tpm_root))
        .route("/tpm/aia/intermediate.der", get(tpm_intermediate))
        .route("/tpm/crl/root.crl", get(tpm_root_crl))
        .route("/tpm/crl/intermediate.crl", get(tpm_intermediate_crl))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, state: Arc<MockCollateralState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_listener(listener, state).await
}

pub async fn serve_listener(
    listener: tokio::net::TcpListener,
    state: Arc<MockCollateralState>,
) -> Result<()> {
    axum::serve(listener, router(state)).await?;
    Ok(())
}

async fn pccs_root_crl(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(hex::encode(state.tdx.root_crl_der()).into_bytes(), None)
}

async fn pck_crl(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    let Ok(collateral) = state.tdx.sample_collateral() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    binary(
        state.tdx.pck_crl_der(),
        Some(("SGX-PCK-CRL-Issuer-Chain", collateral.pck_crl_issuer_chain)),
    )
}

async fn tcb_info(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    let Ok(collateral) = state.tdx.sample_collateral() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(tcb_info) = serde_json::from_str::<serde_json::Value>(&collateral.tcb_info) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    json_response(
        json!({"tcbInfo": tcb_info, "signature": hex::encode(collateral.tcb_info_signature)}),
        Some((
            "SGX-TCB-Info-Issuer-Chain",
            collateral.tcb_info_issuer_chain,
        )),
    )
}

async fn qe_identity(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    let Ok(collateral) = state.tdx.sample_collateral() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(qe_identity) = serde_json::from_str::<serde_json::Value>(&collateral.qe_identity) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    json_response(
        json!({"enclaveIdentity": qe_identity, "signature": hex::encode(collateral.qe_identity_signature)}),
        Some((
            "SGX-Enclave-Identity-Issuer-Chain",
            collateral.qe_identity_issuer_chain,
        )),
    )
}

async fn sev_ca_chain(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(state.sev_snp.ca_chain_pem(), None)
}

async fn sev_vcek(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(state.sev_snp.vcek_der(), None)
}

async fn tpm_root(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(state.tpm.root_ca_der(), None)
}
async fn tpm_intermediate(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(state.tpm.intermediate_der(), None)
}
async fn tpm_root_crl(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(state.tpm.root_crl_der(), None)
}
async fn tpm_intermediate_crl(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    binary(state.tpm.intermediate_crl_der(), None)
}

fn json_response(value: serde_json::Value, header: Option<(&str, String)>) -> Response<Body> {
    let mut response = Response::new(Body::from(value.to_string()));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some((name, value)) = header {
        let Ok(name) = axum::http::HeaderName::from_bytes(name.as_bytes()) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let Ok(value) = HeaderValue::from_str(&urlencoding::encode(&value)) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        response.headers_mut().insert(name, value);
    }
    response
}

fn binary(value: Vec<u8>, header: Option<(&str, String)>) -> Response<Body> {
    let mut response = Response::new(Body::from(value));
    *response.status_mut() = StatusCode::OK;
    if let Some((name, value)) = header {
        let Ok(name) = axum::http::HeaderName::from_bytes(name.as_bytes()) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let Ok(value) = HeaderValue::from_str(&urlencoding::encode(&value)) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        response.headers_mut().insert(name, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn independent_host_and_guest_from_sys_config_seed_interoperate() {
        let seed = [0x5a; 32];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        // These states model separate host and CVM processes. No certificates,
        // keys, or Arc state are exchanged after construction.
        let host = Arc::new(MockCollateralState::from_seed(seed, &url).unwrap());
        let guest = MockCollateralState::from_seed(seed, &url).unwrap();
        let task = tokio::spawn(serve_listener(listener, host.clone()));

        let report_data = [0x61; 64];
        let tdx = guest.tdx.attest(report_data).unwrap();
        let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(&url)
            .unwrap()
            .fetch(&tdx.quote)
            .await
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tdx_verifier = dcap_qvl::verify::QuoteVerifier::new(host.tdx.root_ca_der());
        tdx_verifier.verify(&tdx.quote, &collateral, now).unwrap();
        let mut tampered = tdx.quote.clone();
        tampered[200] ^= 1;
        assert!(tdx_verifier.verify(&tampered, &collateral, now).is_err());

        let sev = guest.sev_snp.attest(report_data).unwrap();
        let sev_verifier = sev_snp_qvl::QuoteVerifier::new_with_root(
            sev_snp_qvl::AmdSnpProduct::Milan,
            host.sev_snp.root_ca_pem().into_bytes(),
        );
        sev_verifier
            .verify(&sev.report, &sev.cert_chain, &report_data)
            .unwrap();
        assert!(sev_verifier
            .verify(&sev.report, &sev.cert_chain, &[0x62; 64])
            .is_err());

        let qualifying = [0x63; 32];
        let tpm = guest.tpm.attest(&qualifying).unwrap();
        let tpm_verifier = tpm_qvl::QuoteVerifier::new(host.tpm.root_ca_pem());
        tpm_verifier.verify(&tpm, &host.tpm.collateral()).unwrap();
        assert!(crate::ensure_report_data(&qualifying, &[0x64; 32]).is_err());

        let nsm = guest.nsm.attest(&report_data).unwrap();
        let verified = nsm_qvl::QuoteVerifier::new(host.nsm.root_ca_pem())
            .verify(&nsm, None, None)
            .unwrap();
        assert_eq!(verified.user_data.as_deref(), Some(report_data.as_slice()));

        let wrong = MockCollateralState::from_seed([0xa5; 32], &url).unwrap();
        assert!(nsm_qvl::QuoteVerifier::new(wrong.nsm.root_ca_pem())
            .verify(&nsm, None, None)
            .is_err());
        task.abort();
    }

    #[tokio::test]
    async fn mock_pccs_and_kds_drive_real_qvls() {
        let state = Arc::new(MockCollateralState::new().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_listener(listener, state.clone()));
        let base = format!("http://{addr}");

        let tdx_evidence = state.tdx.attest([0x42; 64]).unwrap();
        let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(&base)
            .unwrap()
            .fetch(&tdx_evidence.quote)
            .await
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        dcap_qvl::verify::QuoteVerifier::new(state.tdx.root_ca_der())
            .verify(&tdx_evidence.quote, &collateral, now)
            .unwrap();

        let sev_evidence = state.sev_snp.attest([0x43; 64]).unwrap();
        let kds = sev_snp_qvl::AmdKdsClient::with_base_url(format!("{base}/vcek/v1")).unwrap();
        sev_snp_qvl::QuoteVerifier::new_with_root(
            sev_snp_qvl::AmdSnpProduct::Milan,
            state.sev_snp.root_ca_pem().into_bytes(),
        )
        .fetch_and_verify(&kds, &sev_evidence.report, &[], &[0x43; 64])
        .await
        .unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn tdx_quote_collateral_and_tcb_matrix() {
        let state = Arc::new(MockCollateralState::new().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let mut task = tokio::spawn(serve_listener(listener, state.clone()));
        let evidence = state.tdx.attest([0x42; 64]).unwrap();
        let client = dcap_qvl::collateral::CollateralClient::with_default_http(&base).unwrap();
        let current = client.fetch(&evidence.quote).await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let verifier = dcap_qvl::verify::QuoteVerifier::new(state.tdx.root_ca_der());
        assert_eq!(
            verifier
                .verify(&evidence.quote, &current, now)
                .unwrap()
                .status,
            "UpToDate"
        );

        let mut tampered_quote = evidence.quote.clone();
        tampered_quote[200] ^= 1;
        assert!(verifier.verify(&tampered_quote, &current, now).is_err());

        task.abort();
        let _ = task.await;
        assert!(verifier.verify(&evidence.quote, &current, now).is_ok());
        assert!(client.fetch(&evidence.quote).await.is_err());

        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        task = tokio::spawn(serve_listener(listener, state.clone()));
        let recovered = client.fetch(&evidence.quote).await.unwrap();
        assert!(verifier.verify(&evidence.quote, &recovered, now).is_ok());

        let mut outdated = state
            .tdx
            .sample_collateral_with_tcb_status("OutOfDate")
            .unwrap();
        outdated.pck_certificate_chain = recovered.pck_certificate_chain.clone();
        assert_eq!(
            verifier
                .verify(&evidence.quote, &outdated, now)
                .unwrap()
                .status,
            "OutOfDate"
        );

        let mut revoked = state
            .tdx
            .sample_collateral_with_tcb_status("Revoked")
            .unwrap();
        revoked.pck_certificate_chain = recovered.pck_certificate_chain.clone();
        assert!(verifier.verify(&evidence.quote, &revoked, now).is_err());

        let expired_time = 4_200_000_000;
        assert!(verifier
            .verify(&evidence.quote, &recovered, expired_time)
            .is_err());

        let mut signature_invalid = recovered.clone();
        signature_invalid.tcb_info_signature[0] ^= 1;
        assert!(verifier
            .verify(&evidence.quote, &signature_invalid, now)
            .is_err());

        let mut malformed = recovered.clone();
        malformed.tcb_info = "{".into();
        assert!(verifier.verify(&evidence.quote, &malformed, now).is_err());
        task.abort();
    }

    #[tokio::test]
    async fn tpm_aia_and_crl_service_builds_verifiable_collateral() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state =
            Arc::new(MockCollateralState::with_base_url(&format!("http://{addr}")).unwrap());
        let task = tokio::spawn(serve_listener(listener, state.clone()));
        let quote = state.tpm.attest(&[0x42; 32]).unwrap();
        let root = state.tpm.root_ca_pem();
        let q = quote.clone();
        let collateral = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime
                .block_on(tpm_qvl::get_collateral(&q, &root))
                .unwrap()
        })
        .await
        .unwrap();
        tpm_qvl::QuoteVerifier::new(state.tpm.root_ca_pem())
            .verify(&quote, &collateral)
            .unwrap();
        task.abort();
    }
}
