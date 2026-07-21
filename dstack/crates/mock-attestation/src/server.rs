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
        .route("/tdx/certification/v4/tcb", get(tcb_info))
        .route("/tdx/certification/v4/qe/identity", get(qe_identity))
        .route("/vcek/v1/Milan/cert_chain", get(sev_ca_chain))
        .route("/vcek/v1/Milan/{chip_id}", get(sev_vcek))
        .route("/tpm/aia/root.pem", get(tpm_root))
        .route("/tpm/aia/intermediate.der", get(tpm_intermediate))
        .route("/tpm/crl/root.crl", get(tpm_root_crl))
        .route("/tpm/crl/intermediate.crl", get(tpm_intermediate_crl))
        .route("/attest/tdx", axum::routing::post(attest_tdx))
        .route("/attest/sev-snp", axum::routing::post(attest_sev_snp))
        .route("/attest/tpm", axum::routing::post(attest_tpm))
        .route("/attest/nsm", axum::routing::post(attest_nsm))
        .with_state(state)
}

async fn attest_tdx(
    State(state): State<Arc<MockCollateralState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Ok(report_data) = <[u8; 64]>::try_from(body.as_ref()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.tdx.attest(report_data) {
        Ok(e) => binary(e.quote, None),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn attest_sev_snp(
    State(state): State<Arc<MockCollateralState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Ok(report_data) = <[u8; 64]>::try_from(body.as_ref()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state
        .sev_snp
        .attest(report_data)
        .and_then(|e| Ok(serde_json::to_vec(&e)?))
    {
        Ok(e) => binary(e, None),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn attest_tpm(
    State(state): State<Arc<MockCollateralState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match state
        .tpm
        .attest(&body)
        .and_then(|e| Ok(serde_json::to_vec(&e)?))
    {
        Ok(e) => binary(e, None),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn attest_nsm(
    State(state): State<Arc<MockCollateralState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match state.nsm.attest(&body) {
        Ok(e) => binary(e, None),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
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
    binary(
        state.tdx.root_crl_der(),
        Some(("SGX-PCK-CRL-Issuer-Chain", state.tdx.root_ca_pem())),
    )
}

async fn tcb_info(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    let collateral = state.tdx.sample_collateral().unwrap();
    json_response(
        json!({"tcbInfo": serde_json::from_str::<serde_json::Value>(&collateral.tcb_info).unwrap(), "signature": hex::encode(collateral.tcb_info_signature)}),
        Some((
            "SGX-TCB-Info-Issuer-Chain",
            collateral.tcb_info_issuer_chain,
        )),
    )
}

async fn qe_identity(State(state): State<Arc<MockCollateralState>>) -> impl IntoResponse {
    let collateral = state.tdx.sample_collateral().unwrap();
    json_response(
        json!({"enclaveIdentity": serde_json::from_str::<serde_json::Value>(&collateral.qe_identity).unwrap(), "signature": hex::encode(collateral.qe_identity_signature)}),
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
        response.headers_mut().insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(&urlencoding::encode(&value)).unwrap(),
        );
    }
    response
}

fn binary(value: Vec<u8>, header: Option<(&str, String)>) -> Response<Body> {
    let mut response = Response::new(Body::from(value));
    *response.status_mut() = StatusCode::OK;
    if let Some((name, value)) = header {
        response.headers_mut().insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(&urlencoding::encode(&value)).unwrap(),
        );
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
    async fn dynamic_attestation_endpoints_pass_all_real_qvls() {
        let state = Arc::new(MockCollateralState::new().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_listener(listener, state.clone()));
        let base = format!("http://{addr}/attest");
        let client = reqwest::Client::new();

        let tdx = client
            .post(format!("{base}/tdx"))
            .body(vec![0x11; 64])
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let tdx_collateral = state.tdx.sample_collateral().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        dcap_qvl::verify::QuoteVerifier::new(state.tdx.root_ca_der())
            .verify(&tdx, &tdx_collateral, now)
            .unwrap();

        let sev = client
            .post(format!("{base}/sev-snp"))
            .body(vec![0x12; 64])
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let sev: crate::sev_snp::SevSnpEvidence = serde_json::from_slice(&sev).unwrap();
        sev_snp_qvl::QuoteVerifier::new_with_root(
            sev_snp_qvl::AmdSnpProduct::Milan,
            state.sev_snp.root_ca_pem().into_bytes(),
        )
        .verify(&sev.report, &sev.cert_chain, &[0x12; 64])
        .unwrap();

        let tpm = client
            .post(format!("{base}/tpm"))
            .body(vec![0x13; 32])
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let tpm: tpm_types::TpmQuote = serde_json::from_slice(&tpm).unwrap();
        tpm_qvl::QuoteVerifier::new(state.tpm.root_ca_pem())
            .verify(&tpm, &state.tpm.collateral())
            .unwrap();

        let nsm = client
            .post(format!("{base}/nsm"))
            .body(vec![0x14; 64])
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        nsm_qvl::QuoteVerifier::new(state.nsm.root_ca_pem())
            .verify(&nsm, None, None)
            .unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_attest_clients_use_dynamic_simulator_evidence() {
        static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _guard = ENV_LOCK.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state =
            Arc::new(MockCollateralState::with_base_url(&format!("http://{addr}")).unwrap());
        let task = tokio::spawn(serve_listener(listener, state.clone()));
        std::env::set_var("DSTACK_MOCK_ATTESTATION_URL", format!("http://{addr}"));

        let rd = [0x51; 64];
        let tdx = tdx_attest::get_quote(&rd).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        dcap_qvl::verify::QuoteVerifier::new(state.tdx.root_ca_der())
            .verify(&tdx, &state.tdx.sample_collateral().unwrap(), now)
            .unwrap();

        let sev = sev_snp_attest::get_report(rd).unwrap();
        sev_snp_qvl::QuoteVerifier::new_with_root(
            sev_snp_qvl::AmdSnpProduct::Milan,
            state.sev_snp.root_ca_pem().into_bytes(),
        )
        .verify(&sev.report, &sev.cert_chain, &rd)
        .unwrap();

        let nsm = nsm_attest::NsmContext::new()
            .unwrap()
            .get_attestation_doc(Some(&rd), None, None)
            .unwrap();
        nsm_qvl::QuoteVerifier::new(state.nsm.root_ca_pem())
            .verify(&nsm, None, None)
            .unwrap();

        let qualifying = [0x52; 32];
        let tpm = tpm_attest::TpmContext::detect()
            .unwrap()
            .create_quote(&qualifying, &tpm_types::PcrSelection::sha256(&[14]))
            .unwrap();
        tpm_qvl::QuoteVerifier::new(state.tpm.root_ca_pem())
            .verify(&tpm, &state.tpm.collateral())
            .unwrap();

        std::env::remove_var("DSTACK_MOCK_ATTESTATION_URL");
        task.abort();
    }
}
