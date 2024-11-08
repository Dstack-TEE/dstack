use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bollard::{container::ListContainersOptions, Docker};
use ra_rpc::{Attestation, RpcCall};
use ra_tls::{
    cert::{CaCert, CertRequest},
    kdf::derive_ecdsa_key_pair,
    qvl::quote::Report,
};
use serde_json::json;
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    worker_server::{WorkerRpc, WorkerServer},
    Container, DeriveKeyArgs, DeriveKeyResponse, ListContainersResponse, TdxQuoteArgs,
    TdxQuoteResponse, WorkerInfo,
};

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    ca: CaCert,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self> {
        let ca = CaCert::load(&config.cert_file, &config.key_file)
            .context("Failed to load CA certificate")?;
        Ok(Self {
            inner: Arc::new(AppStateInner { ca }),
        })
    }
}

pub struct InternalRpcHandler {
    state: AppState,
}

impl TappdRpc for InternalRpcHandler {
    async fn derive_key(self, request: DeriveKeyArgs) -> Result<DeriveKeyResponse> {
        let derived_key =
            derive_ecdsa_key_pair(&self.state.inner.ca.key, &[request.path.as_bytes()])
                .context("Failed to derive key")?;
        let req = CertRequest::builder()
            .subject(&request.subject)
            .key(&derived_key)
            .build();
        let cert = self
            .state
            .inner
            .ca
            .sign(req)
            .context("Failed to sign certificate")?;
        Ok(DeriveKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain: vec![cert.pem(), self.state.inner.ca.cert.pem()],
        })
    }

    async fn tdx_quote(self, request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let todo = "add the event log to the response";
        let todo = "define the report data format";
        let report_data = sha2_512(&request.report_data);
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;
        Ok(TdxQuoteResponse {
            quote,
            event_log: Default::default(),
        })
    }
}

impl RpcCall<AppState> for InternalRpcHandler {
    type PrpcService = TappdServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TappdServer::new(self)
    }

    fn construct(state: &AppState, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(InternalRpcHandler {
            state: state.clone(),
        })
    }
}

fn sha2_512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub struct ExternalRpcHandler {
    state: AppState,
}

impl WorkerRpc for ExternalRpcHandler {
    async fn info(self) -> Result<WorkerInfo> {
        let ca = &self.state.inner.ca;
        let Some(attestation) = ca.decode_attestation().ok().flatten() else {
            return Ok(WorkerInfo::default());
        };
        let app_id = attestation
            .decode_app_id()
            .context("Failed to decode app id")?;
        let instance_id = attestation
            .decode_instance_id()
            .context("Failed to decode instance_id")?;
        let quote = attestation
            .decode_quote()
            .context("Failed to decode quote")?;
        let rootfs_hash = attestation
            .decode_rootfs_hash()
            .context("Failed to decode rootfs hash")?;
        let report = match &quote.report {
            Report::SgxEnclave(_) => bail!("SGX reports are not supported"),
            Report::TD10(tdreport10) => &tdreport10,
            Report::TD15(tdreport15) => &tdreport15.base,
        };
        let mrtd = hex::encode(&report.mr_td);
        let rtmr0 = hex::encode(&report.rt_mr0);
        let rtmr1 = hex::encode(&report.rt_mr1);
        let rtmr2 = hex::encode(&report.rt_mr2);
        let rtmr3 = hex::encode(&report.rt_mr3);
        let tcb_info = serde_json::to_string_pretty(&json!({
            "rootfs_hash": rootfs_hash,
            "mrtd": mrtd,
            "rtmr0": rtmr0,
            "rtmr1": rtmr1,
            "rtmr2": rtmr2,
            "rtmr3": rtmr3,
        }))
        .unwrap_or_default();
        Ok(WorkerInfo {
            app_id,
            instance_id,
            app_cert: ca.pem_cert.clone(),
            tcb_info,
        })
    }

    async fn list_containers(self) -> Result<ListContainersResponse> {
        list_containers().await
    }
}

pub(crate) async fn list_containers() -> Result<ListContainersResponse> {
    let docker = Docker::connect_with_defaults().context("Failed to connect to Docker")?;
    let containers = docker
        .list_containers::<&str>(Some(ListContainersOptions {
            all: true,
            ..Default::default()
        }))
        .await
        .context("Failed to list containers")?;
    Ok(ListContainersResponse {
        containers: containers
            .into_iter()
            .map(|c| Container {
                id: c.id.unwrap_or_default(),
                names: c.names.unwrap_or_default(),
                image: c.image.unwrap_or_default(),
                image_id: c.image_id.unwrap_or_default(),
                command: c.command.unwrap_or_default(),
                created: c.created.unwrap_or_default(),
                state: c.state.unwrap_or_default(),
                status: c.status.unwrap_or_default(),
            })
            .collect(),
    })
}

impl RpcCall<AppState> for ExternalRpcHandler {
    type PrpcService = WorkerServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        WorkerServer::new(self)
    }

    fn construct(state: &AppState, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(ExternalRpcHandler {
            state: state.clone(),
        })
    }
}
