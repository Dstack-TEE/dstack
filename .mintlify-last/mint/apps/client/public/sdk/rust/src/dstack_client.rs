use anyhow::Result;
use hex::{encode as hex_encode, FromHexError};
use http_client_unix_domain_socket::{ClientUnix, Method};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::env;

const INIT_MR: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn replay_rtmr(history: Vec<String>) -> Result<String, FromHexError> {
    if history.is_empty() {
        return Ok(INIT_MR.to_string());
    }
    let mut mr = hex::decode(INIT_MR)?;
    for content in history {
        let mut content_bytes = hex::decode(content)?;
        if content_bytes.len() < 48 {
            content_bytes.resize(48, 0);
        }
        mr.extend_from_slice(&content_bytes);
        mr = sha2::Sha384::digest(&mr).to_vec();
    }
    Ok(hex_encode(mr))
}

fn get_endpoint(endpoint: Option<&str>) -> String {
    if let Some(e) = endpoint {
        return e.to_string();
    }
    if let Ok(sim_endpoint) = env::var("DSTACK_SIMULATOR_ENDPOINT") {
        return sim_endpoint;
    }
    "/var/run/dstack.sock".to_string()
}

#[derive(Debug)]
pub enum ClientKind {
    Http,
    Unix,
}

#[derive(Serialize, Deserialize)]
pub struct EventLog {
    imr: u32,
    event_type: u32,
    digest: String,
    event: String,
    event_payload: String,
}

#[derive(bon::Builder, Serialize)]
pub struct TlsKeyConfig {
    #[builder(into, default = String::new())]
    pub subject: String,
    #[builder(default = Vec::new())]
    pub alt_names: Vec<String>,
    #[builder(default = false)]
    pub usage_ra_tls: bool,
    #[builder(default = true)]
    pub usage_server_auth: bool,
    #[builder(default = false)]
    pub usage_client_auth: bool,
}

#[derive(Serialize, Deserialize)]
pub struct GetKeyResponse {
    pub key: String,
    pub signature_chain: Vec<String>,
}

impl GetKeyResponse {
    pub fn decode_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.key)
    }

    pub fn decode_signature_chain(&self) -> Result<Vec<Vec<u8>>, FromHexError> {
        self.signature_chain.iter().map(hex::decode).collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetQuoteResponse {
    pub quote: String,
    pub event_log: String,
}

impl GetQuoteResponse {
    pub fn decode_quote(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.quote)
    }

    pub fn decode_event_log(&self) -> Result<Vec<EventLog>, serde_json::Error> {
        serde_json::from_str(&self.event_log)
    }

    pub fn replay_rtmrs(&self) -> Result<HashMap<u8, String>> {
        let parsed_event_log: Vec<EventLog> = self.decode_event_log()?;
        let mut rtmrs = HashMap::new();
        for idx in 0..4 {
            let mut history = vec![];
            for event in &parsed_event_log {
                if event.imr == idx {
                    history.push(event.digest.clone());
                }
            }
            rtmrs.insert(idx as u8, replay_rtmr(history)?);
        }
        Ok(rtmrs)
    }
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    app_id: String,
    instance_id: String,
    app_cert: String,
    tcb_info: TcbInfo,
    app_name: String,
    public_logs: bool,
    public_sysinfo: bool,
    device_id: String,
    mr_aggregated: String,
    os_image_hash: String,
    mr_key_provider: String,
    key_provider_info: String,
    compose_hash: String,
}

impl InfoResponse {
    pub fn validated_from_value(mut obj: Value) -> Result<Self, serde_json::Error> {
        if let Some(tcb_info_str) = obj.get("tcb_info").and_then(Value::as_str) {
            let parsed_tcb_info: TcbInfo = from_str(tcb_info_str)?;
            obj["tcb_info"] = serde_json::to_value(parsed_tcb_info)?;
        }
        serde_json::from_value(obj)
    }
}

#[derive(Serialize, Deserialize)]
struct TcbInfo {
    mrtd: String,
    rootfs_hash: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    event_log: Vec<EventLog>,
}

#[derive(Serialize, Deserialize)]
pub struct GetTlsKeyResponse {
    pub key: String,
    pub certificate_chain: Vec<String>,
}

pub trait BaseClient {}

pub struct DstackClient {
    base_url: String,
    endpoint: String,
    client: ClientKind,
}

impl BaseClient for DstackClient {}

impl DstackClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        let endpoint = get_endpoint(endpoint);
        let (base_url, client) = match endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), ClientKind::Http)
            }
            _ => ("http://localhost".to_string(), ClientKind::Unix),
        };

        DstackClient {
            base_url,
            endpoint,
            client,
        }
    }

    async fn send_rpc_request<S: Serialize, D: DeserializeOwned>(
        &self,
        path: &str,
        payload: &S,
    ) -> anyhow::Result<D> {
        match &self.client {
            ClientKind::Http => {
                let client = Client::new();
                let url = format!(
                    "{}/{}",
                    self.base_url.trim_end_matches('/'),
                    path.trim_start_matches('/')
                );
                let res = client
                    .post(&url)
                    .json(payload)
                    .header("Content-Type", "application/json")
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(res.json().await?)
            }
            ClientKind::Unix => {
                let mut unix_client = ClientUnix::try_new(&self.endpoint).await?;
                let res = unix_client
                    .send_request_json::<_, _, Value>(
                        path,
                        Method::POST,
                        &[("Content-Type", "application/json")],
                        Some(&payload),
                    )
                    .await?;
                Ok(res.1)
            }
        }
    }

    pub async fn get_key(
        &self,
        path: Option<String>,
        purpose: Option<String>,
    ) -> Result<GetKeyResponse> {
        let data = json!({
            "path": path.unwrap_or_default(),
            "purpose": purpose.unwrap_or_default(),
        });
        let response = self.send_rpc_request("/GetKey", &data).await?;
        let response = serde_json::from_value::<GetKeyResponse>(response)?;

        Ok(response)
    }

    pub async fn get_quote(&self, report_data: Vec<u8>) -> Result<GetQuoteResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            anyhow::bail!("Invalid report data length")
        }
        let hex_data = hex_encode(report_data);
        let data = json!({ "report_data": hex_data });
        let response = self.send_rpc_request("/GetQuote", &data).await?;
        let response = serde_json::from_value::<GetQuoteResponse>(response)?;

        Ok(response)
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let response = self.send_rpc_request("/Info", &json!({})).await?;
        Ok(InfoResponse::validated_from_value(response)?)
    }

    pub async fn emit_event(&self, event: String, payload: Vec<u8>) -> Result<()> {
        if event.is_empty() {
            anyhow::bail!("Event name cannot be empty")
        }
        let hex_payload = hex_encode(payload);
        let data = json!({ "event": event, "payload": hex_payload });
        self.send_rpc_request::<_, ()>("/EmitEvent", &data).await?;
        Ok(())
    }

    pub async fn get_tls_key(&self, tls_key_config: TlsKeyConfig) -> Result<GetTlsKeyResponse> {
        let response = self.send_rpc_request("/GetTlsKey", &tls_key_config).await?;
        let response = serde_json::from_value::<GetTlsKeyResponse>(response)?;

        Ok(response)
    }
}
