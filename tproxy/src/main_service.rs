use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    process::Command,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{bail, Context, Result};
use certbot::WorkDir;
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use rinja::Template as _;
use tproxy_rpc::{
    tproxy_server::{TproxyRpc, TproxyServer},
    AcmeInfoResponse, HostInfo as PbHostInfo, ListResponse, RegisterCvmRequest,
    RegisterCvmResponse, TappdConfig, WireGuardConfig,
};
use tracing::{error, info};

use crate::{
    config::Config,
    models::{InstanceInfo, WgConf},
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<AppStateInner>>,
}

pub(crate) struct AppStateInner {
    config: Config,
    // The mapping from the host name to the IP address.
    apps: BTreeMap<String, BTreeSet<String>>,
    instances: BTreeMap<String, InstanceInfo>,
    allocated_addresses: BTreeSet<Ipv4Addr>,
}

impl AppState {
    pub(crate) fn lock(&self) -> MutexGuard<AppStateInner> {
        self.inner.lock().expect("failed to lock AppState")
    }

    pub fn new(config: Config) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(AppStateInner {
                config,
                apps: BTreeMap::new(),
                instances: BTreeMap::new(),
                allocated_addresses: BTreeSet::new(),
            })),
        })
    }
}

impl AppStateInner {
    fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for ip in self.config.wg.client_ip_range.hosts() {
            if ip == self.config.wg.ip {
                continue;
            }
            if self.allocated_addresses.contains(&ip) {
                continue;
            }
            self.allocated_addresses.insert(ip);
            return Some(ip);
        }
        None
    }

    fn new_client_by_id(
        &mut self,
        id: &str,
        app_id: &str,
        public_key: &str,
    ) -> Option<InstanceInfo> {
        let ip = self.alloc_ip()?;
        if let Some(existing) = self.instances.get(id) {
            if existing.public_key == public_key {
                return Some(existing.clone());
            }
        }
        let host_info = InstanceInfo {
            id: id.to_string(),
            app_id: app_id.to_string(),
            ip,
            public_key: public_key.to_string(),
        };
        let todo = "support for multiple clients per app";
        self.instances.insert(id.to_string(), host_info.clone());
        self.apps
            .entry(app_id.to_string())
            .or_default()
            .insert(id.to_string());
        if let Err(err) = self.reconfigure() {
            error!("failed to reconfigure: {}", err);
        }
        Some(host_info)
    }

    fn generate_wg_config(&self) -> Result<String> {
        let model = WgConf {
            private_key: &self.config.wg.private_key,
            listen_port: self.config.wg.listen_port,
            peers: (&self.instances).into(),
        };
        Ok(model.render()?)
    }

    pub(crate) fn reconfigure(&mut self) -> Result<()> {
        let wg_config = self.generate_wg_config()?;
        fs::write(&self.config.wg.config_path, wg_config)?;
        // wg setconf <interface_name> <config_path>
        let output = Command::new("wg")
            .arg("syncconf")
            .arg(&self.config.wg.interface)
            .arg(&self.config.wg.config_path)
            .output()?;

        if !output.status.success() {
            error!("failed to set wg config: {}", output.status);
        } else {
            info!("wg config updated");
        }
        Ok(())
    }

    pub(crate) fn select_a_host(&self, id: &str) -> Option<InstanceInfo> {
        if let Some(info) = self.instances.get(id).cloned() {
            return Some(info);
        }
        let app_instances = self.apps.get(id)?;
        let todo = "load balance";
        let selected = app_instances.iter().next()?;
        self.instances.get(selected).cloned()
    }
}

pub struct RpcHandler {
    attestation: Option<Attestation>,
    state: AppState,
}

impl TproxyRpc for RpcHandler {
    async fn register_cvm(self, request: RegisterCvmRequest) -> Result<RegisterCvmResponse> {
        let Some(ra) = &self.attestation else {
            bail!("no attestation provided");
        };
        let app_id = ra
            .decode_app_id()
            .context("failed to decode app-id from attestation")?;
        let instance_id = ra
            .decode_instance_id()
            .context("failed to decode instance-id from attestation")?;
        let mut state = self.state.lock();
        let client_info = state
            .new_client_by_id(&instance_id, &app_id, &request.client_public_key)
            .context("failed to allocate IP address for client")?;

        Ok(RegisterCvmResponse {
            wg: Some(WireGuardConfig {
                server_public_key: state.config.wg.public_key.clone(),
                client_ip: client_info.ip.to_string(),
                server_ip: state.config.wg.ip.to_string(),
                server_endpoint: state.config.wg.endpoint.clone(),
            }),
            tappd: Some(TappdConfig {
                external_port: state.config.proxy.listen_port as u32,
                internal_port: state.config.proxy.tappd_port as u32,
                domain: state.config.proxy.base_domain.clone(),
            }),
        })
    }

    async fn list(self) -> Result<ListResponse> {
        let state = self.state.lock();
        let base_domain = &state.config.proxy.base_domain;
        let hosts = state
            .instances
            .values()
            .map(|instance| PbHostInfo {
                id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain: base_domain.clone(),
                port: state.config.proxy.listen_port as u32,
            })
            .collect::<Vec<_>>();
        Ok(ListResponse { hosts })
    }

    async fn acme_info(self) -> Result<AcmeInfoResponse> {
        let state = self.state.lock();
        let workdir = WorkDir::new(&state.config.certbot.workdir);
        let account_uri = workdir.acme_account_uri().unwrap_or_default();
        let keys = workdir.list_cert_public_keys().unwrap_or_default();
        Ok(AcmeInfoResponse {
            account_uri,
            hist_keys: keys.into_iter().collect(),
        })
    }
}

impl RpcCall<AppState> for RpcHandler {
    type PrpcService = TproxyServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TproxyServer::new(self)
    }

    fn construct(state: &AppState, attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            attestation,
            state: state.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
