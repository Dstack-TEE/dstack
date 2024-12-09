use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    process::Command,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use certbot::WorkDir;
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use rand::seq::IteratorRandom;
use rinja::Template as _;
use serde::{Deserialize, Serialize};
use tproxy_rpc::{
    tproxy_server::{TproxyRpc, TproxyServer},
    AcmeInfoResponse, GetInfoRequest, GetInfoResponse, HostInfo as PbHostInfo, ListResponse,
    RegisterCvmRequest, RegisterCvmResponse, TappdConfig, WireGuardConfig, GetMetaResponse,
};
use tracing::{debug, error, info};

use crate::{
    config::Config,
    models::{InstanceInfo, WgConf},
};

#[derive(Clone)]
pub struct AppState {
    pub(crate) config: Arc<Config>,
    inner: Arc<Mutex<AppStateInner>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct State {
    apps: BTreeMap<String, BTreeSet<String>>,
    instances: BTreeMap<String, InstanceInfo>,
    allocated_addresses: BTreeSet<Ipv4Addr>,
}

pub(crate) struct AppStateInner {
    config: Arc<Config>,
    state: State,
}

impl AppState {
    pub(crate) fn lock(&self) -> MutexGuard<AppStateInner> {
        self.inner.lock().expect("Failed to lock AppState")
    }

    pub fn new(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let state_path = &config.state_path;
        let state = if fs::metadata(state_path).is_ok() {
            let state_str = fs::read_to_string(state_path).context("Failed to read state")?;
            serde_json::from_str(&state_str).context("Failed to load state")?
        } else {
            State {
                apps: BTreeMap::new(),
                instances: BTreeMap::new(),
                allocated_addresses: BTreeSet::new(),
            }
        };
        let inner = Arc::new(Mutex::new(AppStateInner {
            config: config.clone(),
            state,
        }));
        start_recycle_thread(Arc::downgrade(&inner), config.clone());
        Ok(Self { config, inner })
    }
}

fn start_recycle_thread(state: Weak<Mutex<AppStateInner>>, config: Arc<Config>) {
    if !config.recycle.enabled {
        info!("recycle is disabled");
        return;
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(config.recycle.interval);
        let Some(state) = state.upgrade() else {
            break;
        };
        if let Err(err) = state.lock().unwrap().recycle() {
            error!("failed to run recycle: {err}");
        };
    });
}

impl AppStateInner {
    fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for ip in self.config.wg.client_ip_range.hosts() {
            if ip == self.config.wg.ip {
                continue;
            }
            if self.state.allocated_addresses.contains(&ip) {
                continue;
            }
            self.state.allocated_addresses.insert(ip);
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
        if id.is_empty() || public_key.is_empty() || app_id.is_empty() {
            return None;
        }
        if let Some(existing) = self.state.instances.get_mut(id) {
            if existing.public_key != public_key {
                info!("public key changed for instance {id}, new key: {public_key}");
                existing.public_key = public_key.to_string();
            }
            return Some(existing.clone());
        }
        let ip = self.alloc_ip()?;
        let host_info = InstanceInfo {
            id: id.to_string(),
            app_id: app_id.to_string(),
            ip,
            public_key: public_key.to_string(),
            reg_time: SystemTime::now(),
        };
        self.state
            .instances
            .insert(id.to_string(), host_info.clone());
        self.state
            .apps
            .entry(app_id.to_string())
            .or_default()
            .insert(id.to_string());
        Some(host_info)
    }

    fn generate_wg_config(&self) -> Result<String> {
        let model = WgConf {
            private_key: &self.config.wg.private_key,
            listen_port: self.config.wg.listen_port,
            peers: (&self.state.instances).into(),
        };
        Ok(model.render()?)
    }

    pub(crate) fn reconfigure(&mut self) -> Result<()> {
        let wg_config = self.generate_wg_config()?;
        fs::write(&self.config.wg.config_path, wg_config).context("Failed to write wg config")?;
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
        let state_str = serde_json::to_string(&self.state).context("Failed to serialize state")?;
        fs::write(&self.config.state_path, state_str).context("Failed to write state")?;
        Ok(())
    }

    pub(crate) fn select_a_host(&self, id: &str) -> Option<InstanceInfo> {
        // Direct instance lookup first
        if let Some(info) = self.state.instances.get(id).cloned() {
            return Some(info);
        }

        let app_instances = self.state.apps.get(id)?;

        // Get latest handshakes to check instance health
        let handshakes = self.latest_handshakes(None).ok()?;

        // Filter healthy instances and choose randomly among them
        let healthy_instances = app_instances.iter().filter(|instance_id| {
            if let Some(instance) = self.state.instances.get(*instance_id) {
                // Consider instance healthy if it had a recent handshake
                handshakes
                    .get(&instance.public_key)
                    .map(|(_, elapsed)| *elapsed < Duration::from_secs(300))
                    .unwrap_or(false)
            } else {
                false
            }
        });

        let selected = healthy_instances.choose(&mut rand::thread_rng())?;
        self.state.instances.get(selected).cloned()
    }

    fn latest_handshakes(
        &self,
        stale_timeout: Option<Duration>,
    ) -> Result<BTreeMap<String, (u64, Duration)>> {
        /*
        $wg show tproxy-kvin1 latest-handshakes
        eHBq6OjihPy1IZ2cFDomSesjeD+new7KNdWn9MHdQC8=    1730190589
        SRuIdjZ1CkR54jJ1g7JC4cy9nxHPezXf2bZlkZHjFxE=    1732085583
        YobeKV6YpmuTAQd0+Tx30Pe4JP12fPFwftC04Umt6Bw=    1731214390
        9pgMHikM4onpoiNPJkya003BFAdzRMiD2WMDSMb64zo=    1731213050
        oZppF/Rk7NgnuPkkfGUiBpY9HbThJvq3jACNGW2vnVA=    1731213485
        3OxwGWcnC+4TZ31rnmDpfgbLBi8DCWdEk4k/7gFG5HU=    1732085521
        */
        let output = Command::new("wg")
            .arg("show")
            .arg(&self.config.wg.interface)
            .arg("latest-handshakes")
            .output()
            .context("failed to execute wg show command")?;

        if !output.status.success() {
            bail!(
                "wg show command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before Unix epoch")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut handshakes = BTreeMap::new();

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 2 {
                continue;
            }

            let pubkey = parts[0].trim().to_string();
            let timestamp = parts[1]
                .trim()
                .parse::<u64>()
                .context("invalid timestamp")?;
            let timestamp_duration = Duration::from_secs(timestamp);

            if timestamp == 0 {
                handshakes.insert(pubkey, (0, Duration::MAX));
            } else {
                let elapsed = now.checked_sub(timestamp_duration).unwrap_or_default();
                match stale_timeout {
                    Some(min_duration) if elapsed < min_duration => continue,
                    _ => (),
                }
                handshakes.insert(pubkey, (timestamp, elapsed));
            }
        }

        Ok(handshakes)
    }

    fn remove_instance(&mut self, id: &str) -> Result<()> {
        let info = self
            .state
            .instances
            .remove(id)
            .context("instance not found")?;
        self.state.allocated_addresses.remove(&info.ip);
        if let Some(app_instances) = self.state.apps.get_mut(&info.app_id) {
            app_instances.remove(id);
            if app_instances.is_empty() {
                self.state.apps.remove(&info.app_id);
            }
        }
        Ok(())
    }

    fn recycle(&mut self) -> Result<()> {
        let stale_timeout = self.config.recycle.timeout;
        let stale_handshakes = self.latest_handshakes(Some(stale_timeout))?;
        debug!("stale handshakes: {:#?}", stale_handshakes);
        // Find and remove instances with matching public keys
        let stale_instances: Vec<_> = self
            .state
            .instances
            .iter()
            .filter(|(_, info)| {
                stale_handshakes.contains_key(&info.public_key) && {
                    info.reg_time.elapsed().unwrap_or_default() > stale_timeout
                }
            })
            .map(|(id, _info)| id.clone())
            .collect();
        debug!("stale instances: {:#?}", stale_instances);
        let num_recycled = stale_instances.len();
        for id in stale_instances {
            self.remove_instance(&id)?;
        }
        info!("recycled {num_recycled} stale instances");
        // Reconfigure WireGuard with updated peers
        if num_recycled > 0 {
            self.reconfigure()?;
        }
        Ok(())
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
        if request.client_public_key.is_empty() {
            bail!("[{instance_id}] client public key is empty");
        }
        let client_info = state
            .new_client_by_id(&instance_id, &app_id, &request.client_public_key)
            .context("failed to allocate IP address for client")?;
        if let Err(err) = state.reconfigure() {
            error!("failed to reconfigure: {}", err);
        }
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
        let handshakes = state.latest_handshakes(None)?;
        let hosts = state
            .state
            .instances
            .values()
            .map(|instance| PbHostInfo {
                id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain: base_domain.clone(),
                port: state.config.proxy.listen_port as u32,
                latest_handshake: {
                    let (ts, _) = handshakes
                        .get(&instance.public_key)
                        .copied()
                        .unwrap_or_default();
                    ts
                },
            })
            .collect::<Vec<_>>();
        Ok(ListResponse { hosts })
    }

    async fn get_info(self, request: GetInfoRequest) -> Result<GetInfoResponse> {
        let state = self.state.lock();
        let base_domain = &state.config.proxy.base_domain;
        let handshakes = state.latest_handshakes(None)?;

        if let Some(instance) = state.state.instances.get(&request.id) {
            let host_info = PbHostInfo {
                id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain: base_domain.clone(),
                port: state.config.proxy.listen_port as u32,
                latest_handshake: {
                    let (ts, _) = handshakes
                        .get(&instance.public_key)
                        .copied()
                        .unwrap_or_default();
                    ts
                },
            };
            Ok(GetInfoResponse {
                found: true,
                info: Some(host_info),
            })
        } else {
            Ok(GetInfoResponse {
                found: false,
                info: None,
            })
        }
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

    async fn get_meta(self) -> Result<GetMetaResponse> {
        let state = self.state.lock();
        let handshakes = state.latest_handshakes(None)?;
        
        // Total registered instances
        let registered = state.state.instances.len();
        
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before Unix epoch")?
            .as_secs();
        
        // Count online instances (those with handshakes in last 5 minutes)
        let online = handshakes
            .values()
            .filter(|(ts, _)| {
                // Skip instances that never connected (ts == 0)
                *ts != 0 && (now - *ts) < 300
            })
            .count();

        Ok(GetMetaResponse {
            registered: registered as u32,
            online: online as u32,
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
