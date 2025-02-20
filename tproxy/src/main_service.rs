use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use certbot::{CertBot, WorkDir};
use cmd_lib::run_cmd as cmd;
use fs_err as fs;
use ra_rpc::{CallContext, RpcCall, VerifiedAttestation};
use rand::seq::IteratorRandom;
use rinja::Template as _;
use safe_write::safe_write;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use tproxy_rpc::{
    tproxy_server::{TproxyRpc, TproxyServer},
    AcmeInfoResponse, GetInfoRequest, GetInfoResponse, GetMetaResponse, HostInfo as PbHostInfo,
    RegisterCvmRequest, RegisterCvmResponse, StatusResponse, TappdConfig, TproxyState,
    WireGuardConfig, WireGuardPeer,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    models::{InstanceInfo, WgConf},
    proxy::AddressGroup,
};

mod sync_client;

#[derive(Clone)]
pub struct Proxy {
    pub(crate) config: Arc<Config>,
    pub(crate) certbot: Option<Arc<CertBot>>,
    my_app_id: Option<Vec<u8>>,
    inner: Arc<Mutex<ProxyState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProxyNodeInfo {
    pub pubkey: String,
    pub url: String,
    pub last_seen: SystemTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxyStateMut {
    nodes: BTreeMap<String, ProxyNodeInfo>,
    apps: BTreeMap<String, BTreeSet<String>>,
    instances: BTreeMap<String, InstanceInfo>,
    allocated_addresses: BTreeSet<Ipv4Addr>,
    #[serde(skip)]
    top_n: BTreeMap<String, (AddressGroup, Instant)>,
}

pub(crate) struct ProxyState {
    config: Arc<Config>,
    state: ProxyStateMut,
}

impl Proxy {
    pub(crate) fn lock(&self) -> MutexGuard<ProxyState> {
        self.inner.lock().expect("Failed to lock AppState")
    }

    pub async fn new(config: Config, my_app_id: Option<Vec<u8>>) -> Result<Self> {
        let certbot = if config.certbot.enabled {
            info!("Starting certbot...");
            let certbot = config
                .certbot
                .build_bot()
                .await
                .context("Failed to build certbot")?;
            info!("First renewal...");
            certbot.renew(false).await.context("Failed to renew cert")?;
            let certbot = Arc::new(certbot);
            start_certbot_task(certbot.clone());
            Some(certbot)
        } else {
            info!("certbot is disabled");
            None
        };
        let config = Arc::new(config);
        let state_path = &config.state_path;
        let state = if fs::metadata(state_path).is_ok() {
            let state_str = fs::read_to_string(state_path).context("Failed to read state")?;
            serde_json::from_str(&state_str).context("Failed to load state")?
        } else {
            let mut nodes = BTreeMap::new();
            nodes.insert(
                config.wg.public_key.clone(),
                ProxyNodeInfo {
                    pubkey: config.wg.public_key.clone(),
                    url: config.sync.my_url.clone(),
                    last_seen: SystemTime::now(),
                },
            );
            ProxyStateMut {
                nodes,
                apps: BTreeMap::new(),
                top_n: BTreeMap::new(),
                instances: BTreeMap::new(),
                allocated_addresses: BTreeSet::new(),
            }
        };
        let inner = Arc::new(Mutex::new(ProxyState {
            config: config.clone(),
            state,
        }));
        start_recycle_thread(Arc::downgrade(&inner), config.clone());
        start_sync_task(Arc::downgrade(&inner), config.clone());
        Ok(Self {
            config,
            inner,
            certbot,
            my_app_id,
        })
    }
}

fn start_recycle_thread(state: Weak<Mutex<ProxyState>>, config: Arc<Config>) {
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

fn start_certbot_task(certbot: Arc<CertBot>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(certbot.renew_interval()).await;
            match certbot.renew(false).await {
                Err(e) => {
                    error!("failed to run certbot: {e:?}");
                }
                Ok(renewed) => {
                    if renewed {
                        // Restart self
                        info!("certificate renewed, restarting...");
                        std::process::exit(0);
                    }
                }
            }
        }
    });
}

fn start_sync_task(proxy: Weak<Mutex<ProxyState>>, config: Arc<Config>) {
    if !config.sync.enabled {
        info!("sync is disabled");
        return;
    }
    tokio::spawn(async move {
        match sync_client::sync_task(proxy, config).await {
            Ok(_) => info!("Sync task exited"),
            Err(err) => error!("Failed to run sync task: {err}"),
        }
    });
}

impl ProxyState {
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
            last_seen: SystemTime::now(),
        };
        self.add_instance(host_info.clone());
        Some(host_info)
    }

    fn add_instance(&mut self, info: InstanceInfo) {
        self.state
            .apps
            .entry(info.app_id.clone())
            .or_default()
            .insert(info.id.clone());
        self.state.instances.insert(info.id.clone(), info);
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
        safe_write(&self.config.wg.config_path, wg_config).context("Failed to write wg config")?;
        // wg setconf <interface_name> <config_path>
        let ifname = &self.config.wg.interface;
        let config_path = &self.config.wg.config_path;

        match cmd!(wg syncconf $ifname $config_path) {
            Ok(_) => info!("wg config updated"),
            Err(e) => error!("failed to set wg config: {e}"),
        }
        self.save_state()?;
        Ok(())
    }

    fn save_state(&self) -> Result<()> {
        let state_str = serde_json::to_string(&self.state).context("Failed to serialize state")?;
        safe_write(&self.config.state_path, state_str).context("Failed to write state")?;
        Ok(())
    }

    pub(crate) fn select_top_n_hosts(&mut self, id: &str) -> Result<AddressGroup> {
        if self.config.proxy.localhost_enabled && id == "localhost" {
            return Ok(smallvec![Ipv4Addr::new(127, 0, 0, 1)]);
        }
        let n = self.config.proxy.connect_top_n;
        if let Some(instance) = self.state.instances.get(id) {
            return Ok(smallvec![instance.ip]);
        };
        let app_instances = self.state.apps.get(id).context("app not found")?;
        if n == 0 {
            // fallback to random selection
            return Ok(self.random_select_a_host(id).unwrap_or_default());
        }
        let (top_n, insert_time) = self
            .state
            .top_n
            .entry(id.to_string())
            .or_insert((SmallVec::new(), Instant::now()));
        if !top_n.is_empty() && insert_time.elapsed() < self.config.proxy.timeouts.cache_top_n {
            return Ok(top_n.clone());
        }

        let handshakes = self.latest_handshakes(None);
        let mut instances = match handshakes {
            Err(err) => {
                warn!("Failed to get handshakes, fallback to random selection: {err}");
                return Ok(self.random_select_a_host(id).unwrap_or_default());
            }
            Ok(handshakes) => app_instances
                .iter()
                .filter_map(|instance_id| {
                    let instance = self.state.instances.get(instance_id)?;
                    let (_, elapsed) = handshakes.get(&instance.public_key)?;
                    Some((instance.ip, *elapsed))
                })
                .collect::<SmallVec<[_; 4]>>(),
        };
        instances.sort_by(|a, b| a.1.cmp(&b.1));
        instances.truncate(n);
        Ok(instances.into_iter().map(|(ip, _)| ip).collect())
    }

    fn random_select_a_host(&self, id: &str) -> Option<AddressGroup> {
        // Direct instance lookup first
        if let Some(info) = self.state.instances.get(id).cloned() {
            return Some(smallvec![info.ip]);
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
        self.state
            .instances
            .get(selected)
            .map(|info| smallvec![info.ip])
    }

    /// Get latest handshakes
    ///
    /// Return a map of public key to (timestamp, elapsed)
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
        let ifname = &self.config.wg.interface;
        let output = cmd_lib::run_fun!(wg show $ifname latest-handshakes)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before Unix epoch")?;
        let mut handshakes = BTreeMap::new();
        for line in output.lines() {
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
        if tracing::enabled!(tracing::Level::DEBUG) {
            for (pubkey, (ts, elapsed)) in &stale_handshakes {
                debug!("stale instance: {pubkey} recent={ts} ({elapsed:?} ago)");
            }
        }
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

    pub(crate) fn exit(&mut self) -> ! {
        std::process::exit(0);
    }

    fn update_state(
        &mut self,
        proxy_nodes: Vec<ProxyNodeInfo>,
        apps: Vec<InstanceInfo>,
    ) -> Result<()> {
        for node in proxy_nodes {
            if let Some(existing) = self.state.nodes.get(&node.pubkey) {
                if node.last_seen > existing.last_seen {
                    continue;
                }
            }
            self.state.nodes.insert(node.pubkey.clone(), node);
        }

        let mut wg_changed = false;
        let mut state_changed = false;
        for app in apps {
            if let Some(existing) = self.state.instances.get(&app.id) {
                let existing_ts = (existing.reg_time, existing.last_seen);
                let update_ts = (app.reg_time, app.last_seen);
                if update_ts <= existing_ts {
                    continue;
                }
                if !wg_changed {
                    wg_changed = existing.public_key != app.public_key || existing.ip != app.ip;
                }
            }
            state_changed = true;
            self.add_instance(app);
        }
        info!("updated, wg_changed: {wg_changed}, state_changed: {state_changed}");
        if wg_changed {
            self.reconfigure()?;
        } else if state_changed {
            self.save_state()?;
        }
        Ok(())
    }

    fn dump_state(&mut self) -> (Vec<ProxyNodeInfo>, Vec<InstanceInfo>) {
        self.refresh_state().ok();
        (
            self.state.nodes.values().cloned().collect(),
            self.state.instances.values().cloned().collect(),
        )
    }

    fn refresh_state(&mut self) -> Result<()> {
        let handshakes = self.latest_handshakes(None)?;
        for instance in self.state.instances.values_mut() {
            let Some((ts, _)) = handshakes.get(&instance.public_key).copied() else {
                continue;
            };
            instance.last_seen = decode_ts(ts);
        }
        self.state.nodes.insert(
            self.config.wg.public_key.clone(),
            ProxyNodeInfo {
                pubkey: self.config.wg.public_key.clone(),
                url: self.config.sync.my_url.clone(),
                last_seen: SystemTime::now(),
            },
        );
        Ok(())
    }
}

fn decode_ts(ts: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(ts))
        .unwrap_or(UNIX_EPOCH)
}

fn encode_ts(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub struct RpcHandler {
    remote_app_id: Option<Vec<u8>>,
    attestation: Option<VerifiedAttestation>,
    state: Proxy,
}

impl RpcHandler {
    fn ensure_from_tproxy(&self) -> Result<()> {
        if !self.state.config.run_as_tapp {
            return Ok(());
        }
        if self.remote_app_id.is_none() {
            bail!("Client authentication is required");
        }
        if self.state.my_app_id != self.remote_app_id {
            bail!("Remote app id is not from tproxy");
        }
        Ok(())
    }
}

impl TproxyRpc for RpcHandler {
    async fn register_cvm(self, request: RegisterCvmRequest) -> Result<RegisterCvmResponse> {
        let Some(ra) = &self.attestation else {
            bail!("no attestation provided");
        };
        let app_info = ra
            .decode_app_info(false)
            .context("failed to decode app-info from attestation")?;
        let app_id = hex::encode(&app_info.app_id);
        let instance_id = hex::encode(&app_info.instance_id);

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
                client_ip: client_info.ip.to_string(),
                servers: vec![WireGuardPeer {
                    pk: state.config.wg.public_key.clone(),
                    ip: state.config.wg.ip.to_string(),
                    endpoint: state.config.wg.endpoint.clone(),
                }],
            }),
            tappd: Some(TappdConfig {
                external_port: state.config.proxy.listen_port as u32,
                internal_port: state.config.proxy.tappd_port as u32,
                domain: state.config.proxy.base_domain.clone(),
            }),
        })
    }

    async fn status(self) -> Result<StatusResponse> {
        let mut state = self.state.lock();
        state.refresh_state()?;
        let base_domain = &state.config.proxy.base_domain;
        let hosts = state
            .state
            .instances
            .values()
            .map(|instance| PbHostInfo {
                instance_id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain: base_domain.clone(),
                port: state.config.proxy.listen_port as u32,
                latest_handshake: encode_ts(instance.last_seen),
            })
            .collect::<Vec<_>>();
        let nodes = state
            .state
            .nodes
            .values()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>();
        Ok(StatusResponse {
            url: state.config.sync.my_url.clone(),
            pubkey: state.config.wg.public_key.clone(),
            bootnode_url: state.config.sync.bootnode.clone(),
            nodes,
            hosts,
        })
    }

    async fn get_info(self, request: GetInfoRequest) -> Result<GetInfoResponse> {
        let state = self.state.lock();
        let base_domain = &state.config.proxy.base_domain;
        let handshakes = state.latest_handshakes(None)?;

        if let Some(instance) = state.state.instances.get(&request.id) {
            let host_info = PbHostInfo {
                instance_id: instance.id.clone(),
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

    async fn update_state(self, request: TproxyState) -> Result<()> {
        self.ensure_from_tproxy()?;
        let mut nodes = vec![];
        let mut apps = vec![];

        for node in request.nodes {
            nodes.push(ProxyNodeInfo {
                pubkey: node.pubkey,
                last_seen: decode_ts(node.last_seen),
                url: node.url,
            });
        }

        for app in request.apps {
            apps.push(InstanceInfo {
                id: app.instance_id,
                app_id: app.app_id,
                ip: app.ip.parse().context("Invalid IP address")?,
                public_key: app.public_key,
                reg_time: decode_ts(app.reg_time),
                last_seen: decode_ts(app.last_seen),
            });
        }

        self.state
            .lock()
            .update_state(nodes, apps)
            .context("failed to update state")?;
        Ok(())
    }
}

impl RpcCall<Proxy> for RpcHandler {
    type PrpcService = TproxyServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(RpcHandler {
            remote_app_id: context.remote_app_id,
            attestation: context.attestation,
            state: context.state.clone(),
        })
    }
}

impl From<ProxyNodeInfo> for tproxy_rpc::ProxyNodeInfo {
    fn from(node: ProxyNodeInfo) -> Self {
        Self {
            pubkey: node.pubkey,
            last_seen: encode_ts(node.last_seen),
            url: node.url,
        }
    }
}

impl From<InstanceInfo> for tproxy_rpc::AppInstanceInfo {
    fn from(app: InstanceInfo) -> Self {
        Self {
            instance_id: app.id,
            app_id: app.app_id,
            ip: app.ip.to_string(),
            public_key: app.public_key,
            reg_time: encode_ts(app.reg_time),
            last_seen: encode_ts(app.last_seen),
        }
    }
}

#[cfg(test)]
mod tests;
