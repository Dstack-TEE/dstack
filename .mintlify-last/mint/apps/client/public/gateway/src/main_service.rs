use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::{atomic::Ordering, Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use auth_client::AuthClient;
use certbot::{CertBot, WorkDir};
use cmd_lib::run_cmd as cmd;
use dstack_gateway_rpc::{
    gateway_server::{GatewayRpc, GatewayServer},
    AcmeInfoResponse, GatewayState, GetInfoRequest, GetInfoResponse, GetMetaResponse,
    GuestAgentConfig, HostInfo as PbHostInfo, RegisterCvmRequest, RegisterCvmResponse,
    StatusResponse, WireGuardConfig, WireGuardPeer,
};
use fs_err as fs;
use ra_rpc::{CallContext, RpcCall, VerifiedAttestation};
use rand::seq::IteratorRandom;
use rinja::Template as _;
use safe_write::safe_write;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use sync_client::SyncEvent;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    models::{InstanceInfo, WgConf},
    proxy::{AddressGroup, AddressInfo, NUM_CONNECTIONS},
};

mod sync_client;

mod auth_client;

#[derive(Clone)]
pub struct Proxy {
    pub(crate) config: Arc<Config>,
    pub(crate) certbot: Option<Arc<CertBot>>,
    my_app_id: Option<Vec<u8>>,
    sync_tx: Sender<SyncEvent>,
    inner: Arc<Mutex<ProxyState>>,
    auth_client: Arc<AuthClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GatewayNodeInfo {
    pub id: Vec<u8>,
    pub url: String,
    pub wg_peer: WireGuardPeer,
    pub last_seen: SystemTime,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ProxyStateMut {
    nodes: BTreeMap<String, GatewayNodeInfo>,
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
        let config = Arc::new(config);
        let mut state = fs::metadata(&config.state_path)
            .is_ok()
            .then(|| load_state(&config.state_path))
            .transpose()
            .unwrap_or_else(|err| {
                error!("Failed to load state: {err}");
                None
            })
            .unwrap_or_default();
        state.nodes.insert(
            config.wg.public_key.clone(),
            GatewayNodeInfo {
                id: config.id(),
                url: config.sync.my_url.clone(),
                wg_peer: WireGuardPeer {
                    pk: config.wg.public_key.clone(),
                    ip: config.wg.ip.to_string(),
                    endpoint: config.wg.endpoint.clone(),
                },
                last_seen: SystemTime::now(),
            },
        );
        let inner = Arc::new(Mutex::new(ProxyState {
            config: config.clone(),
            state,
        }));
        start_recycle_thread(Arc::downgrade(&inner), config.clone());
        let (sync_tx, sync_rx) = mpsc::channel(1);
        start_sync_task(Arc::downgrade(&inner), config.clone(), sync_rx);
        let certbot = start_certbot_task(&config).await?;
        let auth_client = Arc::new(AuthClient::new(config.auth.clone()));
        Ok(Self {
            config,
            inner,
            certbot,
            my_app_id,
            sync_tx,
            auth_client,
        })
    }
}

fn load_state(state_path: &str) -> Result<ProxyStateMut> {
    let state_str = fs::read_to_string(state_path).context("Failed to read state")?;
    serde_json::from_str(&state_str).context("Failed to load state")
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

async fn start_certbot_task(config: &Arc<Config>) -> Result<Option<Arc<CertBot>>> {
    if !config.certbot.enabled {
        info!("Certbot is disabled");
        return Ok(None);
    }
    info!("Starting certbot...");
    let certbot = config
        .certbot
        .build_bot()
        .await
        .context("Failed to build certbot")?;
    info!("First renewal...");
    certbot.renew(false).await.context("Failed to renew cert")?;
    let certbot = Arc::new(certbot);
    let certbot_clone = certbot.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(certbot.renew_interval()).await;
            match certbot.renew(false).await {
                Err(e) => {
                    error!("Failed to run certbot: {e:?}");
                }
                Ok(renewed) => {
                    if renewed {
                        // Restart self
                        info!("Certificate renewed, restarting...");
                        std::process::exit(0);
                    }
                }
            }
        }
    });
    Ok(Some(certbot_clone))
}

fn start_sync_task(
    proxy: Weak<Mutex<ProxyState>>,
    config: Arc<Config>,
    event_rx: Receiver<SyncEvent>,
) {
    if !config.sync.enabled {
        info!("sync is disabled");
        return;
    }
    tokio::spawn(async move {
        match sync_client::sync_task(proxy, config, event_rx).await {
            Ok(_) => info!("Sync task exited"),
            Err(err) => error!("Failed to run sync task: {err}"),
        }
    });
}

impl ProxyState {
    fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for ip in self.config.wg.client_ip_range.hosts() {
            if self.config.wg.ip.broadcast() == ip {
                continue;
            }
            if self.config.wg.ip.addr() == ip {
                continue;
            }
            for net in &self.config.wg.reserved_net {
                if net.contains(&ip) {
                    continue;
                }
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
            connections: Default::default(),
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
            return Ok(smallvec![AddressInfo {
                ip: Ipv4Addr::new(127, 0, 0, 1),
                counter: Default::default(),
            }]);
        }
        let n = self.config.proxy.connect_top_n;
        if let Some(instance) = self.state.instances.get(id) {
            return Ok(smallvec![AddressInfo {
                ip: instance.ip,
                counter: instance.connections.clone(),
            }]);
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
                    Some((instance.ip, *elapsed, instance.connections.clone()))
                })
                .collect::<SmallVec<[_; 4]>>(),
        };
        instances.sort_by(|a, b| a.1.cmp(&b.1));
        instances.truncate(n);
        Ok(instances
            .into_iter()
            .map(|(ip, _, counter)| AddressInfo { ip, counter })
            .collect())
    }

    fn random_select_a_host(&self, id: &str) -> Option<AddressGroup> {
        // Direct instance lookup first
        if let Some(info) = self.state.instances.get(id).cloned() {
            return Some(smallvec![AddressInfo {
                ip: info.ip,
                counter: info.connections.clone(),
            }]);
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
        self.state.instances.get(selected).map(|info| {
            smallvec![AddressInfo {
                ip: info.ip,
                counter: info.connections.clone(),
            }]
        })
    }

    /// Get latest handshakes
    ///
    /// Return a map of public key to (timestamp, elapsed)
    fn latest_handshakes(
        &self,
        stale_timeout: Option<Duration>,
    ) -> Result<BTreeMap<String, (u64, Duration)>> {
        /*
        $wg show ds-gw-kvin1 latest-handshakes
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
        // Recycle stale Gateway nodes
        let mut staled_nodes = vec![];
        for node in self.state.nodes.values() {
            if node.wg_peer.pk == self.config.wg.public_key {
                continue;
            }
            if node.last_seen.elapsed().unwrap_or_default() > self.config.recycle.node_timeout {
                staled_nodes.push(node.wg_peer.pk.clone());
            }
        }
        for id in staled_nodes {
            self.state.nodes.remove(&id);
        }

        // Recycle stale CVM instances
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

    fn dedup_nodes(&mut self) {
        // Dedup nodes by URL, keeping the latest one
        let mut node_map = BTreeMap::<String, GatewayNodeInfo>::new();

        for node in std::mem::take(&mut self.state.nodes).into_values() {
            match node_map.get(&node.wg_peer.endpoint) {
                Some(existing) if existing.last_seen >= node.last_seen => {}
                _ => {
                    node_map.insert(node.wg_peer.endpoint.clone(), node);
                }
            }
        }
        for node in node_map.into_values() {
            self.state.nodes.insert(node.wg_peer.pk.clone(), node);
        }
    }

    fn update_state(
        &mut self,
        proxy_nodes: Vec<GatewayNodeInfo>,
        apps: Vec<InstanceInfo>,
    ) -> Result<()> {
        for node in proxy_nodes {
            if node.wg_peer.pk == self.config.wg.public_key {
                continue;
            }
            if node.url == self.config.sync.my_url {
                continue;
            }
            if let Some(existing) = self.state.nodes.get(&node.wg_peer.pk) {
                if node.last_seen <= existing.last_seen {
                    continue;
                }
            }
            self.state.nodes.insert(node.wg_peer.pk.clone(), node);
        }
        self.dedup_nodes();

        let mut wg_changed = false;
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
            } else {
                wg_changed = true;
            }
            self.add_instance(app);
        }
        info!("updated, wg_changed: {wg_changed}");
        if wg_changed {
            self.reconfigure()?;
        } else {
            self.save_state()?;
        }
        Ok(())
    }

    fn dump_state(&mut self) -> (Vec<GatewayNodeInfo>, Vec<InstanceInfo>) {
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
        if let Some(node) = self.state.nodes.get_mut(&self.config.wg.public_key) {
            node.last_seen = SystemTime::now();
        }
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
    fn ensure_from_gateway(&self) -> Result<()> {
        if !self.state.config.run_in_dstack {
            return Ok(());
        }
        if self.remote_app_id.is_none() {
            bail!("Client authentication is required");
        }
        if self.state.my_app_id != self.remote_app_id {
            bail!("Remote app id is not from dstack-gateway");
        }
        Ok(())
    }
}

impl GatewayRpc for RpcHandler {
    async fn register_cvm(self, request: RegisterCvmRequest) -> Result<RegisterCvmResponse> {
        let Some(ra) = &self.attestation else {
            bail!("no attestation provided");
        };
        let app_info = ra
            .decode_app_info(false)
            .context("failed to decode app-info from attestation")?;
        self.state
            .auth_client
            .ensure_app_authorized(&app_info)
            .await
            .context("App authorization failed")?;
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
        let servers = state
            .state
            .nodes
            .values()
            .map(|n| n.wg_peer.clone())
            .collect::<Vec<_>>();
        let response = RegisterCvmResponse {
            wg: Some(WireGuardConfig {
                client_ip: client_info.ip.to_string(),
                servers,
            }),
            agent: Some(GuestAgentConfig {
                external_port: state.config.proxy.listen_port as u32,
                internal_port: state.config.proxy.agent_port as u32,
                domain: state.config.proxy.base_domain.clone(),
            }),
        };
        if let Err(err) = self.state.sync_tx.try_send(SyncEvent::Broadcast) {
            warn!("Failed to talk to sync task: {err}");
        }
        Ok(response)
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
                num_connections: instance.num_connections(),
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
            id: state.config.id(),
            bootnode_url: state.config.sync.bootnode.clone(),
            nodes,
            hosts,
            num_connections: NUM_CONNECTIONS.load(Ordering::Relaxed),
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
                num_connections: instance.num_connections(),
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

    async fn update_state(self, request: GatewayState) -> Result<()> {
        self.ensure_from_gateway()?;
        let mut nodes = vec![];
        let mut apps = vec![];

        for node in request.nodes {
            nodes.push(GatewayNodeInfo {
                id: node.id,
                wg_peer: node.wg_peer.context("wg_peer is missing")?,
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
                connections: Default::default(),
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
    type PrpcService = GatewayServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(RpcHandler {
            remote_app_id: context.remote_app_id,
            attestation: context.attestation,
            state: context.state.clone(),
        })
    }
}

impl From<GatewayNodeInfo> for dstack_gateway_rpc::GatewayNodeInfo {
    fn from(node: GatewayNodeInfo) -> Self {
        Self {
            id: node.id,
            wg_peer: Some(node.wg_peer),
            last_seen: encode_ts(node.last_seen),
            url: node.url,
        }
    }
}

impl From<InstanceInfo> for dstack_gateway_rpc::AppInstanceInfo {
    fn from(app: InstanceInfo) -> Self {
        Self {
            num_connections: app.num_connections(),
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
