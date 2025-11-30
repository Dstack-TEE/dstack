// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    ops::Deref,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use auth_client::AuthClient;
use certbot::{CertBot, WorkDir};
use cmd_lib::run_cmd as cmd;
use dstack_gateway_rpc::{
    gateway_server::{GatewayRpc, GatewayServer},
    AcmeInfoResponse, GatewayState, GuestAgentConfig, InfoResponse, QuotedPublicKey,
    RegisterCvmRequest, RegisterCvmResponse, WireGuardConfig, WireGuardPeer,
};
use dstack_guest_agent_rpc::{dstack_guest_client::DstackGuestClient, RawQuoteArgs};
use fs_err as fs;
use http_client::prpc::PrpcClient;
use ra_rpc::{CallContext, RpcCall, VerifiedAttestation};
use ra_tls::attestation::QuoteContentType;
use rand::seq::IteratorRandom;
use rinja::Template as _;
use safe_write::safe_write;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::{
    config::{Config, TlsConfig},
    kv::{AppIdValidator, HttpsClientConfig, InstanceData, KvStore, NodeData, WaveKvSyncService},
    models::{InstanceInfo, WgConf},
    proxy::{create_acceptor, AddressGroup, AddressInfo},
};

mod auth_client;

#[derive(Clone)]
pub struct Proxy {
    _inner: Arc<ProxyInner>,
}

impl Deref for Proxy {
    type Target = ProxyInner;
    fn deref(&self) -> &Self::Target {
        &self._inner
    }
}

pub struct ProxyInner {
    pub(crate) config: Arc<Config>,
    pub(crate) certbot: Option<Arc<CertBot>>,
    my_app_id: Option<Vec<u8>>,
    state: Mutex<ProxyState>,
    pub(crate) notify_state_updated: Notify,
    auth_client: AuthClient,
    pub(crate) acceptor: RwLock<TlsAcceptor>,
    pub(crate) h2_acceptor: RwLock<TlsAcceptor>,
    /// WaveKV-based store for persistence (and cross-node sync when enabled)
    kv_store: Arc<KvStore>,
    /// WaveKV sync service for network synchronization
    pub(crate) wavekv_sync: Option<Arc<WaveKvSyncService>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GatewayNodeInfo {
    pub id: Vec<u8>,
    pub url: String,
    pub wg_peer: WireGuardPeer,
    pub last_seen: SystemTime,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct ProxyStateMut {
    pub(crate) nodes: BTreeMap<String, GatewayNodeInfo>,
    pub(crate) apps: BTreeMap<String, BTreeSet<String>>,
    pub(crate) instances: BTreeMap<String, InstanceInfo>,
    pub(crate) allocated_addresses: BTreeSet<Ipv4Addr>,
    #[serde(skip)]
    pub(crate) top_n: BTreeMap<String, (AddressGroup, Instant)>,
}

pub(crate) struct ProxyState {
    pub(crate) config: Arc<Config>,
    pub(crate) state: ProxyStateMut,
    /// Reference to KvStore for syncing changes
    kv_store: Arc<KvStore>,
}

/// Options for creating a Proxy instance
pub struct ProxyOptions {
    pub config: Config,
    pub my_app_id: Option<Vec<u8>>,
    /// TLS configuration (from Rocket's tls config)
    pub tls_config: TlsConfig,
}

impl Proxy {
    pub async fn new(options: ProxyOptions) -> Result<Self> {
        Ok(Self {
            _inner: Arc::new(ProxyInner::new(options).await?),
        })
    }
}

impl ProxyInner {
    pub(crate) fn lock(&self) -> MutexGuard<ProxyState> {
        self.state.lock().expect("Failed to lock AppState")
    }

    pub async fn new(options: ProxyOptions) -> Result<Self> {
        let ProxyOptions {
            config,
            my_app_id,
            tls_config,
        } = options;
        let config = Arc::new(config);

        // Initialize WaveKV store (always used for persistence, sync is optional)
        let kv_store = Arc::new(
            KvStore::new(
                config.sync.node_id,
                config.sync.peer_node_ids.clone(),
                &config.sync.wavekv_data_dir,
            )
            .context("failed to initialize WaveKV store")?,
        );
        info!(
            "WaveKV store initialized: node_id={}, peers={:?}, sync_enabled={}",
            config.sync.node_id, config.sync.peer_node_ids, config.sync.enabled
        );

        // Load state from WaveKV or legacy JSON
        let instances = kv_store.load_all_instances();
        let nodes = kv_store.load_all_nodes();
        let mut state = if !instances.is_empty() || !nodes.is_empty() {
            info!(
                "Loaded state from WaveKV: {} instances, {} nodes",
                instances.len(),
                nodes.len()
            );
            build_state_from_kv_store(instances, nodes, &config)
        } else {
            // Fallback to legacy JSON state
            load_legacy_state(&config)
        };

        state
            .nodes
            .retain(|_, info| info.wg_peer.ip != config.wg.ip.to_string());

        // Register this node
        let my_node_info = GatewayNodeInfo {
            id: config.id(),
            url: config.sync.my_url.clone(),
            wg_peer: WireGuardPeer {
                pk: config.wg.public_key.clone(),
                ip: config.wg.ip.to_string(),
                endpoint: config.wg.endpoint.clone(),
            },
            last_seen: SystemTime::now(),
        };
        state
            .nodes
            .insert(config.wg.public_key.clone(), my_node_info.clone());

        // Sync this node to KvStore
        let node_data = NodeData {
            id: config.id(),
            url: config.sync.my_url.clone(),
            wg_public_key: config.wg.public_key.clone(),
            wg_endpoint: config.wg.endpoint.clone(),
            wg_ip: config.wg.ip.to_string(),
        };
        if let Err(err) = kv_store.sync_node(config.sync.node_id, &node_data) {
            error!("Failed to sync this node to KvStore: {err}");
        }
        // Register this node's sync URL in DB (for peer discovery)
        if let Err(err) = kv_store.register_peer_url(config.sync.node_id, &config.sync.my_url) {
            error!("Failed to register peer URL: {err}");
        }

        // Create WaveKV sync service (only if sync is enabled)
        let wavekv_sync = if config.sync.enabled {
            // Build HttpsClientConfig from Rocket's TlsConfig
            let https_config = {
                let tls = tls_config;
                let cert_validator = my_app_id
                    .clone()
                    .map(|app_id| Arc::new(AppIdValidator::new(app_id)) as _);
                HttpsClientConfig {
                    cert_path: tls.certs,
                    key_path: tls.key,
                    ca_cert_path: tls.mutual.ca_certs,
                    cert_validator,
                }
            };
            match WaveKvSyncService::new(&kv_store, &config.sync, https_config) {
                Ok(sync_service) => Some(Arc::new(sync_service)),
                Err(err) => {
                    error!("Failed to create WaveKV sync service: {err}");
                    None
                }
            }
        } else {
            None
        };

        let state = Mutex::new(ProxyState {
            config: config.clone(),
            state,
            kv_store: kv_store.clone(),
        });
        let auth_client = AuthClient::new(config.auth.clone());
        let certbot = match config.certbot.enabled {
            true => {
                let certbot = config
                    .certbot
                    .build_bot()
                    .await
                    .context("Failed to build certbot")?;
                info!("Certbot built, renewing...");
                // Try first renewal for the acceptor creation
                certbot.renew(false).await.context("Failed to renew cert")?;
                Some(Arc::new(certbot))
            }
            false => None,
        };
        let acceptor = RwLock::new(
            create_acceptor(&config.proxy, false).context("Failed to create acceptor")?,
        );
        let h2_acceptor =
            RwLock::new(create_acceptor(&config.proxy, true).context("Failed to create acceptor")?);
        Ok(Self {
            config,
            state,
            notify_state_updated: Notify::new(),
            my_app_id,
            auth_client,
            acceptor,
            h2_acceptor,
            certbot,
            kv_store,
            wavekv_sync,
        })
    }

    pub(crate) fn kv_store(&self) -> &Arc<KvStore> {
        &self.kv_store
    }

    pub(crate) fn my_app_id(&self) -> Option<&[u8]> {
        self.my_app_id.as_deref()
    }
}

impl Proxy {
    pub(crate) async fn start_bg_tasks(&self) -> Result<()> {
        start_recycle_thread(self.clone());
        // Start WaveKV sync
        if let Some(ref wavekv_sync) = self.wavekv_sync {
            start_wavekv_sync_task(self.clone(), wavekv_sync.clone()).await;
        }
        start_wavekv_watch_task(self.clone());
        start_certbot_task(self.clone()).await?;
        Ok(())
    }

    pub(crate) async fn renew_cert(&self, force: bool) -> Result<bool> {
        let Some(certbot) = &self.certbot else {
            return Ok(false);
        };
        let renewed = certbot.renew(force).await.context("Failed to renew cert")?;
        if renewed {
            self.reload_certificates()
                .context("Failed to reload certificates")?;
        }
        Ok(renewed)
    }

    pub(crate) async fn acme_info(&self) -> Result<AcmeInfoResponse> {
        let config = self.lock().config.clone();
        let workdir = WorkDir::new(&config.certbot.workdir);
        let account_uri = workdir.acme_account_uri().unwrap_or_default();
        let keys = workdir.list_cert_public_keys().unwrap_or_default();
        let agent = crate::dstack_agent().context("Failed to get dstack agent")?;
        let account_quote = get_or_generate_quote(
            &agent,
            QuoteContentType::Custom("acme-account"),
            account_uri.as_bytes(),
            workdir.acme_account_quote_path(),
        )
        .await
        .unwrap_or_default();

        let mut quoted_hist_keys = vec![];
        for cert_path in workdir.list_certs().unwrap_or_default() {
            let cert_pem = fs::read_to_string(&cert_path).context("Failed to read key")?;
            let pubkey = certbot::read_pubkey(&cert_pem).context("Failed to read pubkey")?;
            let quote = get_or_generate_quote(
                &agent,
                QuoteContentType::Custom("zt-cert"),
                &pubkey,
                cert_path.display().to_string() + ".quote",
            )
            .await
            .unwrap_or_default();
            quoted_hist_keys.push(QuotedPublicKey {
                public_key: pubkey,
                quote,
            });
        }
        let active_cert =
            fs::read_to_string(workdir.cert_path()).context("Failed to read active cert")?;

        Ok(AcmeInfoResponse {
            account_uri,
            hist_keys: keys.into_iter().collect(),
            account_quote,
            quoted_hist_keys,
            active_cert,
            base_domain: config.proxy.base_domain.clone(),
        })
    }

    /// Register a CVM with the given app_id, instance_id and client_public_key
    pub fn do_register_cvm(
        &self,
        app_id: &str,
        instance_id: &str,
        client_public_key: &str,
    ) -> Result<RegisterCvmResponse> {
        let mut state = self.lock();
        if app_id.is_empty() {
            bail!("[{instance_id}] app id is empty");
        }
        if instance_id.is_empty() {
            bail!("[{instance_id}] instance id is empty");
        }
        if client_public_key.is_empty() {
            bail!("[{instance_id}] client public key is empty");
        }
        let client_info = state
            .new_client_by_id(instance_id, app_id, client_public_key)
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
                external_port: state.config.proxy.external_port as u32,
                internal_port: state.config.proxy.agent_port as u32,
                domain: state.config.proxy.base_domain.clone(),
                app_address_ns_prefix: state.config.proxy.app_address_ns_prefix.clone(),
            }),
        };
        self.notify_state_updated.notify_one();
        Ok(response)
    }
}

fn load_state(state_path: &str) -> Result<ProxyStateMut> {
    let state_str = fs::read_to_string(state_path).context("Failed to read state")?;
    serde_json::from_str(&state_str).context("Failed to load state")
}

fn load_legacy_state(config: &Config) -> ProxyStateMut {
    fs::metadata(&config.state_path)
        .is_ok()
        .then(|| load_state(&config.state_path))
        .transpose()
        .unwrap_or_else(|err| {
            error!("Failed to load legacy state: {err}");
            None
        })
        .unwrap_or_default()
}

fn build_state_from_kv_store(
    instances: BTreeMap<String, InstanceData>,
    nodes: BTreeMap<wavekv::types::NodeId, NodeData>,
    _config: &Config,
) -> ProxyStateMut {
    let mut state = ProxyStateMut::default();

    // Build instances
    for (instance_id, data) in instances {
        let info = InstanceInfo {
            id: instance_id.clone(),
            app_id: data.app_id.clone(),
            ip: data.ip,
            public_key: data.public_key,
            reg_time: UNIX_EPOCH
                .checked_add(Duration::from_secs(data.reg_time))
                .unwrap_or(UNIX_EPOCH),
            last_seen: SystemTime::now(),
            connections: Default::default(),
        };
        state.allocated_addresses.insert(data.ip);
        state
            .apps
            .entry(data.app_id)
            .or_default()
            .insert(instance_id.clone());
        state.instances.insert(instance_id, info);
    }

    // Build nodes
    for (_node_id, data) in nodes {
        let node_info = GatewayNodeInfo {
            id: data.id,
            url: data.url,
            wg_peer: WireGuardPeer {
                pk: data.wg_public_key.clone(),
                ip: data.wg_ip,
                endpoint: data.wg_endpoint,
            },
            last_seen: SystemTime::now(),
        };
        state.nodes.insert(data.wg_public_key, node_info);
    }

    state
}

fn start_recycle_thread(proxy: Proxy) {
    if !proxy.config.recycle.enabled {
        info!("recycle is disabled");
        return;
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(proxy.config.recycle.interval);
        if let Err(err) = proxy.lock().recycle() {
            error!("failed to run recycle: {err}");
        };
    });
}

async fn start_certbot_task(proxy: Proxy) -> Result<()> {
    let Some(certbot) = proxy.certbot.clone() else {
        info!("Certbot is not enabled");
        return Ok(());
    };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(certbot.renew_interval()).await;
            if let Err(err) = proxy.renew_cert(false).await {
                error!("Failed to renew cert: {err}");
            }
        }
    });
    Ok(())
}

async fn start_wavekv_sync_task(proxy: Proxy, wavekv_sync: Arc<WaveKvSyncService>) {
    if !proxy.config.sync.enabled {
        info!("WaveKV sync is disabled");
        return;
    }

    // Add peer endpoints from config
    for &peer_id in &proxy.config.sync.peer_node_ids {
        // We need to discover peer URLs from stored node data or config
        // For now, peer URLs will be added dynamically when nodes are discovered
        info!("WaveKV peer {peer_id} registered (URL will be discovered)");
    }

    // Bootstrap from peers
    info!("WaveKV: bootstrapping from peers...");
    if let Err(err) = wavekv_sync.bootstrap().await {
        error!("WaveKV bootstrap failed: {err}");
    }

    // Start periodic sync tasks (runs forever in background)
    tokio::spawn(async move {
        wavekv_sync.start_sync_tasks().await;
    });
    info!("WaveKV sync tasks started");
}

fn start_wavekv_watch_task(proxy: Proxy) {
    let kv_store = proxy.kv_store.clone();

    // Watch for instance changes
    let proxy_clone = proxy.clone();
    let store_clone = kv_store.clone();
    tokio::spawn(async move {
        let mut rx = store_clone.watch_instances();
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            info!("WaveKV: detected remote instance changes, reloading...");
            if let Err(err) = reload_instances_from_kv_store(&proxy_clone, &store_clone) {
                error!("Failed to reload instances from KvStore: {err}");
            }
        }
    });

    // Watch for node changes
    tokio::spawn(async move {
        let mut rx = kv_store.watch_nodes();
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            info!("WaveKV: detected remote node changes, reloading...");
            if let Err(err) = reload_nodes_from_kv_store(&proxy, &kv_store) {
                error!("Failed to reload nodes from KvStore: {err}");
            }
        }
    });
}

fn reload_instances_from_kv_store(proxy: &Proxy, store: &KvStore) -> Result<()> {
    let instances = store.load_all_instances();
    let mut state = proxy.lock();
    let mut wg_changed = false;

    for (instance_id, data) in instances {
        let new_info = InstanceInfo {
            id: instance_id.clone(),
            app_id: data.app_id.clone(),
            ip: data.ip,
            public_key: data.public_key.clone(),
            reg_time: UNIX_EPOCH
                .checked_add(Duration::from_secs(data.reg_time))
                .unwrap_or(UNIX_EPOCH),
            last_seen: SystemTime::now(),
            connections: Default::default(),
        };

        if let Some(existing) = state.state.instances.get(&instance_id) {
            // Check if wg config needs update
            if existing.public_key != data.public_key || existing.ip != data.ip {
                wg_changed = true;
            }
            // Only update if remote is newer (based on reg_time)
            if data.reg_time <= encode_ts(existing.reg_time) {
                continue;
            }
        } else {
            wg_changed = true;
        }

        state.state.allocated_addresses.insert(data.ip);
        state
            .state
            .apps
            .entry(data.app_id)
            .or_default()
            .insert(instance_id.clone());
        state.state.instances.insert(instance_id, new_info);
    }

    if wg_changed {
        state.reconfigure()?;
    }
    Ok(())
}

fn reload_nodes_from_kv_store(proxy: &Proxy, store: &KvStore) -> Result<()> {
    let nodes = store.load_all_nodes();
    let mut state = proxy.lock();

    for (_node_id, data) in nodes {
        // Skip self
        if data.wg_public_key == state.config.wg.public_key {
            continue;
        }

        let new_info = GatewayNodeInfo {
            id: data.id,
            url: data.url,
            wg_peer: WireGuardPeer {
                pk: data.wg_public_key.clone(),
                ip: data.wg_ip,
                endpoint: data.wg_endpoint,
            },
            last_seen: SystemTime::now(),
        };

        // Update or insert node
        state.state.nodes.insert(data.wg_public_key, new_info);
    }

    Ok(())
}

impl ProxyState {
    fn valid_ip(&self, ip: Ipv4Addr) -> bool {
        if self.config.wg.ip.broadcast() == ip {
            return false;
        }
        if self.config.wg.ip.addr() == ip {
            return false;
        }
        if self
            .config
            .wg
            .reserved_net
            .iter()
            .any(|net| net.contains(&ip))
        {
            return false;
        }
        true
    }
    fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for ip in self.config.wg.client_ip_range.hosts() {
            if !self.valid_ip(ip) {
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
            let existing = existing.clone();
            if self.valid_ip(existing.ip) {
                return Some(existing);
            }
            info!("ip {} is invalid, removing", existing.ip);
            self.state.allocated_addresses.remove(&existing.ip);
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
        // Sync to KvStore
        let data = InstanceData {
            app_id: info.app_id.clone(),
            ip: info.ip,
            public_key: info.public_key.clone(),
            reg_time: encode_ts(info.reg_time),
        };
        if let Err(err) = self.kv_store.sync_instance(&info.id, &data) {
            error!("Failed to sync instance to KvStore: {err}");
        }

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
    pub(crate) fn latest_handshakes(
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

        // Sync deletion to KvStore
        if let Err(err) = self.kv_store.sync_delete_instance(id) {
            error!("Failed to sync instance deletion to KvStore: {err}");
        }

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
        // Refresh state from WireGuard (updates instance last_seen and syncs to KvStore)
        if let Err(err) = self.refresh_state() {
            warn!("Failed to refresh state: {err}");
        }

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

    pub(crate) fn refresh_state(&mut self) -> Result<()> {
        let handshakes = self.latest_handshakes(None)?;
        for instance in self.state.instances.values_mut() {
            let Some((ts, _)) = handshakes.get(&instance.public_key).copied() else {
                continue;
            };
            instance.last_seen = decode_ts(ts);

            // Sync last_seen to KvStore
            if let Err(err) = self.kv_store.sync_instance_last_seen(&instance.id, ts) {
                debug!("Failed to sync instance last_seen: {err}");
            }
        }
        if let Some(node) = self.state.nodes.get_mut(&self.config.wg.public_key) {
            node.last_seen = SystemTime::now();
        }
        Ok(())
    }

    /// Sync connection count for an instance to KvStore
    pub(crate) fn sync_connections(&self, instance_id: &str, count: u64) {
        if let Err(err) = self.kv_store.sync_connections(instance_id, count) {
            debug!("Failed to sync connections: {err}");
        }
    }

    /// Get total connections for an instance from KvStore (across all nodes)
    pub(crate) fn get_total_connections(&self, instance_id: &str) -> u64 {
        self.kv_store.get_total_connections(instance_id)
    }
}

fn decode_ts(ts: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(ts))
        .unwrap_or(UNIX_EPOCH)
}

pub(crate) fn encode_ts(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub struct RpcHandler {
    remote_app_id: Option<Vec<u8>>,
    attestation: Option<VerifiedAttestation>,
    state: Proxy,
}

impl RpcHandler {
    fn ensure_from_gateway(&self) -> Result<()> {
        if self.state.config.danger_disable_attestation {
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
        self.state
            .do_register_cvm(&app_id, &instance_id, &request.client_public_key)
    }

    async fn acme_info(self) -> Result<AcmeInfoResponse> {
        self.state.acme_info().await
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

    async fn info(self) -> Result<InfoResponse> {
        let state = self.state.lock();
        Ok(InfoResponse {
            base_domain: state.config.proxy.base_domain.clone(),
            external_port: state.config.proxy.external_port as u32,
            app_address_ns_prefix: state.config.proxy.app_address_ns_prefix.clone(),
        })
    }
}

async fn get_or_generate_quote(
    agent: &DstackGuestClient<PrpcClient>,
    content_type: QuoteContentType<'_>,
    payload: &[u8],
    quote_path: impl AsRef<Path>,
) -> Result<String> {
    let quote_path = quote_path.as_ref();
    if fs::metadata(quote_path).is_ok() {
        return fs::read_to_string(quote_path).context("Failed to read quote");
    }
    let report_data = content_type.to_report_data(payload).to_vec();
    let response = agent
        .get_quote(RawQuoteArgs { report_data })
        .await
        .context("Failed to get quote")?;
    let quote = serde_json::to_string(&response).context("Failed to serialize quote")?;
    safe_write(quote_path, &quote).context("Failed to write quote")?;
    Ok(quote)
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
