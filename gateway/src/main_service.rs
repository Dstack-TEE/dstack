// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use auth_client::AuthClient;

use crate::distributed_certbot::DistributedCertBot;
use cmd_lib::run_cmd as cmd;
use dstack_gateway_rpc::{
    gateway_server::{GatewayRpc, GatewayServer},
    AcmeInfoResponse, GatewayNodeInfo, GetPeersResponse, GuestAgentConfig, InfoResponse, PeerInfo,
    QuotedPublicKey, RegisterCvmRequest, RegisterCvmResponse, WireGuardConfig, WireGuardPeer,
};
use ra_rpc::{CallContext, RpcCall, VerifiedAttestation};
use rand::seq::IteratorRandom;
use rinja::Template as _;
use safe_write::safe_write;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::{
    cert_store::CertStore,
    config::{Config, TlsConfig},
    kv::{
        fetch_peers_from_bootnode, AppIdValidator, HttpsClientConfig, InstanceData, KvStore,
        NodeData, NodeStatus, WaveKvSyncService,
    },
    models::{InstanceInfo, WgConf},
    proxy::{create_acceptor, create_acceptor_with_cert_store, AddressGroup, AddressInfo},
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
    /// Multi-domain certbot (from KvStore DNS credentials and domain configs)
    pub(crate) multi_domain_certbot: Arc<DistributedCertBot>,
    my_app_id: Option<Vec<u8>>,
    state: Mutex<ProxyState>,
    pub(crate) notify_state_updated: Notify,
    auth_client: AuthClient,
    pub(crate) acceptor: RwLock<TlsAcceptor>,
    pub(crate) h2_acceptor: RwLock<TlsAcceptor>,
    /// In-memory certificate store for SNI-based resolution
    pub(crate) cert_store: Arc<CertStore>,
    /// WaveKV-based store for persistence (and cross-node sync when enabled)
    kv_store: Arc<KvStore>,
    /// WaveKV sync service for network synchronization
    pub(crate) wavekv_sync: Option<Arc<WaveKvSyncService>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct ProxyStateMut {
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

        // Initialize WaveKV store without peers (peers will be added dynamically from bootnode)
        let kv_store = Arc::new(
            KvStore::new(config.sync.node_id, vec![], &config.sync.data_dir)
                .context("failed to initialize WaveKV store")?,
        );
        info!(
            "WaveKV store initialized: node_id={}, sync_enabled={}",
            config.sync.node_id, config.sync.enabled
        );

        // Load state from WaveKV
        let instances = kv_store.load_all_instances();
        let nodes = kv_store.load_all_nodes();
        info!(
            "Loaded state from WaveKV: {} instances, {} nodes",
            instances.len(),
            nodes.len()
        );
        let state = build_state_from_kv_store(instances);

        // Sync this node to KvStore
        let node_data = NodeData {
            uuid: config.uuid(),
            url: config.sync.my_url.clone(),
            wg_public_key: config.wg.public_key.clone(),
            wg_endpoint: config.wg.endpoint.clone(),
            wg_ip: config.wg.ip.to_string(),
        };
        if let Err(err) = kv_store.sync_node(config.sync.node_id, &node_data) {
            error!("Failed to sync this node to KvStore: {err}");
        }
        // Set this node's status to Online
        if let Err(err) = kv_store.set_node_status(config.sync.node_id, NodeStatus::Up) {
            error!("Failed to set node status: {err}");
        }
        // Register this node's sync URL in DB (for peer discovery)
        if let Err(err) = kv_store.register_peer_url(config.sync.node_id, &config.sync.my_url) {
            error!("Failed to register peer URL: {err}");
        }

        // Build HttpsClientConfig for mTLS communication
        let https_config = {
            let tls = &tls_config;
            let cert_validator = my_app_id
                .clone()
                .map(|app_id| Arc::new(AppIdValidator::new(app_id)) as _);
            HttpsClientConfig {
                cert_path: tls.certs.clone(),
                key_path: tls.key.clone(),
                ca_cert_path: tls.mutual.ca_certs.clone(),
                cert_validator,
            }
        };

        // Fetch peers from bootnode if configured (only when sync is enabled)
        if config.sync.enabled && !config.sync.bootnode.is_empty() {
            if let Err(err) = fetch_peers_from_bootnode(
                &config.sync.bootnode,
                &kv_store,
                config.sync.node_id,
                &https_config,
            )
            .await
            {
                warn!("Failed to fetch peers from bootnode: {err}");
            }
        }

        // Create WaveKV sync service (only if sync is enabled)
        let wavekv_sync = if config.sync.enabled {
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
        // Bootstrap WaveKV first if sync is enabled, so certbot can load certs from peers
        if let Some(ref wavekv_sync) = wavekv_sync {
            info!("WaveKV: bootstrapping from peers...");
            if let Err(err) = wavekv_sync.bootstrap().await {
                warn!("WaveKV bootstrap failed: {err}");
            }
        }

        // Create CertStore and load certificates from KvStore
        let cert_store = Arc::new(CertStore::new());
        let all_cert_data = kv_store.load_all_cert_data();
        for (domain, data) in &all_cert_data {
            if let Err(err) = cert_store.load_cert(domain, data) {
                warn!("failed to load certificate for {}: {}", domain, err);
            }
        }
        info!(
            "CertStore: loaded {} certificates from KvStore",
            all_cert_data.len()
        );

        // Create multi-domain certbot (uses KvStore configs for DNS credentials and domains)
        let multi_domain_certbot = Arc::new(DistributedCertBot::new(
            kv_store.clone(),
            cert_store.clone(),
            config.certbot.renew_before_expiration,
            config.certbot.renew_timeout,
        ));
        // Initialize any configured domains
        if let Err(err) = multi_domain_certbot.init_all().await {
            warn!("Failed to initialize multi-domain certbot: {}", err);
        }

        // Create acceptors
        // If CertStore has certificates, use SNI-based resolution
        // Otherwise fall back to legacy single-cert mode from files
        let (acceptor, h2_acceptor) = if cert_store.list_domains().is_empty() {
            info!("No certificates in CertStore, using legacy file-based acceptor");
            let acceptor = RwLock::new(
                create_acceptor(&config.proxy, false).context("failed to create acceptor")?,
            );
            let h2_acceptor = RwLock::new(
                create_acceptor(&config.proxy, true).context("failed to create h2 acceptor")?,
            );
            (acceptor, h2_acceptor)
        } else {
            info!(
                "Using CertStore with {} domains for SNI-based TLS",
                cert_store.list_domains().len()
            );
            let acceptor = RwLock::new(
                create_acceptor_with_cert_store(&config.proxy, cert_store.clone(), false)
                    .context("failed to create acceptor with cert store")?,
            );
            let h2_acceptor = RwLock::new(
                create_acceptor_with_cert_store(&config.proxy, cert_store.clone(), true)
                    .context("failed to create h2 acceptor with cert store")?,
            );
            (acceptor, h2_acceptor)
        };

        Ok(Self {
            config,
            state,
            notify_state_updated: Notify::new(),
            my_app_id,
            auth_client,
            acceptor,
            h2_acceptor,
            cert_store,
            multi_domain_certbot,
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
        // Start WaveKV periodic sync (bootstrap already done in new())
        if let Some(ref wavekv_sync) = self.wavekv_sync {
            start_wavekv_sync_task(self.clone(), wavekv_sync.clone()).await;
        }
        start_wavekv_watch_task(self.clone()).context("Failed to start WaveKV watch task")?;
        start_certbot_task(self.clone()).await?;
        start_cert_store_watch_task(self.clone());
        Ok(())
    }

    /// Reload all certificates from KvStore into CertStore and recreate TLS acceptors
    pub(crate) fn reload_all_certs_from_kvstore(&self) -> Result<()> {
        let all_cert_data = self.kv_store.load_all_cert_data();
        let mut loaded = 0;
        for (domain, data) in &all_cert_data {
            if let Err(err) = self.cert_store.load_cert(domain, data) {
                warn!("failed to reload certificate for {}: {}", domain, err);
            } else {
                loaded += 1;
            }
        }
        info!("CertStore: reloaded {} certificates from KvStore", loaded);

        // Recreate acceptors with updated CertStore
        if !self.cert_store.list_domains().is_empty() {
            let new_acceptor =
                create_acceptor_with_cert_store(&self.config.proxy, self.cert_store.clone(), false)
                    .context("failed to recreate acceptor")?;
            let new_h2_acceptor =
                create_acceptor_with_cert_store(&self.config.proxy, self.cert_store.clone(), true)
                    .context("failed to recreate h2 acceptor")?;

            *self.acceptor.write().unwrap() = new_acceptor;
            *self.h2_acceptor.write().unwrap() = new_h2_acceptor;
            info!("TLS acceptors recreated with updated CertStore");
        }
        Ok(())
    }

    /// Renew a specific domain certificate or all domains
    pub(crate) async fn renew_cert(&self, domain: Option<&str>, force: bool) -> Result<bool> {
        match domain {
            Some(domain) => self
                .multi_domain_certbot
                .try_renew(domain, force)
                .await
                .context("failed to renew cert"),
            None => {
                // Renew all domains
                self.multi_domain_certbot
                    .try_renew_all()
                    .await
                    .context("failed to renew all certs")?;
                Ok(true)
            }
        }
    }

    /// Get ACME info for all managed domains (or a specific domain)
    pub(crate) fn acme_info(&self, domain: Option<&str>) -> Result<AcmeInfoResponse> {
        let config = self.lock().config.clone();
        let kv_store = self.kv_store.clone();

        let mut quoted_hist_keys = vec![];
        let mut active_cert = String::new();

        // Get domains to query
        let domains: Vec<String> = match domain {
            Some(d) => vec![d.to_string()],
            None => kv_store
                .list_cert_configs()
                .into_iter()
                .map(|c| c.domain)
                .collect(),
        };

        for domain in &domains {
            // Get all attestations for this domain
            let attestations = kv_store.list_cert_attestations(domain);
            for att in attestations {
                quoted_hist_keys.push(QuotedPublicKey {
                    public_key: att.public_key,
                    quote: att.quote,
                });
            }

            // Get active certificate
            if let Some(cert_data) = kv_store.get_cert_data(domain) {
                if active_cert.is_empty() {
                    active_cert = cert_data.cert_pem;
                }
            }
        }

        Ok(AcmeInfoResponse {
            account_uri: String::new(),   // Stored per-domain in KvStore now
            hist_keys: vec![],            // Deprecated, use quoted_hist_keys
            account_quote: String::new(), // Deprecated
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

        // Check if this node is marked as down
        let my_status = state.kv_store.get_node_status(state.config.sync.node_id);
        if matches!(my_status, NodeStatus::Down) {
            bail!("this gateway node is marked as down and cannot accept new registrations");
        }

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
        let gateways = state.get_active_nodes();
        let servers = gateways
            .iter()
            .map(|n| WireGuardPeer {
                pk: n.wg_public_key.clone(),
                ip: n.wg_ip.clone(),
                endpoint: n.wg_endpoint.clone(),
            })
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
            gateways,
        };
        self.notify_state_updated.notify_one();
        Ok(response)
    }
}

fn build_state_from_kv_store(instances: BTreeMap<String, InstanceData>) -> ProxyStateMut {
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

/// Start periodic certificate renewal task for multi-domain certbot
async fn start_certbot_task(proxy: Proxy) -> Result<()> {
    let renew_interval = proxy.config.certbot.renew_interval;
    if renew_interval.is_zero() {
        info!("certificate renewal task is disabled (renew_interval is 0)");
        return Ok(());
    }

    info!(
        "starting certificate renewal task (interval: {:?})",
        renew_interval
    );

    // Periodic renewal task for all domains
    tokio::spawn(async move {
        // Wait for initial delay before first check
        tokio::time::sleep(renew_interval).await;
        loop {
            if let Err(err) = proxy.renew_cert(None, false).await {
                error!("failed to renew certificates: {err}");
            }
            tokio::time::sleep(renew_interval).await;
        }
    });
    Ok(())
}

/// Watch for certificate changes from KvStore and update CertStore
fn start_cert_store_watch_task(proxy: Proxy) {
    let kv_store = proxy.kv_store.clone();

    // Watch for any certificate changes (all domains)
    let mut rx = kv_store.watch_all_certs();
    tokio::spawn(async move {
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            info!("WaveKV: detected certificate changes, reloading CertStore...");
            if let Err(err) = proxy.reload_all_certs_from_kvstore() {
                error!("Failed to reload certificates from KvStore: {err}");
            }
        }
    });
    info!("CertStore watch task started");
}

async fn start_wavekv_sync_task(proxy: Proxy, wavekv_sync: Arc<WaveKvSyncService>) {
    if !proxy.config.sync.enabled {
        info!("WaveKV sync is disabled");
        return;
    }

    // Bootstrap already done in ProxyInner::new() before certbot init
    // Peers are discovered from bootnode or via Admin.SetNodeInfo RPC

    // Start periodic sync tasks (runs forever in background)
    tokio::spawn(async move {
        wavekv_sync.start_sync_tasks().await;
    });
    info!("WaveKV sync tasks started");
}

fn start_wavekv_watch_task(proxy: Proxy) -> Result<()> {
    let kv_store = proxy.kv_store.clone();

    // Watch for instance changes
    let proxy_clone = proxy.clone();
    let store_clone = kv_store.clone();
    // Register watcher first, then do initial load to avoid race condition
    let mut rx = store_clone.watch_instances();
    reload_instances_from_kv_store(&proxy_clone, &store_clone)
        .context("Failed to initial load instances from KvStore")?;
    tokio::spawn(async move {
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

    // Initial WireGuard configuration
    proxy.lock().reconfigure()?;

    // Watch for node changes and reconfigure WireGuard
    let mut rx = kv_store.watch_nodes();
    let proxy_for_nodes = proxy.clone();
    tokio::spawn(async move {
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            info!("WaveKV: detected remote node changes, reconfiguring WireGuard...");
            if let Err(err) = proxy_for_nodes.lock().reconfigure() {
                error!("Failed to reconfigure WireGuard: {err}");
            }
        }
    });

    // Start periodic persistence task
    let persist_interval = proxy.config.sync.persist_interval;
    if !persist_interval.is_zero() {
        let kv_store_for_persist = kv_store.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(persist_interval);
            loop {
                ticker.tick().await;
                match kv_store_for_persist.persist_if_dirty() {
                    Ok(true) => info!("WaveKV: periodic persist completed"),
                    Ok(false) => {} // No changes to persist
                    Err(err) => error!("WaveKV: periodic persist failed: {err}"),
                }
            }
        });
        info!("WaveKV: periodic persistence enabled (interval: {persist_interval:?})");
    }

    // Start periodic connection sync task
    if proxy.config.sync.sync_connections_enabled {
        let sync_interval = proxy.config.sync.sync_connections_interval;
        let proxy_for_sync = proxy.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(sync_interval);
            loop {
                ticker.tick().await;
                let state = proxy_for_sync.lock();
                for (instance_id, instance) in &state.state.instances {
                    let count = instance.num_connections();
                    state.sync_connections(instance_id, count);
                }
            }
        });
        info!(
            "WaveKV: periodic connection sync enabled (interval: {:?})",
            proxy.config.sync.sync_connections_interval
        );
    }

    Ok(())
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
                // Sync existing instance to KvStore (might be from legacy state)
                let data = InstanceData {
                    app_id: existing.app_id.clone(),
                    ip: existing.ip,
                    public_key: existing.public_key.clone(),
                    reg_time: encode_ts(existing.reg_time),
                };
                if let Err(err) = self.kv_store.sync_instance(&existing.id, &data) {
                    error!("failed to sync existing instance to KvStore: {err}");
                }
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
            error!("failed to sync instance to KvStore: {err}");
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
        // Refresh state: sync local handshakes to KvStore, update local last_seen from global
        if let Err(err) = self.refresh_state() {
            warn!("failed to refresh state: {err}");
        }

        // Note: Gateway nodes are not removed from KvStore, only marked offline/retired

        // Recycle stale CVM instances based on global last_seen (max across all nodes)
        let stale_timeout = self.config.recycle.timeout;
        let now = SystemTime::now();

        let stale_instances: Vec<_> = self
            .state
            .instances
            .iter()
            .filter(|(id, info)| {
                // Skip if instance was registered recently
                if info.reg_time.elapsed().unwrap_or_default() <= stale_timeout {
                    return false;
                }
                // Check global last_seen from KvStore (max across all nodes)
                let global_ts = self.kv_store.get_instance_latest_handshake(id);
                let last_seen = global_ts.map(decode_ts).unwrap_or(info.reg_time);
                let elapsed = now.duration_since(last_seen).unwrap_or_default();
                if elapsed > stale_timeout {
                    debug!(
                        "stale instance: {} last_seen={:?} ({:?} ago)",
                        id, last_seen, elapsed
                    );
                    true
                } else {
                    false
                }
            })
            .map(|(id, _)| id.clone())
            .collect();

        let num_recycled = stale_instances.len();
        for id in stale_instances {
            self.remove_instance(&id)?;
        }

        if num_recycled > 0 {
            info!("recycled {num_recycled} stale instances");
            self.reconfigure()?;
        }
        Ok(())
    }

    pub(crate) fn exit(&mut self) -> ! {
        std::process::exit(0);
    }

    pub(crate) fn refresh_state(&mut self) -> Result<()> {
        // Get local WG handshakes and sync to KvStore
        let handshakes = self.latest_handshakes(None)?;

        // Build a map from public_key to instance_id for lookup
        let pk_to_id: BTreeMap<&str, &str> = self
            .state
            .instances
            .iter()
            .map(|(id, info)| (info.public_key.as_str(), id.as_str()))
            .collect();

        // Sync local handshake observations to KvStore
        for (pk, (ts, _)) in &handshakes {
            if let Some(&instance_id) = pk_to_id.get(pk.as_str()) {
                if let Err(err) = self.kv_store.sync_instance_handshake(instance_id, *ts) {
                    debug!("failed to sync instance handshake: {err}");
                }
            }
        }

        // Update this node's last_seen in KvStore
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(err) = self
            .kv_store
            .sync_node_last_seen(self.config.sync.node_id, now)
        {
            debug!("failed to sync node last_seen: {err}");
        }
        Ok(())
    }

    /// Sync connection count for an instance to KvStore
    pub(crate) fn sync_connections(&self, instance_id: &str, count: u64) {
        if let Err(err) = self.kv_store.sync_connections(instance_id, count) {
            debug!("Failed to sync connections: {err}");
        }
    }

    /// Get latest handshake for an instance from KvStore (max across all nodes)
    pub(crate) fn get_instance_latest_handshake(&self, instance_id: &str) -> Option<u64> {
        self.kv_store.get_instance_latest_handshake(instance_id)
    }

    /// Get all nodes from KvStore (for admin API - includes all nodes)
    pub(crate) fn get_all_nodes(&self) -> Vec<GatewayNodeInfo> {
        self.get_all_nodes_filtered(false)
    }

    /// Get nodes for CVM registration (excludes nodes with status "down")
    pub(crate) fn get_active_nodes(&self) -> Vec<GatewayNodeInfo> {
        self.get_all_nodes_filtered(true)
    }

    /// Get all nodes from KvStore with optional filtering
    fn get_all_nodes_filtered(&self, exclude_down: bool) -> Vec<GatewayNodeInfo> {
        let node_statuses = if exclude_down {
            self.kv_store.load_all_node_statuses()
        } else {
            Default::default()
        };

        self.kv_store
            .load_all_nodes()
            .into_iter()
            .filter(|(id, _)| {
                if !exclude_down {
                    return true;
                }
                // Exclude nodes with status "down"
                match node_statuses.get(id) {
                    Some(NodeStatus::Down) => false,
                    _ => true, // Include Up or nodes without explicit status
                }
            })
            .map(|(id, node)| GatewayNodeInfo {
                id,
                uuid: node.uuid,
                wg_public_key: node.wg_public_key,
                wg_ip: node.wg_ip,
                wg_endpoint: node.wg_endpoint,
                url: node.url,
                last_seen: self.kv_store.get_node_latest_last_seen(id).unwrap_or(0),
            })
            .collect()
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
        if self.state.config.debug.insecure_skip_attestation {
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
        self.state.acme_info(None)
    }

    async fn info(self) -> Result<InfoResponse> {
        let state = self.state.lock();
        Ok(InfoResponse {
            base_domain: state.config.proxy.base_domain.clone(),
            external_port: state.config.proxy.external_port as u32,
            app_address_ns_prefix: state.config.proxy.app_address_ns_prefix.clone(),
        })
    }

    async fn get_peers(self) -> Result<GetPeersResponse> {
        self.ensure_from_gateway()?;

        let kv_store = self.state.kv_store();
        let config = &self.state.config;

        // Get all peer addresses from KvStore
        let peer_addrs = kv_store.get_all_peer_addrs();

        let peers: Vec<PeerInfo> = peer_addrs
            .into_iter()
            .map(|(id, url)| PeerInfo { id, url })
            .collect();

        Ok(GetPeersResponse {
            my_id: config.sync.node_id,
            my_url: config.sync.my_url.clone(),
            peers,
        })
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

#[cfg(test)]
mod tests;
