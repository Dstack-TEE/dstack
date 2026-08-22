// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::Ipv4Addr,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context, Result};
use auth_client::AuthClient;

use crate::distributed_certbot::DistributedCertBot;
use cmd_lib::run_cmd as cmd;
use dstack_gateway_rpc::{
    gateway_server::{GatewayRpc, GatewayServer},
    AcmeInfoResponse, GatewayNodeInfo, GetPeersResponse, GuestAgentConfig, InfoResponse, PeerInfo,
    QuotedPublicKey, RegisterCvmRequest, RegisterCvmResponse, WireGuardConfig, WireGuardPeer,
};
use or_panic::ResultOrPanic;
use ra_rpc::{CallContext, RpcCall, VerifiedAttestation};
use ra_tls::attestation::AppInfo;
use rand::seq::IteratorRandom;
use rinja::Template as _;
use safe_write::safe_write_with_mode;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender},
    Notify,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use wavekv::types::NodeId;

use crate::{
    cert_store::{CertResolver, CertStoreBuilder},
    config::{Config, TlsConfig},
    kv::{
        fetch_peers_from_bootnode, import, keys, AdminOverrides, AdminPortPolicy, AppIdValidator,
        CertData, HttpsClientConfig, InstanceData, InstanceGate, KvStore, LoadedInstances,
        LoadedOverrides, NodeData, NodeStatus, PortPolicy, WaveKvSyncService,
    },
    models::{InstanceInfo, PortPolicyView, WgConf, WgPeer},
    proxy::{create_acceptor_with_cert_resolver, AddressGroup, AddressInfo, AppAddressResolver},
    time::{decode_ts, now_secs},
};

mod auth_client;
mod handshakes;

use handshakes::LatestHandshakesCache;

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
    pub(crate) certbot: Arc<DistributedCertBot>,
    my_app_id: Option<Vec<u8>>,
    state: Mutex<ProxyState>,
    pub(crate) notify_state_updated: Notify,
    auth_client: AuthClient,
    pub(crate) acceptor: TlsAcceptor,
    pub(crate) h2_acceptor: TlsAcceptor,
    /// Certificate resolver for SNI-based resolution (supports atomic updates)
    pub(crate) cert_resolver: Arc<CertResolver>,
    /// WaveKV-based store for persistence (and cross-node sync when enabled)
    kv_store: Arc<KvStore>,
    /// WaveKV sync service for network synchronization
    pub(crate) wavekv_sync: Option<Arc<WaveKvSyncService>>,
    /// HTTPS client config for mTLS (used for bootnode peer discovery)
    https_config: Option<HttpsClientConfig>,
    /// Sender for the background port_policy lazy-fetch worker. On a cache
    /// miss the proxy data path enqueues the instance_id and immediately
    /// rejects the connection (fail-close); the fetch populates the cache
    /// asynchronously so subsequent connections can proceed. Without a
    /// known policy, `restrict_mode` is indeterminate and we cannot safely
    /// allow traffic.
    pub(crate) port_policy_tx: UnboundedSender<String>,
    handshake_cache: Arc<LatestHandshakesCache>,
    /// Shared DNS resolver for SNI TXT lookups. Reusing one resolver lets the
    /// hickory DNS cache work across proxy connections.
    pub(crate) app_address_resolver: Arc<AppAddressResolver>,
}

const HANDSHAKE_CACHE_TTL: Duration = Duration::from_secs(30);
const HANDSHAKE_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

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
    handshake_cache: Arc<LatestHandshakesCache>,
    admin_shutdown: Option<rocket::Shutdown>,
    /// Reason last logged for each KV instance record this node refuses, so a
    /// record that stays bad is reported once rather than on every reload.
    reported_rejections: BTreeMap<String, String>,
    /// The same, for `admin/` records this node cannot decode.
    reported_bad_overrides: BTreeMap<String, String>,
}

/// Options for creating a Proxy instance
pub struct ProxyOptions {
    pub config: Config,
    pub my_app_id: Option<Vec<u8>>,
    /// TLS configuration (from Rocket's tls config)
    pub tls_config: TlsConfig,
}

/// Outcome of an operator-initiated CVM removal.
///
/// Both fields are false when the instance was never known (or the removal
/// already completed), which lets the operator distinguish a mistyped
/// instance_id from an actual removal.
pub struct CvmRemoval {
    /// A live instance record (decodable or not) existed in WaveKV.
    pub record_existed: bool,
    /// The CVM was present in this node's local data plane.
    pub removed_locally: bool,
}

/// Outcome of an operator-initiated gateway node removal.
///
/// Both fields are false when the node was never known (or the removal
/// already completed), which lets the operator distinguish a mistyped
/// node_id from an actual removal.
pub struct NodeRemoval {
    /// Any of the node's records (info, status, or sync address) was live
    /// in WaveKV.
    pub record_existed: bool,
    /// The node was still in this gateway's sync peer set.
    pub removed_from_peer_set: bool,
}

/// A refused instance record plus its local data-plane footprint.
pub struct RejectedInstanceReport {
    pub rejected: import::RejectedInstance,
    /// Whether the instance still holds state in this node's data plane. An
    /// unusable record keeps whatever the data plane already had, so removing
    /// an active instance also drops its routing.
    pub active_locally: bool,
}

impl Proxy {
    /// Remove one CVM by explicit operator request.
    ///
    /// The tombstone is written even when this node cannot decode the stored
    /// record or no longer has the CVM in memory. This makes the operation an
    /// idempotent recovery path for bad replicated instance records without
    /// exposing arbitrary raw-KV deletion.
    pub fn remove_cvm(&self, instance_id: &str) -> Result<CvmRemoval> {
        let mut state = self.lock();
        let record_existed = state
            .kv_store
            .sync_delete_instance(instance_id)
            .with_context(|| format!("failed to delete CVM {instance_id} from WaveKV"))?;

        let removed_locally = state.forget_instance(instance_id).is_some();
        // Reconfigure unconditionally: the tombstone write and the in-memory
        // removal are not repeated on a retry, so gating this on them would
        // leave a failed reconfigure with no retry path and the removed CVM's
        // WireGuard peer stuck on the interface.
        state.reconfigure()?;
        Ok(CvmRemoval {
            record_existed,
            removed_locally,
        })
    }

    /// Instance records this node currently refuses to import.
    ///
    /// Recomputed from the store on every call rather than read from the
    /// cached rejection log, so the answer is current even right after a
    /// restart and does not depend on when the last reload ran.
    pub fn rejected_instances(&self) -> Vec<RejectedInstanceReport> {
        let rejected =
            import::accept_instances(&self.config.wg, self.kv_store.load_all_instances()).rejected;
        let state = self.lock();
        rejected
            .into_iter()
            .map(|rejected| RejectedInstanceReport {
                active_locally: state.state.instances.contains_key(&rejected.instance_id),
                rejected,
            })
            .collect()
    }

    /// Remove a decommissioned gateway node by explicit operator request.
    ///
    /// Tombstones the node's replicated records and drops it from this
    /// gateway's sync peer set immediately; other gateways prune their own
    /// sets when the `__peer_addr` tombstone reaches them. A node removed by
    /// mistake rejoins when it restarts (startup re-registers its records),
    /// or via `SetNodeUrl` from any live gateway.
    pub fn remove_node(&self, node_id: NodeId) -> Result<NodeRemoval> {
        ensure!(
            node_id != self.config.sync.node_id,
            "a node cannot remove itself"
        );
        // Drop the peer before publishing the tombstone: the __peer_addr
        // deletion wakes the peer-address watcher, whose prune would
        // otherwise race this call and make the reported membership depend
        // on scheduling.
        let removed_from_peer_set = self.kv_store.remove_peer(node_id)?;
        let record_existed = self
            .kv_store
            .sync_remove_node(node_id)
            .with_context(|| format!("failed to delete node {node_id} from WaveKV"))?;
        Ok(NodeRemoval {
            record_existed,
            removed_from_peer_set,
        })
    }

    pub async fn new(options: ProxyOptions) -> Result<Self> {
        let (port_policy_tx, port_policy_rx) = unbounded_channel();
        let inner = ProxyInner::new(options, port_policy_tx).await?;
        let proxy = Self {
            _inner: Arc::new(inner),
        };
        crate::proxy::port_policy::spawn_fetcher(proxy.clone(), port_policy_rx);
        Ok(proxy)
    }
}

impl ProxyInner {
    pub(crate) fn lock(&self) -> MutexGuard<'_, ProxyState> {
        self.state.lock().or_panic("Failed to lock AppState")
    }

    pub async fn new(
        options: ProxyOptions,
        port_policy_tx: UnboundedSender<String>,
    ) -> Result<Self> {
        let ProxyOptions {
            config,
            my_app_id,
            tls_config,
        } = options;
        let config = Arc::new(config);

        // Initialize WaveKV store without peers (peers will be added dynamically from bootnode)
        let kv_store = Arc::new(
            KvStore::new(
                config.sync.node_id,
                vec![],
                &config.sync.data_dir,
                (!config.sync.wal_sync_window.is_zero()).then_some(config.sync.wal_sync_window),
            )
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
            "Loaded state from WaveKV: {} instances ({} unreadable), {} nodes",
            instances.decoded.len(),
            instances.undecodable.len(),
            nodes.len()
        );
        // Read-only: nothing may be written before the bootstrap below, so the
        // move of any legacy overrides waits for the first reload.
        let overrides = kv_store.load_all_instance_overrides();
        let legacy_overrides = kv_store.legacy_instance_overrides();
        let state = build_state_from_kv_store(&config, instances, &overrides, &legacy_overrides);

        // This node's own records are written *after* the bootstrap below, not
        // here. A local write allocates a sequence number, and after a
        // data-directory loss this node has no record of which numbers it
        // already spent — only its peers do. `bootstrap` rebuilds the counter
        // from their coverage, so anything written before it reuses numbers the
        // peers already treat as seen and is silently dropped cluster-wide.
        // That would strand exactly the records recovery depends on: the fresh
        // uuid peers check us against, and our sync address.
        let node_data = NodeData {
            uuid: config.uuid(),
            url: config.sync.my_url.clone(),
            wg_public_key: config.wg.public_key.clone(),
            wg_endpoint: config.wg.endpoint.clone(),
            wg_ip: config.wg.ip.to_string(),
        };
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
                warn!("Failed to fetch peers from bootnode: {err:?}");
            }
        }

        // Create WaveKV sync service (only if sync is enabled)
        let wavekv_sync = if config.sync.enabled {
            match WaveKvSyncService::new(
                &kv_store,
                &config.sync,
                https_config.clone(),
                node_data.uuid.clone(),
            ) {
                Ok(sync_service) => Some(Arc::new(sync_service)),
                Err(err) => {
                    error!("Failed to create WaveKV sync service: {err:?}");
                    None
                }
            }
        } else {
            None
        };

        let handshake_cache = Arc::new(LatestHandshakesCache::new(
            config.wg.interface.clone(),
            HANDSHAKE_CACHE_TTL,
        ));
        if let Err(err) = handshake_cache.refresh().await {
            warn!("failed to preload WireGuard latest-handshakes cache: {err:?}");
        }

        let state = Mutex::new(ProxyState {
            config: config.clone(),
            state,
            kv_store: kv_store.clone(),
            handshake_cache: handshake_cache.clone(),
            admin_shutdown: None,
            reported_rejections: BTreeMap::new(),
            reported_bad_overrides: BTreeMap::new(),
        });
        let auth_client = AuthClient::new(config.auth.clone());
        // Bootstrap WaveKV first if sync is enabled, so certbot can load certs from peers
        if let Some(ref wavekv_sync) = wavekv_sync {
            info!("WaveKV: bootstrapping from peers...");
            if let Err(err) = wavekv_sync.bootstrap().await {
                warn!("WaveKV bootstrap failed: {err:?}");
            }
        }

        // Publish this node's own records now that the sequence counter reflects
        // whatever the peers already know we have spent (see the note above).
        if let Err(err) = kv_store.sync_node(config.sync.node_id, &node_data) {
            error!("Failed to sync this node to KvStore: {err:?}");
        }
        // Set this node's status to Online
        if let Err(err) = kv_store.set_node_status(config.sync.node_id, NodeStatus::Up) {
            error!("Failed to set node status: {err:?}");
        }
        // Register this node's sync URL in DB (for peer discovery)
        if let Err(err) = kv_store.register_peer_url(config.sync.node_id, &config.sync.my_url) {
            error!("Failed to register peer URL: {err:?}");
        }

        // Create CertResolver and load certificates from KvStore
        let cert_resolver = Arc::new(CertResolver::new());
        let all_cert_data = kv_store.load_all_cert_data();
        if !all_cert_data.is_empty() {
            let mut builder = CertStoreBuilder::new();
            for (domain, data) in &all_cert_data {
                if let Err(err) = builder.add_cert(domain, data) {
                    warn!("failed to load certificate for {domain}: {err:?}");
                }
            }
            cert_resolver.set(Arc::new(builder.build()));
            info!(
                "CertStore: loaded {} certificates from KvStore",
                all_cert_data.len()
            );
        }
        if let (Some(base_domain), Some(cert_chain), Some(cert_key)) = (
            &config.proxy.base_domain,
            &config.proxy.cert_chain,
            &config.proxy.cert_key,
        ) {
            let cert_pem = std::fs::read_to_string(cert_chain).with_context(|| {
                format!("failed to read proxy cert_chain {}", cert_chain.display())
            })?;
            let key_pem = std::fs::read_to_string(cert_key)
                .with_context(|| format!("failed to read proxy cert_key {}", cert_key.display()))?;
            let now = now_secs();
            let cert_data = CertData {
                cert_pem,
                key_pem,
                not_after: now + 14 * 24 * 60 * 60,
                issued_by: config.sync.node_id,
                issued_at: now,
            };
            cert_resolver
                .update_cert(base_domain, &cert_data)
                .with_context(|| format!("failed to load static proxy cert for {base_domain}"))?;
            info!("CertStore: loaded static proxy certificate for *.{base_domain}");
        }

        // Create multi-domain certbot (uses KvStore configs for DNS credentials and domains)
        let certbot = Arc::new(DistributedCertBot::new(
            kv_store.clone(),
            cert_resolver.clone(),
            wavekv_sync
                .clone()
                .map(|service| service as Arc<dyn crate::kv::PersistentWriteNotifier>),
        ));
        // Initialize any configured domains
        if let Err(err) = certbot.init_all().await {
            warn!("Failed to initialize multi-domain certbot: {err:?}");
        }

        // Create TLS acceptors with CertResolver for SNI-based resolution
        // CertResolver allows atomic certificate updates without recreating acceptors
        info!(
            "CertResolver initialized with {} domains",
            cert_resolver.list_domains().len()
        );
        let acceptor =
            create_acceptor_with_cert_resolver(&config.proxy, cert_resolver.clone(), false)
                .context("failed to create acceptor with cert resolver")?;
        let h2_acceptor =
            create_acceptor_with_cert_resolver(&config.proxy, cert_resolver.clone(), true)
                .context("failed to create h2 acceptor with cert resolver")?;
        let app_address_resolver = Arc::new(
            AppAddressResolver::new(
                config.proxy.app_address_ns_prefix.clone(),
                config.proxy.app_address_ns_compat,
                config.proxy.app_address_dns_servers.clone(),
            )
            .context("failed to create app address resolver")?,
        );

        Ok(Self {
            config,
            state,
            notify_state_updated: Notify::new(),
            my_app_id,
            auth_client,
            acceptor,
            h2_acceptor,
            cert_resolver,
            certbot,
            kv_store,
            wavekv_sync,
            https_config: Some(https_config),
            port_policy_tx,
            handshake_cache,
            app_address_resolver,
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
        if let Err(err) = self.handshake_cache.refresh().await {
            warn!("failed to refresh WireGuard latest-handshakes cache before starting background tasks: {err:?}");
        }
        self.handshake_cache
            .clone()
            .spawn_refresh_task(HANDSHAKE_REFRESH_INTERVAL);
        start_recycle_thread(self.clone());
        // Start WaveKV periodic sync (bootstrap already done in new())
        if let Some(ref wavekv_sync) = self.wavekv_sync {
            start_wavekv_sync_task(self.clone(), wavekv_sync.clone()).await;
        }
        start_wavekv_watch_task(self.clone()).context("Failed to start WaveKV watch task")?;
        start_certbot_task(self.clone()).await;
        start_cert_store_watch_task(self.clone());
        start_zt_domain_watch_task(self.clone());
        start_bootnode_discovery_task(self.clone());
        Ok(())
    }

    /// Reload all certificates from KvStore into CertStore (atomic replacement)
    pub(crate) fn reload_all_certs_from_kvstore(&self) -> Result<()> {
        let all_cert_data = self.kv_store.load_all_cert_data();

        // Build new CertStore from scratch
        let mut builder = CertStoreBuilder::new();
        let mut loaded = 0;
        for (domain, data) in &all_cert_data {
            if let Err(err) = builder.add_cert(domain, data) {
                warn!("failed to reload certificate for {domain}: {err:?}");
            } else {
                loaded += 1;
            }
        }

        // Atomically replace the CertStore (no need to recreate acceptors)
        self.cert_resolver.set(Arc::new(builder.build()));
        info!("CertStore: reloaded {loaded} certificates from KvStore");
        Ok(())
    }

    /// Renew a specific domain certificate or all domains
    pub(crate) async fn renew_cert(&self, domain: Option<&str>, force: bool) -> Result<bool> {
        match domain {
            Some(domain) => self
                .certbot
                .try_renew(domain, force)
                .await
                .context("failed to renew cert"),
            None => {
                // Renew all domains
                self.certbot
                    .try_renew_all()
                    .await
                    .context("failed to renew all certs")?;
                Ok(true)
            }
        }
    }

    pub(crate) async fn rotate_acme_credentials(&self) -> Result<(String, usize)> {
        self.certbot.rotate_acme_credentials().await
    }

    /// Get ACME info for all managed domains (or a specific domain)
    pub(crate) fn acme_info(&self, domain: Option<&str>) -> Result<AcmeInfoResponse> {
        let kv_store = self.kv_store.clone();

        let mut quoted_hist_keys = vec![];

        // Get domains to query
        let domains: Vec<String> = match domain {
            Some(d) => vec![d.to_string()],
            None => kv_store
                .list_zt_domain_configs()
                .into_iter()
                .map(|c| c.domain)
                .collect(),
        };

        // The account URI comes from the published credentials; the attestation
        // record is written best-effort and may lag behind a rotation, so it
        // only supplies the quote when it matches the current account.
        let attestation = kv_store
            .get_acme_attestation()
            .context("failed to read the ACME account attestation")?;
        let account_uri = kv_store
            .get_acme_credentials()
            .context("call RotateAcmeCredentials to replace the stored ACME credentials")?
            .and_then(|creds| {
                crate::distributed_certbot::extract_account_uri(&creds.acme_credentials)
            })
            .or_else(|| attestation.as_ref().map(|att| att.account_uri.clone()))
            .unwrap_or_default();
        let (account_quote, account_attestation) = attestation
            .filter(|att| att.account_uri == account_uri)
            .map(|att| (att.quote, att.attestation))
            .unwrap_or_default();

        for domain in &domains {
            // Get all attestations for this domain
            let attestations = kv_store.list_cert_attestations(domain);
            for att in attestations {
                quoted_hist_keys.push(QuotedPublicKey {
                    public_key: att.public_key,
                    quote: att.quote,
                    attestation: att.attestation,
                });
            }
        }
        Ok(AcmeInfoResponse {
            account_uri,
            account_quote,
            account_attestation,
            quoted_hist_keys,
        })
    }

    /// Register a CVM with the given app_id, instance_id and client_public_key.
    ///
    /// `port_policy = None` means the CVM didn't report any policy (legacy
    /// CVM). The gateway will lazily fetch it via Info() on first connection.
    ///
    /// `compose_hash` is the attested compose_hash — used to invalidate any
    /// cached `port_policy` when the app is upgraded.
    pub fn do_register_cvm(
        &self,
        app_id: &str,
        instance_id: &str,
        client_public_key: &str,
        compose_hash: &str,
        port_policy: Option<PortPolicy>,
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
        import::validate_wg_public_key(client_public_key)
            .with_context(|| format!("[{instance_id}] invalid client public key"))?;
        let client_info = state
            .new_client_by_id(
                instance_id,
                app_id,
                client_public_key,
                compose_hash,
                port_policy,
            )
            .context("failed to allocate IP address for client")?;
        if let Err(err) = state.reconfigure() {
            error!("failed to reconfigure: {err:?}");
        }
        // Capture the prewarm decision before continuing under the lock.
        // If the instance arrived without port_policy (legacy CVM, or
        // compose_hash mismatch invalidated the cache), enqueue a
        // background fetch so the first proxied connection isn't the one
        // that triggers it. The fetcher dedupes, so this is safe.
        let needs_prewarm = client_info.port_policy.is_none();
        let gateways = state.get_active_nodes();
        let servers = gateways
            .iter()
            .map(|n| WireGuardPeer {
                pk: n.wg_public_key.clone(),
                ip: n.wg_ip.clone(),
                endpoint: n.wg_endpoint.clone(),
            })
            .collect::<Vec<_>>();
        let (base_domain, port) = state.kv_store.get_best_zt_domain().unwrap_or_default();
        let response = RegisterCvmResponse {
            wg: Some(WireGuardConfig {
                client_ip: client_info.ip.to_string(),
                servers,
            }),
            agent: Some(GuestAgentConfig {
                external_port: port.into(),
                internal_port: state.config.proxy.agent_port.into(),
                domain: base_domain,
                app_address_ns_prefix: state.config.proxy.app_address_ns_prefix.clone(),
            }),
            gateways,
        };
        drop(state);
        if needs_prewarm {
            let _ = self.port_policy_tx.send(instance_id.to_string());
        }
        self.notify_state_updated.notify_one();
        Ok(response)
    }
}

/// Log the records a KV import refused, one line each.
///
/// A refused record makes its CVM invisible to this node, so it must never be
/// a silent skip.
fn report_rejected_instances(rejected: &[import::RejectedInstance]) {
    for import::RejectedInstance {
        instance_id,
        reason,
        ..
    } in rejected
    {
        error!("ignoring KV instance record {instance_id}: {reason:#}");
    }
}

/// Report refused records, but only what has changed since the last reload.
///
/// A record is refused because of what it contains, so nothing about the next
/// reload will make it acceptable — it stays refused until someone rewrites it.
/// Logging the whole set every round turns one stuck record into an unbounded
/// stream of identical `error!` lines, at whatever rate peer syncs happen to
/// wake the watch task, which buries the very first occurrence. Report a record
/// when it starts being refused or its reason changes, and again when it
/// recovers, so the log carries transitions instead of a level.
fn report_new_rejections(
    reported: &mut BTreeMap<String, String>,
    rejected: &[import::RejectedInstance],
) {
    let mut current = BTreeMap::new();
    for import::RejectedInstance {
        instance_id,
        reason,
        ..
    } in rejected
    {
        let reason = format!("{reason:#}");
        if reported.get(instance_id) != Some(&reason) {
            error!("ignoring KV instance record {instance_id}: {reason}");
        }
        current.insert(instance_id.clone(), reason);
    }
    for instance_id in reported.keys() {
        if !current.contains_key(instance_id) {
            info!("KV instance record {instance_id} is usable again");
        }
    }
    *reported = current;
}

/// The operator overrides in force for `instance_id`.
///
/// The `admin/` record wins whenever there is one, including when it says
/// nothing is overridden. Only when there is none does the copy an older build
/// left inside the instance record apply -- that is the same rule
/// [`KvStore::migrate_legacy_instance_overrides`] writes by, so a reload before
/// the move and one after it answer the same thing.
///
/// A record that will not decode is neither. Guessing "nothing is overridden"
/// is what would return a quarantined instance to rotation, so the instance is
/// held out of app-id selection until the record is readable again; it stays
/// reachable by instance id throughout, as a gated instance always is.
fn effective_overrides(
    instance_id: &str,
    current: &LoadedOverrides,
    legacy: &BTreeMap<String, AdminOverrides>,
) -> AdminOverrides {
    if current.unreadable.contains_key(instance_id) {
        return AdminOverrides {
            port_policy: None,
            ready: Some(false),
        };
    }
    // Per key, not per instance. They are separate keys, so one of them
    // existing says nothing about the other: an operator who sets the gate
    // through the new path on an instance whose port-policy override is still
    // in the instance record would otherwise have the override dropped, which
    // is the failure this whole split exists to remove.
    let written = current.written_keys(instance_id);
    let stored = current.decoded.get(instance_id);
    let legacy = legacy.get(instance_id);
    AdminOverrides {
        ready: if written.contains(keys::ADMIN_READY) {
            stored.and_then(|stored| stored.ready)
        } else {
            legacy.and_then(|legacy| legacy.ready)
        },
        port_policy: if written.contains(keys::ADMIN_PORT_POLICY) {
            stored.and_then(|stored| stored.port_policy.clone())
        } else {
            legacy.and_then(|legacy| legacy.port_policy.clone())
        },
    }
}

/// Report override records this node cannot read, once per transition.
///
/// Unreadable means the instance is held out of app-id rotation, so it is not a
/// quiet condition -- but a record that stays bad would otherwise be reported on
/// every reload, and reloads are driven by cluster activity.
fn report_unreadable_overrides(proxy: &Proxy, loaded: &LoadedOverrides) {
    let mut state = proxy.lock();
    for (instance_id, reason) in &loaded.unreadable {
        if state.reported_bad_overrides.get(instance_id) != Some(reason) {
            error!(
                "cannot read the operator overrides for instance {instance_id}, holding it \
                 out of load balancing until they are readable again: {reason}"
            );
        }
    }
    for instance_id in state.reported_bad_overrides.keys() {
        if !loaded.unreadable.contains_key(instance_id) {
            info!("operator overrides for instance {instance_id} are readable again");
        }
    }
    state.reported_bad_overrides = loaded.unreadable.clone();
}

fn build_state_from_kv_store(
    config: &Config,
    instances: LoadedInstances,
    overrides: &LoadedOverrides,
    legacy_overrides: &BTreeMap<String, AdminOverrides>,
) -> ProxyStateMut {
    let mut state = ProxyStateMut::default();

    let accepted = import::accept_instances(&config.wg, instances);
    report_rejected_instances(&accepted.rejected);

    // Build instances
    for (instance_id, data) in accepted.instances {
        let admin = effective_overrides(&instance_id, overrides, legacy_overrides);
        let info = InstanceInfo {
            id: instance_id.clone(),
            app_id: data.app_id.clone(),
            ip: data.ip,
            public_key: data.public_key,
            reg_time: UNIX_EPOCH
                .checked_add(Duration::from_secs(data.reg_time))
                .unwrap_or(UNIX_EPOCH),
            port_policy: data.port_policy,
            port_policy_hash: data.port_policy_hash,
            admin_port_policy: admin.port_policy,
            ready: admin.ready,
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
            error!("failed to run recycle: {err:?}");
        };
    });
}

/// Start periodic certificate renewal task for multi-domain certbot
async fn start_certbot_task(proxy: Proxy) {
    info!("starting certificate renewal task");

    // Periodic renewal task for all domains
    tokio::spawn(async move {
        // Run once at startup to check for any pending renewals
        info!("running initial certificate renewal check");
        if let Err(err) = proxy.renew_cert(None, false).await {
            error!("failed initial certificate renewal: {err:?}");
        }

        loop {
            // Get current config from KV store (allows dynamic updates)
            let renew_interval = match proxy.kv_store.get_certbot_config() {
                Ok(config) => config.renew_interval,
                Err(err) => {
                    // Falling back to the defaults here would switch acme_url
                    // back to Let's Encrypt production; wait for an operator to
                    // repair the record instead.
                    error!("failed to read certbot config, skipping renewal round: {err:?}");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    continue;
                }
            };
            if renew_interval.is_zero() {
                // Check again later if disabled
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }

            // Wait for the interval
            tokio::time::sleep(renew_interval).await;

            // Renew certificates
            if let Err(err) = proxy.renew_cert(None, false).await {
                error!("failed to renew certificates: {err:?}");
            }
        }
    });
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
                error!("Failed to reload certificates from KvStore: {err:?}");
            }
        }
    });
    info!("CertStore watch task started");
}

/// Watch for ZT-Domain config changes and auto-renew certificates
fn start_zt_domain_watch_task(proxy: Proxy) {
    let kv_store = proxy.kv_store.clone();
    let certbot = proxy.certbot.clone();

    let mut rx = kv_store.watch_zt_domain_configs();
    tokio::spawn(async move {
        // Track known domains to detect additions
        let mut known_domains = kv_store
            .list_zt_domain_configs()
            .into_iter()
            .map(|c| c.domain)
            .collect::<HashSet<_>>();

        loop {
            if rx.changed().await.is_err() {
                break;
            }

            // Get current domains
            let current_domains: HashSet<String> = kv_store
                .list_zt_domain_configs()
                .into_iter()
                .map(|c| c.domain)
                .collect();

            // Find newly added domains
            let new_domains: Vec<String> = current_domains
                .iter()
                .filter(|d| !known_domains.contains(*d))
                .cloned()
                .collect();

            // Update known domains
            known_domains = current_domains;

            // Trigger renewal for new domains
            for domain in new_domains {
                info!("ZT-Domain added: {domain}, attempting certificate request...");
                let certbot = certbot.clone();
                tokio::spawn(async move {
                    match certbot.try_renew(&domain, false).await {
                        Ok(renewed) => {
                            if renewed {
                                info!("cert[{domain}]: successfully issued/renewed");
                            } else {
                                info!("cert[{domain}]: renewal not needed or another node is handling it");
                            }
                        }
                        Err(e) => {
                            warn!("cert[{domain}]: auto-renewal failed: {e:?}");
                        }
                    }
                });
            }
        }
    });
    info!("ZT-Domain watch task started");
}

/// Periodically retry bootnode peer discovery if no peers are available
fn start_bootnode_discovery_task(proxy: Proxy) {
    if !proxy.config.sync.enabled || proxy.config.sync.bootnode.is_empty() {
        return;
    }

    let bootnode = proxy.config.sync.bootnode.clone();
    let node_id = proxy.config.sync.node_id;
    let kv_store = proxy.kv_store.clone();
    let https_config = match &proxy.https_config {
        Some(config) => config.clone(),
        None => return,
    };

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            // Check if we already have peers
            let n_peers = kv_store
                .load_all_node_statuses()
                .keys()
                .filter(|&id| *id != node_id)
                .count();
            if n_peers > 0 {
                info!("bootnode peer discovery finished, {n_peers} peers found");
                break;
            }
            // Try to fetch peers from bootnode
            debug!("retrying bootnode peer discovery...");
            if let Err(err) =
                fetch_peers_from_bootnode(&bootnode, &kv_store, node_id, &https_config).await
            {
                warn!("bootnode discovery retry failed: {err:?}");
            } else {
                info!("bootnode peer discovery succeeded");
            }
        }
    });
    info!("Bootnode discovery task started (will retry every 10s if no peers)");
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
    // The operator overrides live under their own prefix, so a peer opening or
    // closing a traffic gate does not touch `inst/` and would never wake the
    // watcher above.
    let mut overrides_rx = store_clone.watch_instance_overrides();
    reload_instances_from_kv_store(&proxy_clone, &store_clone)
        .context("Failed to initial load instances from KvStore")?;
    tokio::spawn(async move {
        loop {
            let reason = tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    "instance"
                }
                changed = overrides_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    "operator override"
                }
            };
            info!("WaveKV: detected remote {reason} changes, reloading...");
            if let Err(err) = reload_instances_from_kv_store(&proxy_clone, &store_clone) {
                error!("Failed to reload instances from KvStore: {err:?}");
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
                error!("Failed to reconfigure WireGuard: {err:?}");
            }
        }
    });

    // Watch for peer address deletions and prune the sync peer set, so a
    // node removed by an operator on any gateway stops being a sync target
    // here without a restart.
    let mut rx = kv_store.watch_peer_addrs();
    let kv_for_peers = kv_store.clone();
    kv_for_peers.prune_removed_peers();
    tokio::spawn(async move {
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            kv_for_peers.prune_removed_peers();
        }
    });

    // Start periodic persistence task.
    //
    // Both this and the WAL sync below run on the blocking pool. Each ends in a
    // synchronous fsync — a snapshot plus its directory entry here, the log
    // there — which is tens of microseconds on an NVMe host and milliseconds on
    // the virtio disk a CVM gets. On a runtime worker that would park every
    // other future assigned to it for the duration, which is the one thing a
    // proxy's event loop cannot afford. It does not make the store lock any
    // shorter: a reader still waits on the writer. It stops one slow disk from
    // being a slow gateway.
    let persist_interval = proxy.config.sync.persist_interval;
    if !persist_interval.is_zero() {
        let kv_store_for_persist = kv_store.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(persist_interval);
            loop {
                ticker.tick().await;
                let kv = kv_store_for_persist.clone();
                match tokio::task::spawn_blocking(move || kv.persist_if_dirty()).await {
                    Ok(Ok(true)) => info!("WaveKV: periodic persist completed"),
                    Ok(Ok(false)) => {} // No changes to persist
                    Ok(Err(err)) => {
                        crate::metrics::record_kv_persist_failure();
                        error!("WaveKV: periodic persist failed: {err:?}");
                    }
                    Err(err) => {
                        crate::metrics::record_kv_persist_failure();
                        error!("WaveKV: the persist task did not finish: {err}");
                    }
                }
            }
        });
        info!("WaveKV: periodic persistence enabled (interval: {persist_interval:?})");
    }

    // Force the write-ahead log on the window the operator configured. Nothing
    // else forces it on a schedule — a snapshot does, but that is minutes apart
    // — so without this the window would be a hope rather than a bound. Ticking
    // at the window itself is enough to make it one: the store measures from
    // its last fsync, so a write is forced at the first tick that finds the
    // window elapsed, never more than one window after it landed.
    let wal_sync_window = proxy.config.sync.wal_sync_window;
    if wal_sync_window.is_zero() {
        // Not silence: no window is the strictest setting, and an operator who
        // set zero expecting to turn the work off should find out here rather
        // than from a latency graph.
        info!("WaveKV: no WAL sync window, every write is forced before it returns");
    } else {
        let kv_store_for_wal = kv_store.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(wal_sync_window);
            loop {
                ticker.tick().await;
                let kv = kv_store_for_wal.clone();
                match tokio::task::spawn_blocking(move || kv.sync_wal_if_due()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => {
                        crate::metrics::record_kv_wal_sync_failure();
                        error!("WaveKV: forcing the write-ahead log failed: {err:?}");
                    }
                    Err(err) => {
                        crate::metrics::record_kv_wal_sync_failure();
                        error!("WaveKV: the write-ahead log sync did not finish: {err}");
                    }
                }
            }
        });
        info!("WaveKV: deferred WAL sync enabled (window: {wal_sync_window:?})");
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

/// Grace period protecting a freshly registered local instance from being
/// dropped by the "gone from KV" pass.
///
/// A registration writes to ProxyState and to the KV store under the same lock,
/// so the two cannot normally disagree — but if that write failed, the instance
/// would otherwise be evicted before the CVM's next registration refresh.
const LOCAL_REGISTRATION_GRACE: Duration = Duration::from_secs(60);

fn reload_instances_from_kv_store(proxy: &Proxy, store: &KvStore) -> Result<()> {
    // Before the read, so an override an older node left in an instance record
    // reaches its own key while that record is still the one carrying it.
    let moved = store.migrate_legacy_instance_overrides();
    if !moved.is_empty() {
        info!(
            "WaveKV: moved operator overrides for {} instance(s) out of the instance record: {}",
            moved.len(),
            moved.join(", ")
        );
    }
    let overrides = store.load_all_instance_overrides();
    report_unreadable_overrides(proxy, &overrides);
    let legacy_overrides = store.legacy_instance_overrides();
    let accepted = import::accept_instances(&proxy.config.wg, store.load_all_instances());
    // An unreadable record is not a deletion. Its instance keeps whatever the
    // data plane already holds, so it must be exempt from the removal pass
    // below; a record that lost an IP or key conflict is not exempt, because
    // the winner owns that IP or key and the loser has to stop being routable.
    let unreadable: HashSet<String> = accepted
        .unreadable()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let instances = accepted.instances;
    let mut state = proxy.lock();
    report_new_rejections(&mut state.reported_rejections, &accepted.rejected);
    let mut wg_changed = false;

    // Instances deleted (or recycled) on another node must stop being routable
    // here too, rather than lingering until this node's own recycle timeout.
    let removed: Vec<String> = state
        .state
        .instances
        .iter()
        .filter(|(id, info)| {
            !instances.contains_key(*id)
                && !unreadable.contains(id.as_str())
                && info.reg_time.elapsed().unwrap_or_default() > LOCAL_REGISTRATION_GRACE
        })
        .map(|(id, _)| id.clone())
        .collect();
    for instance_id in removed {
        info!("WaveKV: instance {instance_id} was deleted remotely, dropping it");
        state.forget_instance(&instance_id);
        // The node that deleted it could only withdraw its own `conn/` and
        // `handshake/` keys. Ours are ours to withdraw.
        if let Err(err) = store.sync_forget_local_observations(&instance_id) {
            warn!("failed to withdraw this node's observations of {instance_id}: {err:?}");
        }
        wg_changed = true;
    }

    for (instance_id, data) in instances {
        let admin = effective_overrides(&instance_id, &overrides, &legacy_overrides);
        let mut new_info = InstanceInfo {
            id: instance_id.clone(),
            app_id: data.app_id.clone(),
            ip: data.ip,
            public_key: data.public_key.clone(),
            reg_time: UNIX_EPOCH
                .checked_add(Duration::from_secs(data.reg_time))
                .unwrap_or(UNIX_EPOCH),
            port_policy: data.port_policy.clone(),
            port_policy_hash: data.port_policy_hash.clone(),
            admin_port_policy: admin.port_policy,
            ready: admin.ready,
            connections: Default::default(),
        };

        let existing = state.state.instances.get(&instance_id).cloned();
        if let Some(existing) = &existing {
            // Check if wg config needs update
            if existing.public_key != data.public_key || existing.ip != data.ip {
                wg_changed = true;
            }
            // WaveKV has already selected the winning value. Materialize it
            // unconditionally instead of applying another LWW rule here.
            new_info.connections = existing.connections.clone();
        } else {
            wg_changed = true;
        }

        // Release old IP if it changed (prevent IP leak)
        if let Some(existing) = &existing {
            if existing.ip != data.ip {
                state.state.allocated_addresses.remove(&existing.ip);
            }
            if existing.app_id != data.app_id {
                if let Some(app_instances) = state.state.apps.get_mut(&existing.app_id) {
                    app_instances.remove(&instance_id);
                    if app_instances.is_empty() {
                        state.state.apps.remove(&existing.app_id);
                        state.state.top_n.remove(&existing.app_id);
                    }
                }
            }
        }
        // Drop any cached selection this record could invalidate. WaveKV is how
        // an operator's traffic gate reaches the other nodes, and a cached
        // `top_n` computed before it arrived would keep feeding the gated
        // instance for up to `cache_top_n` -- on every node except the one that
        // took the RPC.
        let selection_is_stale = match &existing {
            Some(existing) => existing.routing_inputs_differ(&new_info),
            // A record this node has not seen before is a new candidate.
            None => true,
        };
        if selection_is_stale {
            state.state.top_n.remove(&data.app_id);
            if let Some(existing) = &existing {
                state.state.top_n.remove(&existing.app_id);
            }
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

/// WireGuard peers keyed by public key, valued by (last handshake, elapsed).
pub(crate) type Handshakes = BTreeMap<String, (u64, Duration)>;

impl ProxyState {
    fn valid_ip(&self, ip: Ipv4Addr) -> bool {
        self.config.wg.is_valid_client_ip(ip)
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
        compose_hash: &str,
        port_policy: Option<PortPolicy>,
    ) -> Result<InstanceInfo> {
        if id.is_empty() {
            bail!("instance_id is empty (no_instance_id is set?)");
        }
        if app_id.is_empty() {
            bail!("app_id is empty");
        }
        // Checked here as well as on the KV import path: a key `wg` refuses
        // makes it reject the whole config file, so it must never enter the
        // instance table in the first place.
        import::validate_wg_public_key(public_key).context("invalid WireGuard public key")?;
        if self
            .state
            .instances
            .values()
            .any(|instance| instance.id != id && instance.public_key == public_key)
        {
            bail!("WireGuard public key is already registered to another instance");
        }
        // The rebuild path below reconstructs the instance from scratch -- it
        // does that when the recorded IP is no longer inside the configured
        // range -- and everything the registration does not re-state has to
        // survive that. The operator overrides in particular live nowhere else:
        // lose them and the traffic gate falls open while the port-policy
        // override silently reverts to whatever the instance says about itself.
        let mut previous: Option<InstanceInfo> = None;
        if let Some(existing) = self.state.instances.get_mut(id) {
            if existing.app_id != app_id {
                bail!("instance_id is already registered to a different app");
            }
            let pubkey_changed = existing.public_key != public_key;
            if pubkey_changed {
                info!("public key changed for instance {id}, new key: {public_key}");
                existing.public_key = public_key.to_string();
                // Update reg_time so other nodes will pick up the change
                existing.reg_time = SystemTime::now();
            }
            // App upgrade detection: a different attested compose_hash invalidates
            // any cached port_policy from the previous code.
            if existing.port_policy_hash != compose_hash {
                info!(
                    "compose_hash changed for instance {id} ({} -> {compose_hash}), \
                     invalidating cached port_policy",
                    existing.port_policy_hash
                );
                existing.port_policy = None;
                existing.port_policy_hash = compose_hash.to_string();
            }
            // Only override cached port_policy when the caller actually reports
            // one. A `None` request (legacy CVM) means "I don't know" — let
            // the lazy fetch path run again.
            if port_policy.is_some() {
                existing.port_policy = port_policy.clone();
            }
            let existing = existing.clone();
            if self.valid_ip(existing.ip) {
                // Sync existing instance to KvStore (might be from legacy state)
                let data = InstanceData::from(&existing);
                if let Err(err) = self.kv_store.sync_instance(&existing.id, &data) {
                    error!("failed to sync existing instance to KvStore: {err:?}");
                }
                return Ok(existing);
            }
            info!("ip {} is invalid, removing", existing.ip);
            self.state.allocated_addresses.remove(&existing.ip);
            previous = Some(existing);
        }
        let ip = self
            .alloc_ip()
            .context("IP pool exhausted, no available addresses in client_ip_range")?;
        let host_info = match previous {
            // Rebuilding a record that already existed. Start from it and
            // overwrite only what this registration actually re-states, so a
            // field added later is carried by default rather than by someone
            // remembering to add a line here.
            Some(existing) => InstanceInfo {
                ip,
                public_key: public_key.to_string(),
                reg_time: SystemTime::now(),
                port_policy,
                port_policy_hash: compose_hash.to_string(),
                connections: Default::default(),
                ..existing
            },
            // First registration: no operator has had the chance to set
            // anything, so every field is stated here and the compiler says so.
            None => InstanceInfo {
                id: id.to_string(),
                app_id: app_id.to_string(),
                ip,
                public_key: public_key.to_string(),
                reg_time: SystemTime::now(),
                port_policy,
                port_policy_hash: compose_hash.to_string(),
                admin_port_policy: None,
                ready: None,
                connections: Default::default(),
            },
        };
        self.add_instance(host_info.clone());
        Ok(host_info)
    }

    /// Lookup an instance's IP. Returns `None` if the instance is unknown.
    pub(crate) fn instance_ip(&self, instance_id: &str) -> Option<Ipv4Addr> {
        self.state.instances.get(instance_id).map(|i| i.ip)
    }

    /// Lookup the effective port_policy for an instance: admin override wins,
    /// otherwise fall back to the instance-reported policy. `None` means
    /// neither is set — caller fails closed and may schedule a lazy fetch.
    pub(crate) fn instance_port_policy(&self, instance_id: &str) -> Option<&PortPolicy> {
        let info = self.state.instances.get(instance_id)?;
        info.admin_port_policy
            .as_ref()
            .or(info.port_policy.as_ref())
    }

    /// Update an instance's port_policy (used after a lazy fetch via Info()).
    /// Persists to the WaveKV store so other gateway nodes pick it up.
    pub(crate) fn update_instance_port_policy(&mut self, instance_id: &str, policy: PortPolicy) {
        let Some(info) = self.state.instances.get_mut(instance_id) else {
            return;
        };
        info.port_policy = Some(policy);
        // Pre-existing behaviour: the lazy fetch retries on its own schedule,
        // so a failed write here is logged rather than surfaced.
        if let Err(err) = self.persist_instance_record(instance_id) {
            error!("{err:?}");
        }
    }

    /// Snapshot view of an instance's port-policy state for inspection.
    pub(crate) fn instance_port_policy_view(&self, instance_id: &str) -> Option<PortPolicyView> {
        let info = self.state.instances.get(instance_id)?;
        Some(PortPolicyView {
            instance_reported: info.port_policy.clone(),
            admin_override: info.admin_port_policy.clone(),
        })
    }

    /// Set an admin override. Errors if the instance is not registered.
    pub(crate) fn set_admin_port_policy(
        &mut self,
        instance_id: &str,
        policy: PortPolicy,
    ) -> Result<()> {
        let Some(info) = self.state.instances.get_mut(instance_id) else {
            bail!("instance {instance_id} not found");
        };
        let prev = info.admin_port_policy.take();
        info.admin_port_policy = Some(policy.clone());
        info!(
            "admin set port_policy for instance {instance_id}: \
             restrict_mode={}, ports={} (prev: {})",
            policy.restrict_mode,
            policy.ports.len(),
            prev.is_some(),
        );
        // Pre-existing behaviour: a failed write is logged, not returned.
        // Left alone here so this change stays about where the record lives.
        if let Err(err) = self.persist_instance_port_policy_override(instance_id) {
            error!("{err:?}");
        }
        Ok(())
    }

    /// Clear any admin override. Errors if the instance is not registered.
    /// No-op (still Ok) if no override was set.
    pub(crate) fn clear_admin_port_policy(&mut self, instance_id: &str) -> Result<()> {
        let Some(info) = self.state.instances.get_mut(instance_id) else {
            bail!("instance {instance_id} not found");
        };
        let had_override = info.admin_port_policy.take().is_some();
        info!("admin cleared port_policy for instance {instance_id} (was set: {had_override})");
        if had_override {
            // Written, not deleted. An absent key means "no operator has
            // decided anything here", which lets the legacy fallback apply --
            // so deleting it would let a copy an older node left in the
            // instance record put the override straight back.
            if let Err(err) = self.persist_instance_port_policy_override(instance_id) {
                error!("{err:?}");
            }
        }
        Ok(())
    }

    /// Open or close the operator traffic gate for an instance.
    ///
    /// Closing it removes the instance from app-id load balancing but leaves it
    /// running and still reachable by instance id, which is the point: an
    /// operator investigating a misbehaving instance needs it out of rotation
    /// and reachable at the same time.
    ///
    /// Existing connections are deliberately left alone. They are already
    /// bridged, and tearing them down would turn "stop sending it new work"
    /// into a second, louder outage.
    ///
    /// Errors if the instance is not registered.
    pub(crate) fn set_ready(&mut self, instance_id: &str, ready: bool) -> Result<()> {
        let Some(info) = self.state.instances.get_mut(instance_id) else {
            bail!("instance {instance_id} not found");
        };
        let prev = info.is_ready();
        info.ready = Some(ready);
        let app_id = info.app_id.clone();
        info!("admin set ready={ready} for instance {instance_id} (prev: {prev})");
        match self.drain_warning(instance_id, &app_id, prev, ready) {
            Ok(Some(message)) => warn!("{message}"),
            Ok(None) => {}
            // The check needs a handshake read, which can fail on its own. That
            // is not a reason to fail the gate -- it is already applied -- but
            // it is a reason not to imply the app is still serving.
            Err(err) => debug!(
                "could not tell whether app {app_id} still has an eligible instance \
                 after gating {instance_id}: {err:?}"
            ),
        }
        // The selection cache holds a pre-gate snapshot. Drop it so the change
        // applies to the next connection rather than up to `cache_top_n` later.
        self.state.top_n.remove(&app_id);
        // Not rolled back, but do not read that as "it took effect". The gate
        // is in memory and nowhere else: it is gone on restart, and any reload
        // that rebuilds instances from the store reads back the very record
        // this write failed to update. How long it survives depends on when
        // that next happens, which is not something to predict in an error
        // message -- so the message says what is known instead. Rolling back
        // here would reach the same end state sooner while throwing away the
        // window in which the operator's intent is at least locally in force.
        self.persist_instance_gate(instance_id).with_context(|| {
            format!(
                "instance {instance_id} is set to ready={ready} in memory on \
                 this node only: the write to the store failed, so the setting \
                 is not durable and has not been shared. Retry before relying \
                 on it"
            )
        })?;
        Ok(())
    }

    /// Whether the WireGuard tunnel to `instance` is fresh enough to route over.
    fn handshake_is_fresh(&self, instance: &InstanceInfo, handshakes: &Handshakes) -> bool {
        handshakes
            .get(&instance.public_key)
            .is_some_and(|(_, elapsed)| *elapsed < self.config.proxy.timeouts.handshake_stale)
    }

    /// Whether `instance` may receive a connection addressed to its app id.
    ///
    /// The one definition both selection paths and the drain warning ask.
    /// They had already drifted apart: the warning looked only at the gate,
    /// so an instance nobody gated but whose tunnel was dead counted as cover.
    fn is_eligible(&self, instance: &InstanceInfo, handshakes: &Handshakes) -> bool {
        instance.is_ready() && self.handshake_is_fresh(instance, handshakes)
    }

    /// The warning an operator should see after a gate change, if any.
    ///
    /// Returned rather than logged so both conditions are testable, because
    /// both were wrong. It counted only the gate, so draining the last live
    /// instance of an app whose others were dead-but-ungated said nothing --
    /// the case the warning exists for. And it keyed on the resulting count
    /// alone, so a second gate-off against an already-drained app warned
    /// again, naming an instance that was never the last ready one; the retry
    /// the failed-write message asks for is exactly that call.
    fn drain_warning(
        &self,
        instance_id: &str,
        app_id: &str,
        prev: bool,
        ready: bool,
    ) -> Result<Option<String>> {
        // Nothing was closed, so nothing can have been closed last.
        if !prev || ready {
            return Ok(None);
        }
        if self.count_eligible_instances(app_id)? > 0 {
            return Ok(None);
        }
        // Not an error -- an operator may well mean to drain an app entirely --
        // but silently refusing every connection to an app is the kind of thing
        // someone should be told about once.
        Ok(Some(format!(
            "gating instance {instance_id} leaves app {app_id} with no instance eligible \
             for load balancing; connections addressed to the app id will be refused \
             until one becomes eligible again"
        )))
    }

    /// Why an app-id selection came back empty.
    ///
    /// The proxy learns "no candidates" as an absence, and the layer that sees
    /// the absence first is the port-policy filter -- which has not looked at a
    /// port yet and cannot say why. Selection is where the reason exists, so
    /// the reason is reconstructed here rather than guessed at downstream.
    pub(crate) fn describe_empty_selection(&self, app_id: &str) -> String {
        let Some(instance_ids) = self.state.apps.get(app_id) else {
            return format!("app {app_id} has no registered instances");
        };
        let total = instance_ids.len();
        // The random-selection fallback swallows this error, so it is a real
        // way to arrive here with instances that are perfectly healthy.
        let handshakes = match self.latest_handshakes(None) {
            Ok(handshakes) => handshakes,
            Err(err) => {
                return format!(
                    "could not read WireGuard handshakes, so none of app {app_id}'s \
                     {total} instance(s) could be checked for liveness: {err:#}"
                )
            }
        };
        let mut gated = 0;
        let mut stale = 0;
        for instance in instance_ids
            .iter()
            .filter_map(|id| self.state.instances.get(id))
        {
            if !instance.is_ready() {
                gated += 1;
            } else if !self.handshake_is_fresh(instance, &handshakes) {
                stale += 1;
            }
        }
        format!(
            "no instance of app {app_id} is currently routable: {total} registered, \
             {gated} gated out by an operator, {stale} with no recent WireGuard handshake"
        )
    }

    /// How many of an app's instances can currently be given new traffic.
    fn count_eligible_instances(&self, app_id: &str) -> Result<usize> {
        let Some(instances) = self.state.apps.get(app_id) else {
            return Ok(0);
        };
        let handshakes = self
            .latest_handshakes(None)
            .context("failed to read WireGuard handshakes")?;
        Ok(instances
            .iter()
            .filter_map(|id| self.state.instances.get(id))
            .filter(|info| self.is_eligible(info, &handshakes))
            .count())
    }

    /// Persist the operator's traffic gate for `instance_id` to WaveKV.
    ///
    /// Separate from [`Self::persist_instance_record`], and from the port-policy
    /// override beside it, because each is a separate key -- which is the point.
    /// This one is written only from `Admin.SetInstanceReady`, so neither a
    /// re-registration nor a peer's unsynced change to the other override can
    /// overwrite it.
    ///
    /// Returns the store error rather than only logging it, so callers whose
    /// API promises the change is durable can say otherwise when it is not.
    fn persist_instance_gate(&self, instance_id: &str) -> Result<()> {
        let Some(info) = self.state.instances.get(instance_id) else {
            return Ok(());
        };
        let Some(ready) = info.ready else {
            return Ok(());
        };
        self.kv_store
            .sync_instance_gate(instance_id, &InstanceGate { ready })
            .with_context(|| {
                format!("failed to sync the gate for instance {instance_id} to KvStore")
            })
    }

    /// Persist the operator's port-policy override for `instance_id` to WaveKV.
    fn persist_instance_port_policy_override(&self, instance_id: &str) -> Result<()> {
        let Some(info) = self.state.instances.get(instance_id) else {
            return Ok(());
        };
        let data = AdminPortPolicy {
            policy: info.admin_port_policy.clone(),
        };
        self.kv_store
            .sync_instance_port_policy_override(instance_id, &data)
            .with_context(|| {
                format!(
                    "failed to sync the port-policy override for instance {instance_id} to KvStore"
                )
            })
    }

    /// Persist the current in-memory `InstanceInfo` snapshot to WaveKV.
    ///
    /// Returns the store error rather than only logging it, so callers whose
    /// API promises the change is durable can say otherwise when it is not.
    fn persist_instance_record(&self, instance_id: &str) -> Result<()> {
        let Some(info) = self.state.instances.get(instance_id) else {
            return Ok(());
        };
        let data = InstanceData::from(info);
        self.kv_store
            .sync_instance(instance_id, &data)
            .with_context(|| format!("failed to sync instance {instance_id} to KvStore"))
    }

    fn add_instance(&mut self, info: InstanceInfo) {
        self.state.top_n.remove(&info.app_id);
        // Sync to KvStore
        let data = InstanceData::from(&info);
        if let Err(err) = self.kv_store.sync_instance(&info.id, &data) {
            error!("failed to sync instance to KvStore: {err:?}");
        }

        self.state
            .apps
            .entry(info.app_id.clone())
            .or_default()
            .insert(info.id.clone());
        self.state.instances.insert(info.id.clone(), info);
    }

    fn generate_wg_config(&self) -> Result<String> {
        // Last check before the values leave Rust: `wg syncconf` refuses the
        // entire file when one peer is malformed, so a record that somehow got
        // past the import boundary must cost only its own routing.
        let mut peers = Vec::with_capacity(self.state.instances.len());
        for info in self.state.instances.values() {
            if let Err(err) = import::validate_wg_public_key(&info.public_key) {
                error!("excluding instance {} from wg config: {err:#}", info.id);
                continue;
            }
            if info.public_key == self.config.wg.public_key {
                error!(
                    "excluding instance {} from wg config: public key belongs to this gateway",
                    info.id
                );
                continue;
            }
            if !self.config.wg.is_routable_client_ip(info.ip) {
                error!(
                    "excluding instance {} from wg config: ip {} is outside the wg network",
                    info.id, info.ip
                );
                continue;
            }
            peers.push(WgPeer {
                public_key: &info.public_key,
                ip: info.ip,
            });
        }
        let model = WgConf {
            private_key: &self.config.wg.private_key,
            listen_port: self.config.wg.listen_port,
            peers,
        };
        Ok(model.render()?)
    }

    pub(crate) fn reconfigure(&mut self) -> Result<()> {
        // Every way out of here that is not a clean apply leaves the data plane
        // on the routing table it already had, so they all feed one counter --
        // the early returns included. A config that cannot be rendered or
        // written never reaches `wg` at all, and both call sites of this
        // function only log the `Err`, so a full disk would otherwise look
        // exactly like having nothing to apply.
        let result = self.reconfigure_inner();
        if result.is_err() {
            crate::metrics::record_wg_reconfigure(false);
        }
        result
    }

    fn reconfigure_inner(&mut self) -> Result<()> {
        let wg_config = self.generate_wg_config()?;
        // the rendered config carries the interface's WireGuard private key.
        safe_write_with_mode(&self.config.wg.config_path, wg_config, 0o600)
            .context("failed to write wg config")?;
        // wg setconf <interface_name> <config_path>
        let ifname = &self.config.wg.interface;
        let config_path = &self.config.wg.config_path;

        match cmd!(wg syncconf $ifname $config_path) {
            Ok(_) => {
                crate::metrics::record_wg_reconfigure(true);
                info!("wg config updated");
            }
            Err(err) => {
                // `wg syncconf` rejects the whole file when one peer stanza is
                // bad, and this stays `Ok` for the caller as it always has, so
                // the counter is the only signal that routing updates stopped
                // reaching the data plane.
                crate::metrics::record_wg_reconfigure(false);
                error!("failed to set wg config: {err:?}");
            }
        }
        Ok(())
    }

    pub(crate) fn select_top_n_hosts(&mut self, id: &str) -> Result<AddressGroup> {
        if self.config.debug.insecure_localhost_backend && id == "localhost" {
            return Ok(smallvec![AddressInfo {
                ip: Ipv4Addr::new(127, 0, 0, 1),
                counter: Default::default(),
                instance_id: "localhost".to_string(),
            }]);
        }
        let n = self.config.proxy.connect_top_n;
        if let Some(instance) = self.state.instances.get(id) {
            return Ok(smallvec![AddressInfo {
                ip: instance.ip,
                counter: instance.connections.clone(),
                instance_id: instance.id.clone(),
            }]);
        };
        let app_instances = self.state.apps.get(id).context("app not found")?;
        if n == 0 {
            // fallback to random selection
            return Ok(self.random_select_a_host(id).unwrap_or_default());
        }
        if let Some((top_n, insert_time)) = self.state.top_n.get(id) {
            if !top_n.is_empty() && insert_time.elapsed() < self.config.proxy.timeouts.cache_top_n {
                return Ok(top_n.clone());
            }
        }

        let handshakes = self.latest_handshakes(None);
        let mut instances = match handshakes {
            Err(err) => {
                warn!("Failed to get handshakes, fallback to random selection: {err:?}");
                return Ok(self.random_select_a_host(id).unwrap_or_default());
            }
            Ok(handshakes) => app_instances
                .iter()
                .filter_map(|instance_id| {
                    let instance = self.state.instances.get(instance_id)?;
                    // Eligibility -- including the operator gate -- is only
                    // applied here, on the app-id path: the instance-id lookup
                    // above returns before this point, so a gated instance
                    // stays directly reachable.
                    if !self.is_eligible(instance, &handshakes) {
                        return None;
                    }
                    // Re-read for the sort key. `is_eligible` already proved
                    // it is present and fresh.
                    let (_, elapsed) = handshakes.get(&instance.public_key)?;
                    Some((
                        instance.ip,
                        *elapsed,
                        instance.connections.clone(),
                        instance.id.clone(),
                    ))
                })
                .collect::<SmallVec<[_; 4]>>(),
        };
        instances.sort_by(|a, b| a.1.cmp(&b.1));
        instances.truncate(n);
        let selected: AddressGroup = instances
            .into_iter()
            .map(|(ip, _, counter, instance_id)| AddressInfo {
                ip,
                counter,
                instance_id,
            })
            .collect();
        self.state
            .top_n
            .insert(id.to_string(), (selected.clone(), Instant::now()));
        Ok(selected)
    }

    fn random_select_a_host(&self, id: &str) -> Option<AddressGroup> {
        // Direct instance lookup first
        if let Some(info) = self.state.instances.get(id).cloned() {
            return Some(smallvec![AddressInfo {
                ip: info.ip,
                counter: info.connections.clone(),
                instance_id: info.id.clone(),
            }]);
        }

        let app_instances = self.state.apps.get(id)?;

        // Get latest handshakes to check instance health
        let handshakes = self.latest_handshakes(None).ok()?;

        // Filter eligible instances and choose randomly among them
        let healthy_instances = app_instances.iter().filter(|instance_id| {
            self.state
                .instances
                .get(*instance_id)
                .is_some_and(|instance| self.is_eligible(instance, &handshakes))
        });

        let selected = healthy_instances.choose(&mut rand::thread_rng())?;
        self.state.instances.get(selected).map(|info| {
            smallvec![AddressInfo {
                ip: info.ip,
                counter: info.connections.clone(),
                instance_id: info.id.clone(),
            }]
        })
    }

    /// Get latest handshakes
    ///
    /// Return a map of public key to (timestamp, elapsed)
    pub(crate) fn latest_handshakes(&self, stale_timeout: Option<Duration>) -> Result<Handshakes> {
        self.handshake_cache.latest(stale_timeout)
    }

    /// Drop an instance from the local state only.
    ///
    /// Used when the KV store already says the instance is gone; the syncing
    /// counterpart is [`Self::remove_instance`].
    fn forget_instance(&mut self, id: &str) -> Option<InstanceInfo> {
        let info = self.state.instances.remove(id)?;
        self.state.allocated_addresses.remove(&info.ip);
        self.state.top_n.remove(&info.app_id);
        if let Some(app_instances) = self.state.apps.get_mut(&info.app_id) {
            app_instances.remove(id);
            if app_instances.is_empty() {
                self.state.apps.remove(&info.app_id);
            }
        }
        Some(info)
    }

    fn remove_instance(&mut self, id: &str) -> Result<()> {
        self.forget_instance(id).context("instance not found")?;

        // Sync deletion to KvStore
        if let Err(err) = self.kv_store.sync_delete_instance(id) {
            error!("Failed to sync instance deletion to KvStore: {err:?}");
        }
        Ok(())
    }

    fn recycle(&mut self) -> Result<()> {
        // Refresh state: sync local handshakes to KvStore, update local last_seen from global
        if let Err(err) = self.refresh_state() {
            warn!("failed to refresh state: {err:?}");
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

    pub(crate) fn set_admin_shutdown(&mut self, shutdown: rocket::Shutdown) {
        self.admin_shutdown = Some(shutdown);
    }

    pub(crate) fn exit(&self, force: bool) -> Result<()> {
        if force {
            std::process::exit(0);
        }

        let shutdown = self
            .admin_shutdown
            .as_ref()
            .context("admin server shutdown handle is not initialized")?;
        shutdown.notify();
        Ok(())
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
                    debug!("failed to sync instance handshake: {err:?}");
                }
            }
        }

        // Update this node's last_seen in KvStore
        let now = now_secs();
        if let Err(err) = self
            .kv_store
            .sync_node_last_seen(self.config.sync.node_id, now)
        {
            debug!("failed to sync node last_seen: {err:?}");
        }
        Ok(())
    }

    /// Sync connection count for an instance to KvStore
    pub(crate) fn sync_connections(&self, instance_id: &str, count: u64) {
        if let Err(err) = self.kv_store.sync_connections(instance_id, count) {
            debug!("Failed to sync connections: {err:?}");
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
            // Shared with the metrics sampler so the gauge and the routing
            // table cannot disagree about what "active" means.
            .filter(|(id, _)| !exclude_down || KvStore::node_is_active(node_statuses.get(id)))
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

pub struct RpcHandler {
    remote_app_id: Option<Vec<u8>>,
    remote_app_info: Option<AppInfo>,
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
        let app_info = match self.remote_app_info {
            Some(app_info) => app_info,
            None => {
                let Some(ra) = &self.attestation else {
                    bail!("neither app-info nor attestation provided");
                };
                ra.decode_app_info(false)
                    .context("failed to decode app-info from attestation")?
            }
        };
        self.state
            .auth_client
            .ensure_app_authorized(&app_info)
            .await
            .context("App authorization failed")?;
        let app_id = hex::encode(&app_info.app_id);
        let instance_id = hex::encode(&app_info.instance_id);
        let compose_hash = hex::encode(&app_info.compose_hash);
        let port_policy = request
            .port_policy
            .map(|policy| -> Result<PortPolicy> {
                let ports = policy
                    .ports
                    .into_iter()
                    .map(|attr| {
                        let port = u16::try_from(attr.port)
                            .with_context(|| format!("port {} out of u16 range", attr.port))?;
                        if port == 0 {
                            bail!("port must be between 1 and 65535");
                        }
                        Ok((port, crate::kv::PortFlags { pp: attr.pp }))
                    })
                    .collect::<Result<_>>()?;
                Ok(PortPolicy {
                    ports,
                    restrict_mode: policy.restrict_mode,
                })
            })
            .transpose()?;
        self.state.do_register_cvm(
            &app_id,
            &instance_id,
            &request.client_public_key,
            &compose_hash,
            port_policy,
        )
    }

    async fn acme_info(self) -> Result<AcmeInfoResponse> {
        self.state.acme_info(None)
    }

    async fn info(self) -> Result<InfoResponse> {
        let state = self.state.lock();
        let (base_domain, port) = state.kv_store.get_best_zt_domain().unwrap_or_default();
        Ok(InfoResponse {
            base_domain,
            external_port: port.into(),
            app_address_ns_prefix: state.config.proxy.app_address_ns_prefix.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
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
            remote_app_info: context.remote_app_info,
            attestation: context.attestation,
            state: context.state.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
