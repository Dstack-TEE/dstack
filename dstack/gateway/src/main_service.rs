// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::Ipv4Addr,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
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
        fetch_peers_from_bootnode, import, AppIdValidator, CertData, HttpsClientConfig,
        InstanceRecord, KvStore, LegacyOverrides, LoadedInstances, NodeData, NodeStatus,
        PortPolicy, PortPolicyOverride, ReplicatedWrites, WaveKvSyncService,
    },
    models::{InstanceInfo, PortPolicyView, ReportedCapabilities, WgConf, WgPeer},
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
    my_app_id: Vec<u8>,
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

/// The routing tables, rebuilt from WaveKV on every reload.
///
/// Held only in memory. It carried `Serialize`/`Deserialize` from the days
/// before WaveKV, when it was written to a state file; nothing has serialized
/// it since, and the derives kept every `#[serde]` attribute on the types it
/// reaches looking load-bearing when none of them were.
#[derive(Debug, Default)]
pub(crate) struct ProxyStateMut {
    pub(crate) apps: BTreeMap<String, BTreeSet<String>>,
    pub(crate) instances: BTreeMap<String, InstanceInfo>,
    pub(crate) allocated_addresses: BTreeSet<Ipv4Addr>,
    pub(crate) top_n: BTreeMap<String, (AddressGroup, Instant)>,
    /// When each app was last warned that its whole fleet reads unhealthy.
    ///
    /// Dropped wherever an app is, so the bound is the number of apps that
    /// exist rather than the number this process has ever seen. See
    /// [`warn_all_unhealthy`].
    pub(crate) all_unhealthy_warned: BTreeMap<String, Instant>,
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
    /// This gateway's own app id, from the guest agent.
    ///
    /// Not optional: it is the only thing `authorize_peer` and `AppIdValidator`
    /// compare a peer against, so a gateway that does not know it cannot decide
    /// who belongs in the cluster. `main` fails to start rather than construct one.
    pub my_app_id: Vec<u8>,
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
    /// exposing arbitrary raw-KV deletion. Re-issuing it after a partial
    /// failure also sweeps up any override or telemetry record left behind.
    ///
    /// An error from the delete means the tombstone itself was not written, so
    /// the CVM is still registered cluster-wide. The local cleanup below is
    /// then deliberately skipped: the record is still live in the store, and
    /// the next reload would re-import the instance anyway. Anything the store
    /// dropped short of that -- an `admin/` override left for a future holder
    /// of the id to inherit, or a leaked telemetry key -- is logged and does
    /// not fail the removal, because the CVM is gone either way and failing
    /// would abort the routing cleanup an operator reached for this call to
    /// get.
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
        // Capture membership before the first write. Every replicated write
        // this function makes wakes a watcher whose prune races it -- the
        // removal marker wakes the marker watcher just as surely as the
        // __peer_addr tombstone wakes the address watcher -- so the answer
        // must come from a read taken while no such signal exists yet, or the
        // reported membership depends on scheduling. A guard test drives both
        // watchers at full speed against this.
        let removed_from_peer_set = self.kv_store.peer_ids().contains(&node_id);
        // The durable half first: the live marker is what keeps the removed
        // node out after the __peer_addr tombstone below has been collected.
        self.kv_store
            .mark_peer_removed(node_id)
            .with_context(|| format!("failed to write the removal marker for node {node_id}"))?;
        // Drop the peer here rather than leaving it to the watchers, so the
        // removal is complete when this call returns. Idempotent when a
        // watcher's prune wins the race, which is why the return value above
        // does not come from this call.
        self.kv_store.remove_peer(node_id)?;
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

    /// WireGuard handshake ages, without taking the routing lock.
    ///
    /// The cache is its own synchronization, so a caller that only needs
    /// handshakes has no reason to hold `ProxyState` while this builds its map
    /// -- which clones every peer's public key, and on a cold cache shells out
    /// to `wg show` synchronously.
    pub(crate) fn latest_handshakes(
        &self,
        stale_timeout: Option<Duration>,
    ) -> Result<BTreeMap<String, (u64, Duration)>> {
        self.handshake_cache.latest(stale_timeout)
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
        if kv_store.is_peer_removed(config.sync.node_id) {
            // Best-effort: a removed node usually never receives its own
            // marker -- the refusals the marker drives are what keep it from
            // replicating here -- so this only fires when the marker slipped
            // in before the lockout took effect. The reliable signal is the
            // sender side reading 403 off its own sync attempts. Only a
            // warning, because this copy may also be stale: re-admission
            // clears the marker on the peers, which is where the lockout is
            // enforced, and a node whose marker really is current gets every
            // envelope refused and can do no harm either way.
            warn!(
                "this node's own data directory says an operator removed it from the cluster; \
                 peers will refuse to sync until it is re-admitted via SetNodeUrl"
            );
        }
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
        let legacy_overrides = kv_store.legacy_instance_overrides();
        let state = build_state_from_kv_store(&config, &kv_store, instances, &legacy_overrides);

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
            let cert_validator = Arc::new(AppIdValidator::new(my_app_id.clone()));
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

    pub(crate) fn my_app_id(&self) -> &[u8] {
        &self.my_app_id
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
        crate::proxy::health_check::spawn_poller(self.clone());
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

    pub(crate) async fn rotate_acme_credentials(
        &self,
    ) -> Result<crate::distributed_certbot::RotationOutcome> {
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
        reported: ReportedCapabilities,
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
                reported,
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

/// The data plane's view of an instance: what the CVM reported in `data`, plus
/// what an operator decided about it under `admin/`.
///
/// One conversion for both the startup build and the reload. They had a
/// hand-written copy each, which is how `admin_port_policy` came to be dropped
/// once already -- the compiler says nothing when a field is missing from one
/// of two literals that are supposed to agree.
///
/// The overrides are read per key, because they are separate keys: one of them
/// existing says nothing about the other. Asking per instance is what would
/// drop the port-policy override of an instance whose gate had already been
/// moved across. A key that exists answers, including when it says "cleared";
/// only a key that does not exist falls back to the copy an older build left
/// in the instance record, or clearing an override would be undone by it.
///
/// Returns why the overrides could not be read, if they could not. That is not
/// "nothing is overridden": the gate is an operator saying an instance must not
/// be given work, so an unreadable answer keeps it out of app-id rotation until
/// the record is readable again. Instance-id routing is never gated, so the
/// instance stays reachable for investigation either way.
fn instance_info_from_record(
    store: &KvStore,
    instance_id: String,
    data: InstanceRecord,
    legacy: Option<&LegacyOverrides>,
    known_gated: bool,
) -> (InstanceInfo, Option<String>) {
    let mut unreadable = None;
    let (admin_port_policy, ready) = match read_overrides(store, &instance_id, legacy) {
        Ok(overrides) => overrides,
        Err(err) => {
            unreadable = Some(format!("{err:#}"));
            (None, Some(false))
        }
    };
    let info = InstanceInfo {
        id: instance_id,
        app_id: data.app_id,
        ip: data.ip,
        public_key: data.public_key,
        reg_time: decode_ts(data.reg_time),
        port_policy: data.port_policy,
        port_policy_hash: data.port_policy_hash,
        admin_port_policy,
        ready,
        // A record written before this field existed says nothing about the
        // app's intent, so it falls back to `known_gated` -- what this node
        // already believes -- rather than reading as "opted out". Reading
        // `false` there would reset health to `Ungated` and drop the app's
        // cached selection on a record that never claimed the app opted out.
        health: data.health_check.unwrap_or(known_gated).into(),
        connections: Default::default(),
    };
    (info, unreadable)
}

fn read_overrides(
    store: &KvStore,
    instance_id: &str,
    legacy: Option<&LegacyOverrides>,
) -> Result<(Option<PortPolicy>, Option<bool>)> {
    let ready = match store.instance_gate(instance_id)? {
        Some(ready) => Some(ready),
        None => legacy.and_then(|legacy| legacy.ready),
    };
    let port_policy = match store.instance_port_policy_override(instance_id)? {
        Some(PortPolicyOverride::Set(policy)) => Some(policy),
        Some(PortPolicyOverride::Cleared) => None,
        None => legacy.and_then(|legacy| legacy.admin_port_policy.clone()),
    };
    Ok((port_policy, ready))
}

/// Report override records this node cannot read, once per transition.
///
/// Unreadable means the instance is held out of app-id rotation, so it is not a
/// quiet condition -- but a record that stays bad would otherwise be reported on
/// every reload, and reloads are driven by cluster activity.
fn report_unreadable_overrides(
    reported: &mut BTreeMap<String, String>,
    unreadable: BTreeMap<String, String>,
) {
    for (instance_id, reason) in &unreadable {
        if reported.get(instance_id) != Some(reason) {
            error!(
                "cannot read the operator overrides for instance {instance_id}, holding it \
                 out of load balancing until they are readable again: {reason}"
            );
        }
    }
    for instance_id in reported.keys() {
        if !unreadable.contains_key(instance_id) {
            info!("operator overrides for instance {instance_id} are readable again");
        }
    }
    *reported = unreadable;
}

fn build_state_from_kv_store(
    config: &Config,
    store: &KvStore,
    instances: LoadedInstances,
    legacy_overrides: &BTreeMap<String, LegacyOverrides>,
) -> ProxyStateMut {
    let mut state = ProxyStateMut::default();

    let accepted = import::accept_instances(&config.wg, instances);
    report_rejected_instances(&accepted.rejected);

    // Build instances
    for (instance_id, data) in accepted.instances {
        let ip = data.ip;
        let app_id = data.app_id.clone();
        let legacy = legacy_overrides.get(&instance_id);
        // Health is this node's own observation and is deliberately not
        // persisted, so a restart starts every instance at `Unknown`. That does
        // not blackhole anything: `Unknown` is not healthy, so an app whose
        // instances are *all* unknown trips the fail-open in `retain_healthy`
        // and is routed to exactly as before, until the first round of polls
        // answers a few seconds later.
        //
        // Nothing is in memory yet to fall back on, unlike the reload path, so
        // a record predating the declaration reads as not gated: routable and
        // unpolled, and the CVM's next re-registration states it again.
        let (info, unreadable) =
            instance_info_from_record(store, instance_id.clone(), data, legacy, false);
        if let Some(reason) = unreadable {
            error!(
                "cannot read the operator overrides for instance {instance_id}, holding it \
                 out of load balancing until they are readable again: {reason}"
            );
        }
        state.allocated_addresses.insert(ip);
        state
            .apps
            .entry(app_id)
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

/// How often the tombstone GC task re-reads its trigger. An implementation
/// detail, not a policy knob: one read of two tiny records and two ack-map
/// sums. The pace of collection itself comes from `tombstone_gc_writes`.
///
/// Short enough that two nodes crossing the same write-count boundary do so
/// within one check period plus one sync round of each other -- well inside
/// the `digest_check_rounds` window the divergence detector needs before it
/// calls the gap a repair case. That window is `sync.interval` times
/// `digest_check_rounds` -- three minutes on the defaults -- so the margin is
/// an assumption about configuration, not a constant: an operator who
/// tightens the sync interval toward this period erodes it.
const TOMBSTONE_GC_CHECK_PERIOD: Duration = Duration::from_secs(15);

/// Whether a store has crossed a collection boundary since the last one.
///
/// The trigger is a pure function of the replicated write count and the shared
/// pace `N`: collect when `writes / N` has grown. Every node evaluates the
/// same function over state that converges within a sync round, so the cluster
/// crosses each boundary together **without any node reading a clock** -- the
/// wall-clock-aligned design this replaces was correct only while every host's
/// clock stayed stepped-together, an assumption this has no use for.
///
/// `last` is the count at this node's previous collection, `None` when it has
/// not collected since the task started (or since collection was re-enabled),
/// which is read as due: the backlog case, where a store that never writes
/// again would otherwise never cross a boundary and never shed the tombstones
/// it already holds.
///
/// In a cluster the backlog case has a cost: a restarted node collects alone,
/// and if anything was collectable the digest repair puts it back a few
/// rounds later, to be shed for good at the next shared boundary. That is one
/// bounded repair per restart, paid to keep the guarantee that a store nobody
/// ever writes to again still ends up empty.
fn tombstone_collection_due(last: Option<ReplicatedWrites>, now: ReplicatedWrites, n: u64) -> bool {
    let Some(last) = last else {
        return true;
    };
    now.persistent / n > last.persistent / n || now.ephemeral / n > last.ephemeral / n
}

/// Drop tombstones the cluster has finished with.
///
/// Beside the persist and WAL tasks because it belongs to the same set: work
/// the store needs on a schedule whether or not this node has peers. A
/// single-node gateway has nobody to resurrect from, so wavekv collects every
/// tombstone it holds -- and it is the deployment where nothing else ever
/// would.
///
/// The pace is read every period rather than once at startup because the
/// operator override lives in the KV itself and can change under a running
/// node. A corrupt override skips the round instead of falling back to the
/// config-file default: the default is per-node, and collecting on it while
/// peers honour the override is exactly the phase drift the shared pace
/// exists to prevent.
///
/// Collection runs on the blocking pool for the same reason persist and WAL
/// sync do: it takes the store's write lock and walks the whole data map, and
/// a proxy's event loop cannot afford a worker parked on that.
fn start_tombstone_gc_task(proxy: &Proxy) {
    let default_pace = proxy.config.sync.tombstone_gc_writes;
    let kv_store = proxy.kv_store.clone();
    tokio::spawn(async move {
        let mut last: Option<ReplicatedWrites> = None;
        let mut peers = kv_store.peer_ids();
        let mut override_unreadable = false;
        loop {
            tokio::time::sleep(TOMBSTONE_GC_CHECK_PERIOD).await;
            let pace = match kv_store.get_tombstone_gc_config() {
                Ok(stored) => {
                    if override_unreadable {
                        info!("WaveKV: the tombstone GC override is readable again");
                        override_unreadable = false;
                    }
                    stored.map_or(default_pace, |c| c.writes_per_collection)
                }
                Err(err) => {
                    // Corruption is deterministic until an operator overwrites
                    // the record, so report the pause once, not every period.
                    if !override_unreadable {
                        error!(
                            "WaveKV: the tombstone GC override is unreadable, \
                             collection is paused until it is overwritten: {err:?}"
                        );
                        override_unreadable = true;
                    }
                    continue;
                }
            };
            if pace == 0 {
                // Re-enabling starts from the backlog case, deliberately.
                last = None;
                continue;
            }
            // A removed peer takes its lifetime of writes out of the count for
            // good (`RemovePeer` drops `acks[removed]`). A baseline above the
            // shrunken count would gate collection on the cluster re-earning
            // writes it no longer remembers -- on a quiet store, indefinitely.
            // Removal replicates, so every node observes it within a sync
            // round of the others and their resets land clustered.
            let now_peers = kv_store.peer_ids();
            if !peers.is_subset(&now_peers) {
                last = None;
            }
            peers = now_peers;
            let now = kv_store.replicated_writes();
            if !tombstone_collection_due(last, now, pace) {
                continue;
            }
            let kv = kv_store.clone();
            match tokio::task::spawn_blocking(move || kv.collect_tombstone_garbage()).await {
                Ok(Ok(collected)) => {
                    // On failure `last` keeps its value and the next period
                    // retries; only success moves the boundary.
                    last = Some(now);
                    if collected.total() > 0 {
                        info!(
                            "WaveKV: collected {} tombstones ({} persistent, {} ephemeral)",
                            collected.total(),
                            collected.persistent,
                            collected.ephemeral
                        );
                    }
                }
                Ok(Err(err)) => error!("WaveKV: tombstone collection failed: {err:?}"),
                Err(err) => error!("WaveKV: the tombstone collection task did not finish: {err}"),
            }
        }
    });
    if default_pace == 0 {
        info!("WaveKV: tombstone collection disabled by default; a stored override can enable it");
    } else {
        info!(
            "WaveKV: tombstone collection enabled (default pace: every {default_pace} replicated writes)"
        );
    }
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

    // The removal marker prunes too. It usually replicates in the same round
    // as the address tombstone, but a node that was offline for the removal
    // can receive the marker alone -- the tombstone may already have been
    // collected everywhere else, and a live record is the one signal that
    // cannot be.
    let mut rx = kv_store.watch_peer_removed();
    let kv_for_removed = kv_store.clone();
    tokio::spawn(async move {
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            kv_for_removed.prune_removed_peers();
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

    start_tombstone_gc_task(&proxy);

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

    let mut unreadable_overrides = BTreeMap::new();
    for (instance_id, data) in instances {
        let legacy = legacy_overrides.get(&instance_id);
        // What this node already believes the app declared, for a record that
        // predates the field. See `instance_info_from_record`.
        let known_gated = state
            .state
            .instances
            .get(&instance_id)
            .is_some_and(|existing| existing.health_check());
        let (mut new_info, unreadable) =
            instance_info_from_record(store, instance_id.clone(), data, legacy, known_gated);
        if let Some(reason) = unreadable {
            unreadable_overrides.insert(instance_id.clone(), reason);
        }

        let existing = state.state.instances.get(&instance_id).cloned();
        if let Some(existing) = &existing {
            // Check if wg config needs update
            if existing.public_key != new_info.public_key || existing.ip != new_info.ip {
                wg_changed = true;
            }
            // WaveKV has already selected the winning value. Materialize it
            // unconditionally instead of applying another LWW rule here.
            new_info.connections = existing.connections.clone();
            // Health is this node's own observation and WaveKV does not carry
            // it, so it has to survive a reload the same way the connection
            // counter does. Re-deriving it from the record would reset every
            // instance to `Unknown` on every sync round -- dropping the whole
            // fleet out of rotation until the next poll, over and over. The
            // conditions under which it must *not* survive live with the field.
            new_info.inherit_health_from(existing);
        } else {
            wg_changed = true;
        }

        // Release old IP if it changed (prevent IP leak)
        if let Some(existing) = &existing {
            if existing.ip != new_info.ip {
                state.state.allocated_addresses.remove(&existing.ip);
            }
            if existing.app_id != new_info.app_id {
                if let Some(app_instances) = state.state.apps.get_mut(&existing.app_id) {
                    app_instances.remove(&instance_id);
                    if app_instances.is_empty() {
                        state.state.apps.remove(&existing.app_id);
                        state.state.top_n.remove(&existing.app_id);
                        state.state.all_unhealthy_warned.remove(&existing.app_id);
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
            state.state.top_n.remove(&new_info.app_id);
            if let Some(existing) = &existing {
                state.state.top_n.remove(&existing.app_id);
            }
        }
        state.state.allocated_addresses.insert(new_info.ip);
        state
            .state
            .apps
            .entry(new_info.app_id.clone())
            .or_default()
            .insert(instance_id.clone());
        state.state.instances.insert(instance_id, new_info);
    }

    report_unreadable_overrides(&mut state.reported_bad_overrides, unreadable_overrides);

    if wg_changed {
        state.reconfigure()?;
    }
    Ok(())
}

/// WireGuard peers keyed by public key, valued by (last handshake, elapsed).
pub(crate) type Handshakes = BTreeMap<String, (u64, Duration)>;

/// One instance still in the running for a connection.
struct Candidate {
    ip: Ipv4Addr,
    handshake_age: Duration,
    counter: Arc<std::sync::atomic::AtomicU64>,
    instance_id: String,
    healthy: bool,
}

/// Drop unhealthy candidates -- unless that would drop all of them.
///
/// Health is inference: a probe can be misconfigured, an agent can die, a whole
/// fleet can report badly at once for a reason that has nothing to do with
/// whether the app works. Blackholing an app on the strength of that is worse
/// than sending traffic to instances that might be fine. The operator gate in
/// `is_ready` deliberately does *not* get this treatment: that one is an
/// instruction, not a guess.
/// Generic over the candidate type because the two selection paths carry
/// different ones -- `select_top_n_hosts` has already resolved each instance to
/// a `Candidate`, while `random_select_a_host` is still holding instance ids.
/// They had a copy of this rule each, which is one more than the number of
/// places a change to the fail-open policy would get applied.
fn retain_healthy<T, A: smallvec::Array<Item = T>>(
    state: &mut ProxyStateMut,
    app_id: &str,
    candidates: &mut SmallVec<A>,
    is_healthy: impl Fn(&T) -> bool,
) {
    if candidates.iter().any(&is_healthy) {
        candidates.retain(|candidate| is_healthy(candidate));
    } else if !candidates.is_empty() {
        warn_all_unhealthy(state, app_id, candidates.len());
    }
}

/// How often one app may report that its whole fleet looks unhealthy.
const ALL_UNHEALTHY_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Warn that an app is being routed to on fail-open, at most once a minute.
///
/// Rate-limited here rather than relying on a caller's cache. The top-n path
/// recomputes at most every `cache_top_n`, but `random_select_a_host` has no
/// cache and runs per connection -- and a fleet that is entirely unhealthy is
/// exactly the sustained state, so an unlimited warning would be one log line
/// per inbound connection for as long as it lasts.
///
/// The state rides in `ProxyStateMut`, which the caller is already holding,
/// rather than in a `static`. A process-global mutex here would be a new
/// serialization point on the per-connection routing path, shared across every
/// tenant -- one app's fail-open would contend with an unrelated app's
/// connections.
fn warn_all_unhealthy(state: &mut ProxyStateMut, app_id: &str, candidates: usize) {
    if let Some(at) = state.all_unhealthy_warned.get(app_id) {
        if at.elapsed() < ALL_UNHEALTHY_WARN_INTERVAL {
            return;
        }
    }
    state
        .all_unhealthy_warned
        .insert(app_id.to_string(), Instant::now());
    warn!(
        "app {app_id}: no instance reports healthy; routing to all {candidates} \
         reachable instance(s) anyway rather than refusing the app"
    );
}

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

    /// Mutate an instance record in place, dropping any cached selection the
    /// change invalidates.
    ///
    /// The one way to write to `instances`, because "and remember to clear
    /// `top_n`" is not a rule a reviewer can enforce. Six call sites got it
    /// right and the seventh -- a CVM re-registering with a new WireGuard key,
    /// i.e. after a reboot -- did not, so the node that took the registration
    /// kept routing to a CVM whose containers were not up for as long as
    /// `cache_top_n`. That is precisely the window health gating exists to
    /// close, on the node most likely to be selected, and every other node in
    /// the cluster got it right via the sync path.
    ///
    /// `InstanceInfo::routing_inputs` is the definition of "invalidates", so
    /// adding a field to the selection means editing one struct rather than
    /// auditing every writer.
    fn edit_instance<T>(
        &mut self,
        id: &str,
        edit: impl FnOnce(&mut InstanceInfo) -> T,
    ) -> Option<T> {
        let info = self.state.instances.get_mut(id)?;
        let before = info.routing_inputs().to_owned();
        let out = edit(info);
        if before == info.routing_inputs() {
            return Some(out);
        }
        let before_app_id = before.app_id;
        let app_id = info.app_id.clone();
        self.state.top_n.remove(&app_id);
        if before_app_id != app_id {
            self.state.top_n.remove(&before_app_id);
        }
        Some(out)
    }

    fn new_client_by_id(
        &mut self,
        id: &str,
        app_id: &str,
        public_key: &str,
        compose_hash: &str,
        reported: ReportedCapabilities,
    ) -> Result<InstanceInfo> {
        let ReportedCapabilities {
            port_policy,
            health_check,
        } = reported;
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
        if self
            .state
            .instances
            .get(id)
            .is_some_and(|existing| existing.app_id != app_id)
        {
            bail!("instance_id is already registered to a different app");
        }
        // Through `edit_instance`, so the app's cached selection is dropped when
        // this changes something the selection was computed from. It can: a
        // reboot resets health here. Doing that without invalidating leaves
        // this node -- the one the CVM registered with, and therefore the one
        // most likely to route to it -- serving a pre-reboot selection for up
        // to `cache_top_n`, while every other node invalidates correctly off
        // the changed key arriving through sync.
        let edited = self.edit_instance(id, |existing| {
            // A restarted CVM's health verdict describes a process that no
            // longer exists, so it has to be dropped -- but "registered again"
            // does not mean "restarted". `dstack-util`'s gateway-checker
            // re-registers every `REFRESH_INTERVAL` (180s) and again whenever
            // the WireGuard handshake goes stale, so resetting on every
            // registration would drop a healthy instance to `Unknown` -- out of
            // the rotation until the next poll -- every three minutes, for a
            // CVM that never went anywhere.
            //
            // A new WireGuard key is what distinguishes the two. The guest
            // caches its key store in `/run/dstack/gateway-cache.json`, which
            // is tmpfs: a boot finds no cache and generates a fresh key, while
            // every refresh within that boot reuses it. A changed capability
            // means a different image, which also means a boot.
            //
            // This leans on where that cache lives. If it ever moves onto
            // persistent storage -- to keep a CVM's WireGuard IP across
            // reboots, say -- a reboot stops being visible here and the reset
            // has to move to an explicit boot id in `RegisterCvmRequest`.
            let pubkey_changed = existing.public_key != public_key;
            // A caller with nothing to say about the capability -- the debug
            // path -- must not be able to downgrade a real CVM's declaration.
            // Doing so would reset its health, then exclude it from polling for
            // good, on the strength of a request that never asked about it.
            let health_check = health_check.unwrap_or(existing.health_check());
            // `set_health_check` re-derives `health` when the declaration
            // changes; a reboot has to reset it even when it did not.
            if pubkey_changed {
                existing.reset_health();
            }
            existing.set_health_check(health_check);
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
            existing.clone()
        });
        if let Some(existing) = edited {
            if self.valid_ip(existing.ip) {
                // Sync existing instance to KvStore (might be from legacy state)
                let record = InstanceRecord::from(&existing);
                if let Err(err) = self.kv_store.sync_instance(&existing.id, &record) {
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
            // remembering to add a line here. `health` in particular: the
            // closure above has already applied this registration's
            // declaration to it, and re-deriving it here would throw away the
            // reboot reset it just made.
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
            // A caller with nothing to say about the capability -- the debug
            // path -- has no earlier declaration to inherit, so it is not gated.
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
                health: health_check.unwrap_or(false).into(),
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
        // `edit_instance` drops the pre-gate selection cache, so the change
        // applies to the next connection rather than up to `cache_top_n` later.
        let Some((prev, app_id)) = self.edit_instance(instance_id, |info| {
            let prev = info.is_ready();
            info.ready = Some(ready);
            (prev, info.app_id.clone())
        }) else {
            bail!("instance {instance_id} not found");
        };
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

    /// Record this node's latest health observation for an instance.
    ///
    /// Logs only when the verdict changes. Every instance is polled every few
    /// seconds, so an app that stays unhealthy for an hour should cost one
    /// line, not several hundred.
    pub(crate) fn record_instance_health(
        &mut self,
        target: &crate::proxy::health_check::Target,
        observation: crate::proxy::health_check::Observation,
    ) {
        let instance_id = target.id.as_str();
        // `edit_instance` drops the cached selection if this write changed
        // anything the selection was computed from.
        let applied = self.edit_instance(instance_id, |info| {
            // The record still exists, but is it the same one that was polled?
            // A round takes as long as its slowest instance, and a CVM can
            // reboot and re-register inside that window -- new WireGuard key,
            // health reset to `Unknown`, containers not up yet. Writing a
            // verdict from before that would put the previous boot's answer on
            // the new one and let it serve immediately, which is exactly what
            // `Unknown` exists to prevent. The IP is checked for the same
            // reason: it can be reallocated to another instance entirely.
            if info.public_key != target.public_key || info.ip != target.ip {
                return Err(());
            }
            let previous = info.health();
            if previous != observation.state {
                info.set_health(observation.state);
            }
            Ok(previous)
        });
        let previous = match applied {
            // Recycled or deregistered while the round was in flight.
            None => return,
            Some(Err(())) => {
                debug!("dropping stale health observation for instance {instance_id}");
                return;
            }
            Some(Ok(previous)) => previous,
        };
        if previous == observation.state {
            return;
        }
        let next = observation.state.as_str();
        if observation.reason.is_empty() {
            info!(
                "instance {instance_id} is now {next} (was {})",
                previous.as_str()
            );
        } else {
            info!(
                "instance {instance_id} is now {next} (was {}): {}",
                previous.as_str(),
                observation.reason
            );
        }
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
            .set_instance_gate(instance_id, ready)
            .with_context(|| {
                format!("failed to sync the gate for instance {instance_id} to KvStore")
            })
    }

    /// Persist the operator's port-policy override for `instance_id` to WaveKV.
    fn persist_instance_port_policy_override(&self, instance_id: &str) -> Result<()> {
        let Some(info) = self.state.instances.get(instance_id) else {
            return Ok(());
        };
        let policy = info.admin_port_policy.clone();
        self.kv_store
            .set_instance_port_policy_override(instance_id, policy)
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
        let record = InstanceRecord::from(info);
        self.kv_store
            .sync_instance(instance_id, &record)
            .with_context(|| format!("failed to sync instance {instance_id} to KvStore"))
    }

    fn add_instance(&mut self, info: InstanceInfo) {
        self.state.top_n.remove(&info.app_id);
        // Sync to KvStore
        let record = InstanceRecord::from(&info);
        if let Err(err) = self.kv_store.sync_instance(&info.id, &record) {
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

    /// Whether health observations are allowed to affect routing at all.
    ///
    /// With polling switched off nothing ever leaves `Unknown`, and `Unknown`
    /// is not healthy -- so the filter has to be skipped outright rather than
    /// merely left unfed. Otherwise disabling the feature would drop exactly
    /// the instances that opted into it, and in a fleet that also has apps
    /// which did not (`Ungated`, which counts as healthy) it would drop the
    /// opted-in ones permanently.
    fn health_gating_enabled(&self) -> bool {
        self.config.proxy.health_check.enabled
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

        let health_gating = self.health_gating_enabled();
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
                    Some(Candidate {
                        ip: instance.ip,
                        handshake_age: *elapsed,
                        counter: instance.connections.clone(),
                        instance_id: instance.id.clone(),
                        healthy: !health_gating || instance.is_healthy(),
                    })
                })
                .collect::<SmallVec<[_; 4]>>(),
        };
        retain_healthy(&mut self.state, id, &mut instances, |candidate| {
            candidate.healthy
        });
        instances.sort_by(|a, b| a.handshake_age.cmp(&b.handshake_age));
        instances.truncate(n);
        let selected: AddressGroup = instances
            .into_iter()
            .map(|candidate| AddressInfo {
                ip: candidate.ip,
                counter: candidate.counter,
                instance_id: candidate.instance_id,
            })
            .collect();
        self.state
            .top_n
            .insert(id.to_string(), (selected.clone(), Instant::now()));
        Ok(selected)
    }

    fn random_select_a_host(&mut self, id: &str) -> Option<AddressGroup> {
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

        // Health is resolved here, alongside eligibility, rather than inside
        // the retain: `retain_healthy` takes `&mut self.state` to rate-limit
        // its warning, so its predicate cannot also be reading instances out of
        // it.
        let health_gating = self.health_gating_enabled();
        // Instances the operator has left open and whose tunnel is fresh, each
        // paired with whether health lets it serve.
        let mut eligible = app_instances
            .iter()
            .filter_map(|instance_id| {
                let instance = self.state.instances.get(instance_id)?;
                self.is_eligible(instance, &handshakes)
                    .then(|| (instance_id.clone(), !health_gating || instance.is_healthy()))
            })
            .collect::<SmallVec<[(String, bool); 4]>>();
        retain_healthy(&mut self.state, id, &mut eligible, |(_, healthy)| *healthy);

        let (selected, _) = eligible.into_iter().choose(&mut rand::thread_rng())?;
        self.state.instances.get(&selected).map(|info| {
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
                // The rate limiter is keyed by app, so it has to be dropped
                // with the app rather than with the instance: keyed on "apps
                // seen since this process started" instead of "apps that
                // exist", it only ever grows, and the key is tenant-chosen.
                self.state.all_unhealthy_warned.remove(&info.app_id);
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
        if self.remote_app_id.is_none() {
            bail!("Client authentication is required");
        }
        if Some(&self.state.my_app_id) != self.remote_app_id.as_ref() {
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
            ReportedCapabilities {
                port_policy,
                // A real CVM always states its intent, either way.
                health_check: Some(request.health_check),
            },
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
