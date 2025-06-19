use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use certbot::{CertBot, WorkDir};
use cmd_lib::run_cmd as cmd;
use fs_err as fs;
use ra_rpc::{Attestation, CallContext, RpcCall};
use rand::seq::IteratorRandom;
use rinja::Template as _;
use safe_write::safe_write;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use tokio_rustls::TlsAcceptor;
use tproxy_rpc::TappdConfig;
use tproxy_rpc::{
    tproxy_server::{TproxyRpc, TproxyServer},
    AcmeInfoResponse, RegisterCvmRequest, RegisterCvmResponse, WireGuardConfig,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    models::{InstanceInfo, WgConf},
    proxy::{create_acceptor, AddressGroup},
};

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
    state: Mutex<ProxyState>,
    pub(crate) acceptor: RwLock<TlsAcceptor>,
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
}

impl Proxy {
    pub async fn new(config: Config) -> Result<Self> {
        Ok(Self {
            _inner: Arc::new(ProxyInner::new(config).await?),
        })
    }
}

impl ProxyInner {
    pub(crate) fn lock(&self) -> MutexGuard<ProxyState> {
        self.state.lock().expect("Failed to lock AppState")
    }

    pub async fn new(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let state = fs::metadata(&config.state_path)
            .is_ok()
            .then(|| load_state(&config.state_path))
            .transpose()
            .unwrap_or_else(|err| {
                error!("Failed to load state: {err}");
                None
            })
            .unwrap_or_default();
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
        let acceptor =
            RwLock::new(create_acceptor(&config.proxy).context("Failed to create acceptor")?);
        Ok(Self {
            config: config.clone(),
            state: Mutex::new(ProxyState { config, state }),
            acceptor,
            certbot,
        })
    }
}

impl Proxy {
    pub(crate) async fn start_bg_tasks(&self) -> Result<()> {
        start_recycle_thread(self.clone());
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
}

fn load_state(state_path: &str) -> Result<ProxyStateMut> {
    let state_str = fs::read_to_string(state_path).context("Failed to read state")?;
    serde_json::from_str(&state_str).context("Failed to load state")
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

impl ProxyState {
    fn alloc_ip(&mut self) -> Option<Ipv4Addr> {
        for ip in self.config.wg.client_ip_range.hosts() {
            if ip == self.config.wg.ip {
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
        safe_write(&self.config.wg.config_path, wg_config).context("Failed to write wg config")?;
        // wg setconf <interface_name> <config_path>
        let ifname = &self.config.wg.interface;
        let config_path = &self.config.wg.config_path;

        match cmd!(wg syncconf $ifname $config_path) {
            Ok(_) => info!("wg config updated"),
            Err(e) => error!("failed to set wg config: {e}"),
        }
        let state_str = serde_json::to_string(&self.state).context("Failed to serialize state")?;
        safe_write(&self.config.state_path, state_str).context("Failed to write state")?;
        Ok(())
    }

    pub(crate) fn select_top_n_hosts(&mut self, id: &str) -> Result<AddressGroup> {
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
    pub(crate) fn latest_handshakes(
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

    pub(crate) fn refresh_state(&mut self) -> Result<()> {
        let handshakes = self.latest_handshakes(None)?;
        for instance in self.state.instances.values_mut() {
            let Some((ts, _)) = handshakes.get(&instance.public_key).copied() else {
                continue;
            };
            instance.last_seen = decode_ts(ts);
        }
        Ok(())
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
    attestation: Option<Attestation>,
    state: Proxy,
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

impl RpcCall<Proxy> for RpcHandler {
    type PrpcService = TproxyServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(RpcHandler {
            attestation: context.attestation,
            state: context.state.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
