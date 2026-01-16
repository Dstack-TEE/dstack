// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use dstack_gateway_rpc::{
    admin_server::{AdminRpc, AdminServer},
    AddDomainCertRequest, CertAttestationInfo, CreateDnsCredentialRequest,
    DeleteDnsCredentialRequest, DeleteDomainCertRequest, DnsCredentialInfo, DomainCertInfo,
    DomainCertStatus, GetDefaultDnsCredentialResponse, GetDnsCredentialRequest,
    GetDomainCertRequest, GetInfoRequest, GetInfoResponse, GetInstanceHandshakesRequest,
    GetInstanceHandshakesResponse, GetMetaResponse, GetNodeStatusesResponse, GlobalConnectionsStats,
    HandshakeEntry, HostInfo, LastSeenEntry, ListCertAttestationsRequest,
    ListCertAttestationsResponse, ListDnsCredentialsResponse, ListDomainCertsResponse,
    NodeStatusEntry, PeerSyncStatus as ProtoPeerSyncStatus, RenewCertResponse,
    RenewDomainCertRequest, RenewDomainCertResponse, SetDefaultDnsCredentialRequest,
    SetNodeStatusRequest, SetNodeUrlRequest, StatusResponse, StoreSyncStatus,
    UpdateDnsCredentialRequest, UpdateDomainCertRequest, WaveKvStatusResponse,
};
use ra_rpc::{CallContext, RpcCall};
use tracing::info;
use wavekv::node::NodeStatus as WaveKvNodeStatus;

use crate::{
    kv::{DnsCredential, DnsProvider, DomainCertConfig, NodeStatus},
    main_service::Proxy,
    proxy::NUM_CONNECTIONS,
};

pub struct AdminRpcHandler {
    state: Proxy,
}

impl AdminRpcHandler {
    pub(crate) async fn status(self) -> Result<StatusResponse> {
        let mut state = self.state.lock();
        state.refresh_state()?;
        let base_domain = &state.config.proxy.base_domain;
        let hosts = state
            .state
            .instances
            .values()
            .map(|instance| {
                // Get global latest_handshake from KvStore (max across all nodes)
                let latest_handshake = state
                    .get_instance_latest_handshake(&instance.id)
                    .unwrap_or(0);
                HostInfo {
                    instance_id: instance.id.clone(),
                    ip: instance.ip.to_string(),
                    app_id: instance.app_id.clone(),
                    base_domain: base_domain.clone(),
                    port: state.config.proxy.listen_port as u32,
                    latest_handshake,
                    num_connections: instance.num_connections(),
                }
            })
            .collect::<Vec<_>>();
        Ok(StatusResponse {
            id: state.config.sync.node_id,
            url: state.config.sync.my_url.clone(),
            uuid: state.config.uuid(),
            bootnode_url: state.config.sync.bootnode.clone(),
            nodes: state.get_all_nodes(),
            hosts,
            num_connections: NUM_CONNECTIONS.load(Ordering::Relaxed),
        })
    }
}

impl AdminRpc for AdminRpcHandler {
    async fn exit(self) -> Result<()> {
        self.state.lock().exit();
    }

    async fn renew_cert(self) -> Result<RenewCertResponse> {
        // Renew all domains with force=true
        let renewed = self.state.renew_cert(None, true).await?;
        Ok(RenewCertResponse { renewed })
    }

    async fn set_caa(self) -> Result<()> {
        // TODO: Implement CAA setting for multi-domain certificates
        // This requires iterating over all domain configurations and setting CAA records
        bail!("set_caa is not implemented for multi-domain certificates yet");
    }

    async fn reload_cert(self) -> Result<()> {
        self.state.reload_certificates()
    }

    async fn status(self) -> Result<StatusResponse> {
        self.status().await
    }

    async fn get_info(self, request: GetInfoRequest) -> Result<GetInfoResponse> {
        let state = self.state.lock();
        let base_domain = &state.config.proxy.base_domain;
        let handshakes = state.latest_handshakes(None)?;

        if let Some(instance) = state.state.instances.get(&request.id) {
            let host_info = HostInfo {
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

    async fn set_node_url(self, request: SetNodeUrlRequest) -> Result<()> {
        let kv_store = self.state.kv_store();
        kv_store.register_peer_url(request.id, &request.url)?;
        info!("Updated peer URL: node {} -> {}", request.id, request.url);
        Ok(())
    }

    async fn set_node_status(self, request: SetNodeStatusRequest) -> Result<()> {
        let kv_store = self.state.kv_store();
        let status = match request.status.as_str() {
            "up" => NodeStatus::Up,
            "down" => NodeStatus::Down,
            _ => anyhow::bail!("invalid status: expected 'up' or 'down'"),
        };
        kv_store.set_node_status(request.id, status)?;
        info!("Updated node status: node {} -> {:?}", request.id, status);
        Ok(())
    }

    async fn wave_kv_status(self) -> Result<WaveKvStatusResponse> {
        let kv_store = self.state.kv_store();

        let persistent_status = kv_store.persistent().read().status();
        let ephemeral_status = kv_store.ephemeral().read().status();

        let get_peer_last_seen = |peer_id: u32| -> Vec<(u32, u64)> {
            kv_store
                .get_node_last_seen_by_all(peer_id)
                .into_iter()
                .collect()
        };

        Ok(WaveKvStatusResponse {
            enabled: self.state.config.sync.enabled,
            persistent: Some(build_store_status(
                "persistent",
                persistent_status,
                &get_peer_last_seen,
            )),
            ephemeral: Some(build_store_status(
                "ephemeral",
                ephemeral_status,
                &get_peer_last_seen,
            )),
        })
    }

    async fn get_instance_handshakes(
        self,
        request: GetInstanceHandshakesRequest,
    ) -> Result<GetInstanceHandshakesResponse> {
        let kv_store = self.state.kv_store();
        let handshakes = kv_store.get_instance_handshakes(&request.instance_id);

        let entries = handshakes
            .into_iter()
            .map(|(observer_node_id, timestamp)| HandshakeEntry {
                observer_node_id,
                timestamp,
            })
            .collect();

        Ok(GetInstanceHandshakesResponse {
            handshakes: entries,
        })
    }

    async fn get_global_connections(self) -> Result<GlobalConnectionsStats> {
        let state = self.state.lock();
        let kv_store = self.state.kv_store();

        let mut node_connections = std::collections::HashMap::new();
        let mut total_connections = 0u64;

        // Iterate through all instances and sum up connections per node
        for instance_id in state.state.instances.keys() {
            // Get connection counts from ephemeral KV for this instance
            let conn_prefix = format!("conn/{}/", instance_id);
            for (key, count) in kv_store
                .ephemeral()
                .read()
                .iter_by_prefix(&conn_prefix)
                .filter_map(|(k, entry)| {
                    let value = entry.value.as_ref()?;
                    let count: u64 = rmp_serde::decode::from_slice(value).ok()?;
                    Some((k.to_string(), count))
                })
            {
                // Parse node_id from key: "conn/{instance_id}/{node_id}"
                if let Some(node_id_str) = key.strip_prefix(&conn_prefix) {
                    if let Ok(node_id) = node_id_str.parse::<u32>() {
                        *node_connections.entry(node_id).or_insert(0) += count;
                        total_connections += count;
                    }
                }
            }
        }

        Ok(GlobalConnectionsStats {
            total_connections,
            node_connections,
        })
    }

    async fn get_node_statuses(self) -> Result<GetNodeStatusesResponse> {
        let kv_store = self.state.kv_store();
        let statuses = kv_store.load_all_node_statuses();

        let entries = statuses
            .into_iter()
            .map(|(node_id, status)| {
                let status_str = match status {
                    NodeStatus::Up => "up",
                    NodeStatus::Down => "down",
                };
                NodeStatusEntry {
                    node_id,
                    status: status_str.to_string(),
                }
            })
            .collect();

        Ok(GetNodeStatusesResponse { statuses: entries })
    }

    // ==================== DNS Credential Management ====================

    async fn list_dns_credentials(self) -> Result<ListDnsCredentialsResponse> {
        let kv_store = self.state.kv_store();
        let credentials = kv_store
            .list_dns_credentials()
            .into_iter()
            .map(dns_cred_to_proto)
            .collect();
        let default_id = kv_store.get_default_dns_credential_id();
        Ok(ListDnsCredentialsResponse {
            credentials,
            default_id,
        })
    }

    async fn get_dns_credential(self, request: GetDnsCredentialRequest) -> Result<DnsCredentialInfo> {
        let kv_store = self.state.kv_store();
        let cred = kv_store
            .get_dns_credential(&request.id)
            .context("dns credential not found")?;
        Ok(dns_cred_to_proto(cred))
    }

    async fn create_dns_credential(
        self,
        request: CreateDnsCredentialRequest,
    ) -> Result<DnsCredentialInfo> {
        let kv_store = self.state.kv_store();

        // Validate provider type
        let provider = match request.provider_type.as_str() {
            "cloudflare" => DnsProvider::Cloudflare {
                api_token: request.cf_api_token,
                zone_id: request.cf_zone_id,
            },
            _ => bail!("unsupported provider type: {}", request.provider_type),
        };

        let now = now_secs();
        let id = generate_cred_id();
        let cred = DnsCredential {
            id: id.clone(),
            name: request.name,
            provider,
            created_at: now,
            updated_at: now,
        };

        kv_store.save_dns_credential(&cred)?;
        info!("Created DNS credential: {} ({})", cred.name, cred.id);

        // Set as default if requested
        if request.set_as_default {
            kv_store.set_default_dns_credential_id(&id)?;
            info!("Set DNS credential {} as default", id);
        }

        Ok(dns_cred_to_proto(cred))
    }

    async fn update_dns_credential(
        self,
        request: UpdateDnsCredentialRequest,
    ) -> Result<DnsCredentialInfo> {
        let kv_store = self.state.kv_store();

        let mut cred = kv_store
            .get_dns_credential(&request.id)
            .context("dns credential not found")?;

        // Update name if provided
        if let Some(name) = request.name {
            cred.name = name;
        }

        // Update provider fields if provided
        match &mut cred.provider {
            DnsProvider::Cloudflare { api_token, zone_id } => {
                if let Some(new_token) = request.cf_api_token {
                    *api_token = new_token;
                }
                if let Some(new_zone) = request.cf_zone_id {
                    *zone_id = new_zone;
                }
            }
        }

        cred.updated_at = now_secs();
        kv_store.save_dns_credential(&cred)?;
        info!("Updated DNS credential: {} ({})", cred.name, cred.id);

        Ok(dns_cred_to_proto(cred))
    }

    async fn delete_dns_credential(self, request: DeleteDnsCredentialRequest) -> Result<()> {
        let kv_store = self.state.kv_store();

        // Check if this is the default credential
        if let Some(default_id) = kv_store.get_default_dns_credential_id() {
            if default_id == request.id {
                bail!("cannot delete the default DNS credential; set a different default first");
            }
        }

        // Check if any domain configs reference this credential
        let configs = kv_store.list_cert_configs();
        for config in configs {
            if config.dns_cred_id.as_deref() == Some(&request.id) {
                bail!(
                    "cannot delete DNS credential: domain {} uses it",
                    config.domain
                );
            }
        }

        kv_store.delete_dns_credential(&request.id)?;
        info!("Deleted DNS credential: {}", request.id);
        Ok(())
    }

    async fn get_default_dns_credential(self) -> Result<GetDefaultDnsCredentialResponse> {
        let kv_store = self.state.kv_store();
        let default_id = kv_store.get_default_dns_credential_id().unwrap_or_default();
        let credential = kv_store.get_default_dns_credential().map(dns_cred_to_proto);
        Ok(GetDefaultDnsCredentialResponse {
            default_id,
            credential,
        })
    }

    async fn set_default_dns_credential(self, request: SetDefaultDnsCredentialRequest) -> Result<()> {
        let kv_store = self.state.kv_store();

        // Verify the credential exists
        kv_store
            .get_dns_credential(&request.id)
            .context("dns credential not found")?;

        kv_store.set_default_dns_credential_id(&request.id)?;
        info!("Set default DNS credential: {}", request.id);
        Ok(())
    }

    // ==================== Domain Certificate Management ====================

    async fn list_domain_certs(self) -> Result<ListDomainCertsResponse> {
        let kv_store = self.state.kv_store();
        let cert_store = &self.state.cert_store;

        let domains = kv_store
            .list_cert_configs()
            .into_iter()
            .map(|config| domain_cert_to_proto(config, kv_store, cert_store))
            .collect();

        Ok(ListDomainCertsResponse { domains })
    }

    async fn get_domain_cert(self, request: GetDomainCertRequest) -> Result<DomainCertInfo> {
        let kv_store = self.state.kv_store();
        let cert_store = &self.state.cert_store;

        let config = kv_store
            .get_cert_config(&request.domain)
            .context("domain certificate config not found")?;

        Ok(domain_cert_to_proto(config, kv_store, cert_store))
    }

    async fn add_domain_cert(self, request: AddDomainCertRequest) -> Result<DomainCertInfo> {
        let kv_store = self.state.kv_store();
        let cert_store = &self.state.cert_store;

        // Check if domain already exists
        if kv_store.get_cert_config(&request.domain).is_some() {
            bail!("domain certificate config already exists: {}", request.domain);
        }

        // Validate DNS credential if specified
        if !request.dns_cred_id.is_empty() {
            kv_store
                .get_dns_credential(&request.dns_cred_id)
                .context("specified dns credential not found")?;
        }

        let acme_url = if request.acme_url.is_empty() {
            "https://acme-v02.api.letsencrypt.org/directory".to_string()
        } else {
            request.acme_url
        };

        let config = DomainCertConfig {
            domain: request.domain.clone(),
            dns_cred_id: if request.dns_cred_id.is_empty() {
                None
            } else {
                Some(request.dns_cred_id)
            },
            acme_url,
            enabled: request.enabled,
            created_at: now_secs(),
        };

        kv_store.save_cert_config(&config)?;
        info!(
            "Added domain certificate config: {} (enabled={})",
            config.domain, config.enabled
        );

        Ok(domain_cert_to_proto(config, kv_store, cert_store))
    }

    async fn update_domain_cert(self, request: UpdateDomainCertRequest) -> Result<DomainCertInfo> {
        let kv_store = self.state.kv_store();
        let cert_store = &self.state.cert_store;

        let mut config = kv_store
            .get_cert_config(&request.domain)
            .context("domain certificate config not found")?;

        // Update fields if provided
        if let Some(dns_cred_id) = request.dns_cred_id {
            if !dns_cred_id.is_empty() {
                kv_store
                    .get_dns_credential(&dns_cred_id)
                    .context("specified dns credential not found")?;
                config.dns_cred_id = Some(dns_cred_id);
            } else {
                config.dns_cred_id = None;
            }
        }

        if let Some(acme_url) = request.acme_url {
            config.acme_url = acme_url;
        }

        if let Some(enabled) = request.enabled {
            config.enabled = enabled;
        }

        kv_store.save_cert_config(&config)?;
        info!(
            "Updated domain certificate config: {} (enabled={})",
            config.domain, config.enabled
        );

        Ok(domain_cert_to_proto(config, kv_store, cert_store))
    }

    async fn delete_domain_cert(self, request: DeleteDomainCertRequest) -> Result<()> {
        let kv_store = self.state.kv_store();

        // Check if config exists
        kv_store
            .get_cert_config(&request.domain)
            .context("domain certificate config not found")?;

        // Delete config (cert data, acme, attestations are kept for historical purposes)
        kv_store.delete_cert_config(&request.domain)?;
        info!("Deleted domain certificate config: {}", request.domain);
        Ok(())
    }

    async fn renew_domain_cert(self, request: RenewDomainCertRequest) -> Result<RenewDomainCertResponse> {
        let certbot = &self.state.multi_domain_certbot;
        let renewed = certbot
            .try_renew(&request.domain, request.force)
            .await
            .context("certificate renewal failed")?;

        if renewed {
            // Get the new certificate data for response
            let kv_store = self.state.kv_store();
            let cert_data = kv_store.get_cert_data(&request.domain);
            let not_after = cert_data.map(|d| d.not_after).unwrap_or(0);
            Ok(RenewDomainCertResponse { renewed, not_after })
        } else {
            Ok(RenewDomainCertResponse {
                renewed: false,
                not_after: 0,
            })
        }
    }

    async fn list_cert_attestations(
        self,
        request: ListCertAttestationsRequest,
    ) -> Result<ListCertAttestationsResponse> {
        let kv_store = self.state.kv_store();

        let latest = kv_store
            .get_cert_attestation_latest(&request.domain)
            .map(|att| CertAttestationInfo {
                public_key: att.public_key,
                quote: att.quote,
                generated_by: att.generated_by,
                generated_at: att.generated_at,
            });

        let mut history: Vec<CertAttestationInfo> = kv_store
            .list_cert_attestations(&request.domain)
            .into_iter()
            .map(|att| CertAttestationInfo {
                public_key: att.public_key,
                quote: att.quote,
                generated_by: att.generated_by,
                generated_at: att.generated_at,
            })
            .collect();

        // Apply limit if specified
        if request.limit > 0 {
            history.truncate(request.limit as usize);
        }

        Ok(ListCertAttestationsResponse { latest, history })
    }
}

fn build_store_status(
    name: &str,
    status: WaveKvNodeStatus,
    get_peer_last_seen: &impl Fn(u32) -> Vec<(u32, u64)>,
) -> StoreSyncStatus {
    StoreSyncStatus {
        name: name.to_string(),
        node_id: status.id,
        n_keys: status.n_kvs as u64,
        next_seq: status.next_seq,
        dirty: status.dirty,
        wal_enabled: status.wal,
        peers: status
            .peers
            .into_iter()
            .map(|p| {
                let last_seen = get_peer_last_seen(p.id)
                    .into_iter()
                    .map(|(node_id, timestamp)| LastSeenEntry { node_id, timestamp })
                    .collect();
                ProtoPeerSyncStatus {
                    id: p.id,
                    local_ack: p.ack,
                    peer_ack: p.pack,
                    buffered_logs: p.logs as u64,
                    last_seen,
                }
            })
            .collect(),
    }
}

impl RpcCall<Proxy> for AdminRpcHandler {
    type PrpcService = AdminServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(AdminRpcHandler {
            state: context.state.clone(),
        })
    }
}

// ==================== Helper Functions ====================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_cred_id() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    // Simple ID: timestamp + random suffix
    let random: u32 = rand::random();
    format!("{:x}{:08x}", ts, random)
}

fn dns_cred_to_proto(cred: DnsCredential) -> DnsCredentialInfo {
    let (provider_type, cf_api_token, cf_zone_id) = match &cred.provider {
        DnsProvider::Cloudflare { api_token, zone_id } => {
            ("cloudflare".to_string(), api_token.clone(), zone_id.clone())
        }
    };
    DnsCredentialInfo {
        id: cred.id,
        name: cred.name,
        provider_type,
        cf_api_token,
        cf_zone_id,
        created_at: cred.created_at,
        updated_at: cred.updated_at,
    }
}

fn domain_cert_to_proto(
    config: DomainCertConfig,
    kv_store: &crate::kv::KvStore,
    cert_store: &crate::cert_store::CertStore,
) -> DomainCertInfo {
    // Get certificate data for status
    let cert_data = kv_store.get_cert_data(&config.domain);
    let loaded_in_memory = cert_store.has_cert(&config.domain);

    let status = Some(DomainCertStatus {
        has_cert: cert_data.is_some(),
        not_after: cert_data.as_ref().map(|d| d.not_after).unwrap_or(0),
        issued_by: cert_data.as_ref().map(|d| d.issued_by).unwrap_or(0),
        issued_at: cert_data.as_ref().map(|d| d.issued_at).unwrap_or(0),
        loaded_in_memory,
    });

    DomainCertInfo {
        domain: config.domain,
        dns_cred_id: config.dns_cred_id.unwrap_or_default(),
        acme_url: config.acme_url,
        enabled: config.enabled,
        created_at: config.created_at,
        status,
    }
}
