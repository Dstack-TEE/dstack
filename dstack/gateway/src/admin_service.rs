// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use dstack_gateway_rpc::{
    admin_server::{AdminRpc, AdminServer},
    CertAttestationInfo, CertbotConfigResponse, ClearInstancePortPolicyRequest,
    CreateDnsCredentialRequest, DeleteDnsCredentialRequest, DeleteZtDomainRequest,
    DnsCredentialInfo, ExitRequest, ForceReleaseCertLockRequest, GetDefaultDnsCredentialResponse,
    GetDnsCredentialRequest, GetInfoRequest, GetInfoResponse, GetInstanceHandshakesRequest,
    GetInstanceHandshakesResponse, GetInstancePortPolicyRequest, GetInstancePortPolicyResponse,
    GetMetaResponse, GetNodeStatusesResponse, GetZtDomainRequest, GlobalConnectionsStats,
    HandshakeEntry, HostInfo, LastSeenEntry, ListCertAttestationsRequest,
    ListCertAttestationsResponse, ListDnsCredentialsResponse, ListRejectedInstancesResponse,
    ListZtDomainsResponse, NodeStatusEntry, PeerSyncStatus as ProtoPeerSyncStatus,
    PortAttrs as RpcPortAttrs, PortPolicy as RpcPortPolicy, RejectedInstanceInfo, RemoveCvmRequest,
    RemoveCvmResponse, RemoveNodeRequest, RemoveNodeResponse, RenewCertResponse,
    RenewZtDomainCertRequest, RenewZtDomainCertResponse, RotateAcmeCredentialsResponse,
    SetCertbotConfigRequest, SetDefaultDnsCredentialRequest, SetInstancePortPolicyRequest,
    SetInstanceReadyRequest, SetNodeStatusRequest, SetNodeUrlRequest, StatusResponse,
    StoreSyncStatus, UpdateDnsCredentialRequest, WaveKvStatusResponse, ZtDomainCertStatus,
    ZtDomainConfig as ProtoZtDomainConfig, ZtDomainInfo,
};
use ra_rpc::{CallContext, RpcCall};
use tracing::{info, warn};
use wavekv::node::NodeStatus as WaveKvNodeStatus;

use crate::{
    kv::{
        import::Rejection, DnsCredential, DnsProvider, GlobalCertbotConfig, NodeStatus, PortFlags,
        PortPolicy, ZtDomainConfig,
    },
    main_service::Proxy,
    models::PortPolicyView,
    proxy::{stats::accel_status, NUM_CONNECTIONS},
    time::now_secs,
};

pub struct AdminRpcHandler {
    state: Proxy,
}

impl AdminRpcHandler {
    pub(crate) async fn status(self) -> Result<StatusResponse> {
        let (base_domain, _port) = self
            .state
            .kv_store()
            .get_best_zt_domain()
            .unwrap_or_default();
        let mut state = self.state.lock();
        state.refresh_state()?;
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
                    latest_handshake,
                    num_connections: instance.num_connections(),
                    ready: Some(instance.is_ready()),
                    health: instance.health().as_str().to_string(),
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
            // Reads the post-probe config, so this is what the data path is
            // running rather than what the file asked for.
            accel: Some(accel_status(&state.config.proxy)),
            health_gating: state.config.proxy.health_check.enabled,
        })
    }
}

impl AdminRpc for AdminRpcHandler {
    async fn exit(self, request: ExitRequest) -> Result<()> {
        self.state.lock().exit(request.force)
    }

    async fn renew_cert(self) -> Result<RenewCertResponse> {
        // Renew all domains with force=true
        let renewed = self.state.renew_cert(None, true).await?;
        Ok(RenewCertResponse { renewed })
    }

    async fn set_caa(self) -> Result<()> {
        self.state.certbot.set_caa_all().await
    }

    async fn reload_cert(self) -> Result<()> {
        self.state.reload_all_certs_from_kvstore()
    }

    async fn rotate_acme_credentials(self) -> Result<RotateAcmeCredentialsResponse> {
        let (account_uri, domains_updated) = self.state.rotate_acme_credentials().await?;
        Ok(RotateAcmeCredentialsResponse {
            account_uri,
            domains_updated: domains_updated.try_into().unwrap_or(u32::MAX),
        })
    }

    async fn status(self) -> Result<StatusResponse> {
        self.status().await
    }

    async fn get_info(self, request: GetInfoRequest) -> Result<GetInfoResponse> {
        let (base_domain, _port) = self
            .state
            .kv_store()
            .get_best_zt_domain()
            .unwrap_or_default();
        let state = self.state.lock();
        let handshakes = state.latest_handshakes(None)?;

        if let Some(instance) = state.state.instances.get(&request.id) {
            let host_info = HostInfo {
                instance_id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain,
                latest_handshake: {
                    let (ts, _) = handshakes
                        .get(&instance.public_key)
                        .copied()
                        .unwrap_or_default();
                    ts
                },
                num_connections: instance.num_connections(),
                ready: Some(instance.is_ready()),
                health: instance.health().as_str().to_string(),
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
                *ts != 0 && now.saturating_sub(*ts) < 300
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

        // Per-peer digest and failure telemetry lives on the sync manager, not the store.
        let links = self
            .state
            .wavekv_sync
            .as_ref()
            .map(|s| s.link_status())
            .unwrap_or_default();
        let links_for = |name: &str| -> Vec<wavekv::sync::PeerLinkStatus> {
            links
                .iter()
                .find(|(store, _)| *store == name)
                .map(|(_, l)| l.clone())
                .unwrap_or_default()
        };

        Ok(WaveKvStatusResponse {
            enabled: self.state.config.sync.enabled,
            persistent: Some(build_store_status(
                "persistent",
                persistent_status,
                &links_for("persistent"),
                &get_peer_last_seen,
            )),
            ephemeral: Some(build_store_status(
                "ephemeral",
                ephemeral_status,
                &links_for("ephemeral"),
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

    async fn remove_cvm(self, request: RemoveCvmRequest) -> Result<RemoveCvmResponse> {
        let instance_id = request.instance_id.as_str();
        // Same bound the KV import boundary puts on identifiers. Legitimate
        // gateways never write an instance_id outside it, so this rejects only
        // typos — and keeps the ID safe to embed in logs and KV keys.
        crate::kv::import::validate_id("instance_id", instance_id)?;

        let removal = self.state.remove_cvm(instance_id)?;
        warn!(
            "admin removed CVM {instance_id} from WaveKV and the local data plane \
             (record existed: {}, present locally: {})",
            removal.record_existed, removal.removed_locally
        );
        Ok(RemoveCvmResponse {
            record_existed: removal.record_existed,
            removed_locally: removal.removed_locally,
        })
    }

    async fn list_rejected_instances(self) -> Result<ListRejectedInstancesResponse> {
        let rejected = self
            .state
            .rejected_instances()
            .into_iter()
            .map(|report| RejectedInstanceInfo {
                instance_id: report.rejected.instance_id,
                reason: format!("{:#}", report.rejected.reason),
                rejection: match report.rejected.rejection {
                    Rejection::Unusable => "unusable".to_string(),
                    Rejection::LostConflict => "lost_conflict".to_string(),
                },
                active_locally: report.active_locally,
            })
            .collect();
        Ok(ListRejectedInstancesResponse { rejected })
    }

    async fn remove_node(self, request: RemoveNodeRequest) -> Result<RemoveNodeResponse> {
        let removal = self.state.remove_node(request.node_id)?;
        warn!(
            "admin removed node {} from WaveKV and the sync peer set \
             (record existed: {}, was a sync peer: {})",
            request.node_id, removal.record_existed, removal.removed_from_peer_set
        );
        Ok(RemoveNodeResponse {
            record_existed: removal.record_existed,
            removed_from_peer_set: removal.removed_from_peer_set,
        })
    }

    // ==================== DNS Credential Management ====================

    async fn list_dns_credentials(self) -> Result<ListDnsCredentialsResponse> {
        let kv_store = self.state.kv_store();
        let credentials = kv_store
            .list_dns_credentials()
            .into_iter()
            .map(dns_cred_to_proto)
            .collect();
        let default_id = kv_store.get_default_dns_credential_id()?;
        Ok(ListDnsCredentialsResponse {
            credentials,
            default_id,
        })
    }

    async fn get_dns_credential(
        self,
        request: GetDnsCredentialRequest,
    ) -> Result<DnsCredentialInfo> {
        let kv_store = self.state.kv_store();
        let cred = kv_store
            .get_dns_credential(&request.id)?
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
                api_url: request.cf_api_url,
            },
            _ => bail!("unsupported provider type: {}", request.provider_type),
        };

        let now = now_secs();
        let id = generate_cred_id();
        let dns_txt_ttl = request.dns_txt_ttl.unwrap_or(60);
        let max_dns_wait_secs = request.max_dns_wait.unwrap_or(60 * 5);
        if dns_txt_ttl == 0 {
            bail!("dns_txt_ttl must be greater than zero");
        }
        if max_dns_wait_secs == 0 {
            bail!("max_dns_wait must be greater than zero");
        }
        let max_dns_wait = Duration::from_secs(max_dns_wait_secs.into());
        let cred = DnsCredential {
            id: id.clone(),
            name: request.name,
            provider,
            created_at: now,
            updated_at: now,
            dns_txt_ttl,
            max_dns_wait,
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
            .get_dns_credential(&request.id)?
            .context("dns credential not found")?;

        // Update name if provided
        if let Some(name) = request.name {
            cred.name = name;
        }

        // Update provider fields if provided
        match &mut cred.provider {
            DnsProvider::Cloudflare { api_token, api_url } => {
                if let Some(new_token) = request.cf_api_token {
                    *api_token = new_token;
                }
                if let Some(new_url) = request.cf_api_url {
                    *api_url = Some(new_url);
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
        if let Some(default_id) = kv_store.get_default_dns_credential_id()? {
            if default_id == request.id {
                bail!("cannot delete the default DNS credential; set a different default first");
            }
        }

        // Check if any ZT-Domain configs reference this credential
        let configs = kv_store.list_zt_domain_configs();
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
        let default_id = kv_store
            .get_default_dns_credential_id()?
            .unwrap_or_default();
        let credential = kv_store
            .get_default_dns_credential()?
            .map(dns_cred_to_proto);
        Ok(GetDefaultDnsCredentialResponse {
            default_id,
            credential,
        })
    }

    async fn set_default_dns_credential(
        self,
        request: SetDefaultDnsCredentialRequest,
    ) -> Result<()> {
        let kv_store = self.state.kv_store();

        // Verify the credential exists
        kv_store
            .get_dns_credential(&request.id)?
            .context("dns credential not found")?;

        kv_store.set_default_dns_credential_id(&request.id)?;
        info!("Set default DNS credential: {}", request.id);
        Ok(())
    }

    // ==================== ZT-Domain Management ====================

    async fn list_zt_domains(self) -> Result<ListZtDomainsResponse> {
        let kv_store = self.state.kv_store();
        let cert_resolver = &self.state.cert_resolver;

        let domains = kv_store
            .list_zt_domain_configs()
            .into_iter()
            .map(|config| zt_domain_to_proto(config, kv_store, cert_resolver))
            .collect();

        Ok(ListZtDomainsResponse { domains })
    }

    async fn get_zt_domain(self, request: GetZtDomainRequest) -> Result<ZtDomainInfo> {
        let kv_store = self.state.kv_store();
        let cert_resolver = &self.state.cert_resolver;

        let domain = normalize_zt_domain(&request.domain)?;
        let config = kv_store
            .get_zt_domain_config(&domain)
            .context("ZT-Domain config not found")?;

        Ok(zt_domain_to_proto(config, kv_store, cert_resolver))
    }

    async fn add_zt_domain(self, request: ProtoZtDomainConfig) -> Result<ZtDomainInfo> {
        let kv_store = self.state.kv_store();
        let cert_resolver = &self.state.cert_resolver;

        let config = proto_to_zt_domain_config(&request, kv_store)?;

        // Uniqueness is checked after normalization so wildcard, case, and a
        // trailing root dot cannot silently overwrite the same DNS name.
        if kv_store.get_zt_domain_config(&config.domain).is_some() {
            bail!("ZT-Domain config already exists: {}", config.domain);
        }

        kv_store.save_zt_domain_config(&config)?;
        info!("Added ZT-Domain config: {}", config.domain);

        Ok(zt_domain_to_proto(config, kv_store, cert_resolver))
    }

    async fn update_zt_domain(self, request: ProtoZtDomainConfig) -> Result<ZtDomainInfo> {
        let kv_store = self.state.kv_store();
        let cert_resolver = &self.state.cert_resolver;

        let config = proto_to_zt_domain_config(&request, kv_store)?;

        // Check the normalized key rather than the caller's presentation.
        kv_store
            .get_zt_domain_config(&config.domain)
            .context("ZT-Domain config not found")?;

        kv_store.save_zt_domain_config(&config)?;
        info!("Updated ZT-Domain config: {}", config.domain);

        Ok(zt_domain_to_proto(config, kv_store, cert_resolver))
    }

    async fn delete_zt_domain(self, request: DeleteZtDomainRequest) -> Result<()> {
        let kv_store = self.state.kv_store();

        let domain = normalize_zt_domain(&request.domain)?;
        // A corrupt config must still be deletable, so check for the record
        // itself: get_zt_domain_config cannot tell missing from unreadable,
        // and refusing would leave a corrupt record permanently stuck.
        ensure!(
            kv_store.zt_domain_config_exists(&domain),
            "ZT-Domain config not found"
        );

        // Delete config (cert data, acme, attestations are kept for historical purposes)
        kv_store.delete_zt_domain_config(&domain)?;
        info!("Deleted ZT-Domain config: {domain}");
        Ok(())
    }

    async fn renew_zt_domain_cert(
        self,
        request: RenewZtDomainCertRequest,
    ) -> Result<RenewZtDomainCertResponse> {
        let certbot = &self.state.certbot;
        let renewed = certbot
            .try_renew(&request.domain, request.force)
            .await
            .context("certificate renewal failed")?;

        if renewed {
            // Get the new certificate data for response
            let kv_store = self.state.kv_store();
            let cert_data = kv_store.get_cert_data(&request.domain);
            let not_after = cert_data.map(|d| d.not_after).unwrap_or(0);
            Ok(RenewZtDomainCertResponse { renewed, not_after })
        } else {
            Ok(RenewZtDomainCertResponse {
                renewed: false,
                not_after: 0,
            })
        }
    }

    async fn force_release_cert_lock(self, request: ForceReleaseCertLockRequest) -> Result<()> {
        let kv_store = self.state.kv_store();
        kv_store.release_cert_lock(&request.domain)?;
        info!(
            "Force released certificate lock for domain: {}",
            request.domain
        );
        Ok(())
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

    // ==================== Global Certbot Configuration ====================

    async fn get_certbot_config(self) -> Result<CertbotConfigResponse> {
        let config = self.state.kv_store().get_certbot_config()?;
        Ok(CertbotConfigResponse {
            renew_interval_secs: config.renew_interval.as_secs(),
            renew_before_expiration_secs: config.renew_before_expiration.as_secs(),
            renew_timeout_secs: config.renew_timeout.as_secs(),
            acme_url: config.acme_url,
        })
    }

    async fn set_certbot_config(self, request: SetCertbotConfigRequest) -> Result<()> {
        let kv_store = self.state.kv_store();
        let config = merge_certbot_config(kv_store.get_certbot_config(), request)?;
        kv_store.set_certbot_config(&config)?;
        info!(
            "Updated certbot config: renew_interval={:?}, renew_before_expiration={:?}, renew_timeout={:?}, acme_url={:?}",
            config.renew_interval,
            config.renew_before_expiration,
            config.renew_timeout,
            config.acme_url
        );
        Ok(())
    }

    async fn set_instance_port_policy(self, request: SetInstancePortPolicyRequest) -> Result<()> {
        let proto = request.policy.context("port policy is required")?;
        let policy = port_policy_from_proto(proto)?;
        self.state
            .lock()
            .set_admin_port_policy(&request.instance_id, policy)
    }

    async fn clear_instance_port_policy(
        self,
        request: ClearInstancePortPolicyRequest,
    ) -> Result<()> {
        self.state
            .lock()
            .clear_admin_port_policy(&request.instance_id)
    }

    async fn get_instance_port_policy(
        self,
        request: GetInstancePortPolicyRequest,
    ) -> Result<GetInstancePortPolicyResponse> {
        let view = self
            .state
            .lock()
            .instance_port_policy_view(&request.instance_id)
            .with_context(|| format!("instance {} not found", request.instance_id))?;
        Ok(port_policy_view_to_proto(view))
    }

    async fn set_instance_ready(self, request: SetInstanceReadyRequest) -> Result<()> {
        self.state
            .lock()
            .set_ready(&request.instance_id, request.ready)
    }
}

fn port_policy_from_proto(proto: RpcPortPolicy) -> Result<PortPolicy> {
    let mut ports = std::collections::BTreeMap::new();
    for attr in proto.ports {
        let port = u16::try_from(attr.port)
            .with_context(|| format!("port {} out of u16 range", attr.port))?;
        ports.insert(port, PortFlags { pp: attr.pp });
    }
    Ok(PortPolicy {
        ports,
        restrict_mode: proto.restrict_mode,
    })
}

fn port_policy_to_proto(policy: &PortPolicy) -> RpcPortPolicy {
    RpcPortPolicy {
        ports: policy
            .ports
            .iter()
            .map(|(port, flags)| RpcPortAttrs {
                port: u32::from(*port),
                pp: flags.pp,
            })
            .collect(),
        restrict_mode: policy.restrict_mode,
    }
}

fn port_policy_view_to_proto(view: PortPolicyView) -> GetInstancePortPolicyResponse {
    let source = view.source().to_string();
    let effective = view.effective().map(port_policy_to_proto);
    GetInstancePortPolicyResponse {
        effective,
        source,
        instance_reported: view.instance_reported.as_ref().map(port_policy_to_proto),
        admin_override: view.admin_override.as_ref().map(port_policy_to_proto),
    }
}

fn build_store_status(
    name: &str,
    status: WaveKvNodeStatus,
    links: &[wavekv::sync::PeerLinkStatus],
    get_peer_last_seen: &impl Fn(u32) -> Vec<(u32, u64)>,
) -> StoreSyncStatus {
    StoreSyncStatus {
        name: name.to_string(),
        node_id: status.id,
        n_keys: status.n_kvs as u64,
        next_seq: status.next_seq,
        dirty: status.dirty,
        wal_enabled: status.wal,
        digest: status.digest,
        entries_merged: status.entries_merged,
        entries_rejected: status.entries_rejected,
        peers: status
            .peers
            .into_iter()
            .map(|p| {
                let last_seen = get_peer_last_seen(p.id)
                    .into_iter()
                    .map(|(node_id, timestamp)| LastSeenEntry { node_id, timestamp })
                    .collect();
                let link = links.iter().find(|l| l.id == p.id);
                ProtoPeerSyncStatus {
                    id: p.id,
                    local_ack: p.ack,
                    peer_ack: p.peer_ack,
                    last_seen,
                    heard_from: p.heard_from,
                    digest_mismatches: link.map(|l| l.digest_mismatches).unwrap_or(0),
                    consecutive_failures: link.map(|l| l.consecutive_failures).unwrap_or(0),
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
    let (provider_type, cf_api_token, cf_api_url) = match &cred.provider {
        DnsProvider::Cloudflare { api_token, api_url } => (
            "cloudflare".to_string(),
            redact_token(api_token),
            api_url.clone().unwrap_or_default(),
        ),
    };
    DnsCredentialInfo {
        id: cred.id,
        name: cred.name,
        provider_type,
        cf_api_token,
        cf_api_url,
        created_at: cred.created_at,
        updated_at: cred.updated_at,
        dns_txt_ttl: Some(cred.dns_txt_ttl),
        max_dns_wait: Some(cred.max_dns_wait.as_secs() as u32),
    }
}

fn redact_token(token: &str) -> String {
    let len = token.len();
    if len <= 8 {
        "*".repeat(len)
    } else {
        format!("{}...{}", &token[..4], &token[len - 4..])
    }
}

fn normalize_zt_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.');
    let domain = domain
        .strip_prefix("*.")
        .unwrap_or(domain)
        .to_ascii_lowercase();
    validate_zt_domain(&domain)?;
    Ok(domain)
}

fn validate_zt_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 || !domain.is_ascii() {
        bail!("domain must be a non-empty ASCII DNS name of at most 253 bytes");
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("domain contains an invalid DNS label");
        }
    }
    Ok(())
}

/// Convert proto ZtDomainConfig to internal ZtDomainConfig
fn proto_to_zt_domain_config(
    proto: &ProtoZtDomainConfig,
    kv_store: &crate::kv::KvStore,
) -> Result<ZtDomainConfig> {
    // Normalize dns_cred_id: treat empty string as None (use default)
    let dns_cred_id = proto
        .dns_cred_id
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned();

    // Validate DNS credential if specified
    if let Some(ref cred_id) = dns_cred_id {
        kv_store
            .get_dns_credential(cred_id)?
            .context("specified dns credential not found")?;
    }

    let domain = normalize_zt_domain(&proto.domain)?;
    if proto.port == 0 {
        bail!("port must be between 1 and 65535");
    }

    Ok(ZtDomainConfig {
        domain,
        dns_cred_id,
        port: proto.port.try_into().context("port out of range")?,
        node: proto.node,
        priority: proto.priority,
    })
}

/// Convert internal ZtDomainConfig to proto ZtDomainInfo (with cert status)
fn zt_domain_to_proto(
    config: ZtDomainConfig,
    kv_store: &crate::kv::KvStore,
    cert_resolver: &crate::cert_store::CertResolver,
) -> ZtDomainInfo {
    // Get certificate data for status
    let cert_data = kv_store.get_cert_data(&config.domain);
    let loaded_in_memory = cert_resolver.has_cert(&config.domain);

    let cert_status = Some(ZtDomainCertStatus {
        has_cert: cert_data.is_some(),
        not_after: cert_data.as_ref().map(|d| d.not_after).unwrap_or(0),
        issued_by: cert_data.as_ref().map(|d| d.issued_by).unwrap_or(0),
        issued_at: cert_data.as_ref().map(|d| d.issued_at).unwrap_or(0),
        loaded_in_memory,
    });

    ZtDomainInfo {
        config: Some(ProtoZtDomainConfig {
            domain: config.domain,
            dns_cred_id: config.dns_cred_id,
            port: config.port.into(),
            node: config.node,
            priority: config.priority,
        }),
        cert_status,
    }
}

/// Apply a partial certbot-config update to the stored record.
///
/// SetCertbotConfig is a merge: a field the operator leaves unset keeps its
/// stored value. That needs a readable base, and `global/certbot_config` is a
/// singleton with no delete RPC — so if an unreadable record simply failed the
/// call, the corruption would be permanent, and since `do_rotate_acme_credentials`
/// reads the same key it would keep RotateAcmeCredentials blocked along with it.
///
/// Merging into the defaults instead is not the answer either: `acme_url`
/// defaults to empty, which means Let's Encrypt production. An operator who hit
/// a corrupt record and then tuned `renew_interval` would silently move issuance
/// off their staging or private ACME server and start burning real rate limits —
/// exactly the switch the fail-closed reader exists to prevent.
///
/// So an unreadable record is repairable, but only by a request that states
/// every field. Nothing is ever inherited from a record we cannot read.
fn merge_certbot_config(
    stored: Result<GlobalCertbotConfig>,
    request: SetCertbotConfigRequest,
) -> Result<GlobalCertbotConfig> {
    let mut config = match stored {
        Ok(config) => config,
        Err(err) => {
            ensure!(
                request.renew_interval_secs.is_some()
                    && request.renew_before_expiration_secs.is_some()
                    && request.renew_timeout_secs.is_some()
                    && request.acme_url.is_some(),
                "the stored certbot config is unreadable ({err:#}), so it can only be \
                 replaced as a whole: resend with renew_interval_secs, \
                 renew_before_expiration_secs, renew_timeout_secs and acme_url all set"
            );
            warn!("certbot config is unreadable ({err:#}); replacing it wholesale");
            GlobalCertbotConfig::default()
        }
    };

    // Update only the fields that are specified
    if let Some(secs) = request.renew_interval_secs {
        config.renew_interval = Duration::from_secs(secs);
    }
    if let Some(secs) = request.renew_before_expiration_secs {
        config.renew_before_expiration = Duration::from_secs(secs);
    }
    if let Some(secs) = request.renew_timeout_secs {
        config.renew_timeout = Duration::from_secs(secs);
    }
    if let Some(url) = request.acme_url {
        config.acme_url = url;
    }
    Ok(config)
}

#[cfg(test)]
mod certbot_config_tests {
    use super::*;

    fn stored() -> GlobalCertbotConfig {
        GlobalCertbotConfig {
            renew_interval: Duration::from_secs(3600),
            acme_url: "https://acme-staging.example/directory".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_partial_update_keeps_the_fields_it_does_not_mention() {
        let merged = merge_certbot_config(
            Ok(stored()),
            SetCertbotConfigRequest {
                renew_timeout_secs: Some(60),
                ..Default::default()
            },
        )
        .expect("a readable record merges");
        assert_eq!(merged.renew_timeout, Duration::from_secs(60));
        assert_eq!(merged.acme_url, stored().acme_url);
    }

    #[test]
    fn a_partial_update_cannot_repair_an_unreadable_record() {
        // Falling back to the defaults here would reset `acme_url` to empty,
        // silently moving issuance to Let's Encrypt production.
        let err = merge_certbot_config(
            Err(anyhow::anyhow!("corrupt record")),
            SetCertbotConfigRequest {
                renew_interval_secs: Some(60),
                ..Default::default()
            },
        )
        .expect_err("a partial update must not inherit from an unreadable record");
        assert!(err.to_string().contains("acme_url"), "{err:#}");
    }

    #[test]
    fn a_complete_request_replaces_an_unreadable_record() {
        // The only repair path: no field is inherited, so nothing is guessed.
        let merged = merge_certbot_config(
            Err(anyhow::anyhow!("corrupt record")),
            SetCertbotConfigRequest {
                renew_interval_secs: Some(60),
                renew_before_expiration_secs: Some(86400),
                renew_timeout_secs: Some(30),
                acme_url: Some("https://acme-staging.example/directory".to_string()),
            },
        )
        .expect("a complete request replaces the record");
        assert_eq!(merged.renew_interval, Duration::from_secs(60));
        assert_eq!(merged.acme_url, "https://acme-staging.example/directory");
    }
}

#[cfg(test)]
mod zt_domain_tests {
    use super::validate_zt_domain;

    #[test]
    fn accepts_a_dns_domain() {
        validate_zt_domain("service.example.com").unwrap();
    }

    #[test]
    fn rejects_empty_and_invalid_dns_domains() {
        for domain in [
            "",
            ".example.com",
            "example..com",
            "-bad.example",
            "bad-.example",
        ] {
            assert!(
                validate_zt_domain(domain).is_err(),
                "{domain} should be rejected"
            );
        }
    }
}

#[cfg(test)]
mod wavekv_status_tests {
    use super::{build_store_status, WaveKvNodeStatus};
    use wavekv::{node::PeerStatus, sync::PeerLinkStatus};

    #[test]
    fn wavekv_status_preserves_store_and_peer_telemetry() {
        let status = WaveKvNodeStatus {
            id: 1,
            n_kvs: 3,
            next_seq: 11,
            dirty: true,
            wal: true,
            digest: "deadbeef".to_string(),
            entries_merged: 17,
            entries_rejected: 2,
            peers: vec![PeerStatus {
                id: 7,
                ack: 5,
                peer_ack: 4,
                heard_from: true,
            }],
        };
        let links = vec![PeerLinkStatus {
            id: 7,
            protocol: "v2",
            digest_mismatches: 3,
            consecutive_failures: 6,
        }];

        let proto = build_store_status("persistent", status, &links, &|peer| {
            assert_eq!(peer, 7);
            vec![(2, 1234)]
        });

        assert_eq!(proto.name, "persistent");
        assert_eq!(proto.node_id, 1);
        assert_eq!(proto.n_keys, 3);
        assert_eq!(proto.next_seq, 11);
        assert!(proto.dirty);
        assert!(proto.wal_enabled);
        assert_eq!(proto.digest, "deadbeef");
        assert_eq!(proto.entries_merged, 17);
        assert_eq!(proto.entries_rejected, 2);
        assert_eq!(proto.peers.len(), 1);

        let peer = &proto.peers[0];
        assert_eq!(peer.id, 7);
        assert_eq!(peer.local_ack, 5);
        assert_eq!(peer.peer_ack, 4);
        assert!(peer.heard_from);
        assert_eq!(peer.digest_mismatches, 3);
        assert_eq!(peer.consecutive_failures, 6);
        assert_eq!(peer.last_seen.len(), 1);
        assert_eq!(peer.last_seen[0].node_id, 2);
        assert_eq!(peer.last_seen[0].timestamp, 1234);
    }
}
