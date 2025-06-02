use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use dstack_gateway_rpc::{gateway_client::GatewayClient, GatewayState};
use dstack_guest_agent_rpc::GetTlsKeyArgs;
use ra_rpc::client::{RaClient, RaClientConfig};
use tokio::sync::mpsc::Receiver;
use tracing::{error, info};

use crate::{config::Config, dstack_agent};

use super::ProxyState;

pub enum SyncEvent {
    Broadcast,
}

struct SyncClient {
    in_dstack: bool,
    cert_pem: String,
    key_pem: String,
    ca_cert_pem: String,
    app_id: Vec<u8>,
    timeout: Duration,
    pccs_url: Option<String>,
}

impl SyncClient {
    fn create_rpc_client(&self, url: &str) -> Result<GatewayClient<RaClient>> {
        let app_id = self.app_id.clone();
        let url = format!("{}/prpc", url.trim_end_matches('/'));
        let client = if self.in_dstack {
            RaClientConfig::builder()
                .remote_uri(url)
                // Don't verify server RA because we use the CA cert from KMS to verify
                // the server cert.
                .verify_server_attestation(false)
                .tls_no_check(true)
                .tls_no_check_hostname(false)
                .tls_client_cert(self.cert_pem.clone())
                .tls_client_key(self.key_pem.clone())
                .tls_ca_cert(self.ca_cert_pem.clone())
                .tls_built_in_root_certs(false)
                .maybe_pccs_url(self.pccs_url.clone())
                .cert_validator(Box::new(move |cert| {
                    let cert = cert.context("TLS cert not found")?;
                    let remote_app_id = cert.app_id.context("App id not found")?;
                    if remote_app_id != app_id {
                        return Err(anyhow::anyhow!("Remote app id mismatch"));
                    }
                    Ok(())
                }))
                .build()
                .into_client()
                .context("failed to create client")?
        } else {
            RaClient::new(url, true)?
        };
        Ok(GatewayClient::new(client))
    }

    async fn sync_state(&self, url: &str, state: &GatewayState) -> Result<()> {
        info!("Trying to sync state to {url}");
        let rpc = self.create_rpc_client(url)?;
        tokio::time::timeout(self.timeout, rpc.update_state(state.clone()))
            .await
            .ok()
            .context("Timeout while syncing state")?
            .context("Failed to sync state")?;
        info!("Synced state to {url}");
        Ok(())
    }

    async fn sync_state_ignore_error(&self, url: &str, state: &GatewayState) -> bool {
        match self.sync_state(url, state).await {
            Ok(_) => true,
            Err(e) => {
                error!("Failed to sync state to {url}: {e:?}");
                false
            }
        }
    }
}

pub(crate) async fn sync_task(
    proxy: Weak<Mutex<ProxyState>>,
    config: Arc<Config>,
    mut event_rx: Receiver<SyncEvent>,
) -> Result<()> {
    let sync_client = if config.run_in_dstack {
        let agent = dstack_agent().context("Failed to create dstack agent client")?;
        let keys = agent
            .get_tls_key(GetTlsKeyArgs {
                subject: "dstack-gateway-sync-client".into(),
                alt_names: vec![],
                usage_ra_tls: false,
                usage_server_auth: false,
                usage_client_auth: true,
            })
            .await
            .context("Failed to get sync-client keys")?;
        let my_app_id = agent
            .info()
            .await
            .context("Failed to get guest info")?
            .app_id;
        SyncClient {
            in_dstack: true,
            cert_pem: keys.certificate_chain.join("\n"),
            key_pem: keys.key,
            ca_cert_pem: keys.certificate_chain.last().cloned().unwrap_or_default(),
            app_id: my_app_id,
            timeout: config.sync.timeout,
            pccs_url: config.pccs_url.clone(),
        }
    } else {
        SyncClient {
            in_dstack: false,
            cert_pem: "".into(),
            key_pem: "".into(),
            ca_cert_pem: "".into(),
            app_id: vec![],
            timeout: config.sync.timeout,
            pccs_url: config.pccs_url.clone(),
        }
    };

    let mut last_broadcast_time = Instant::now();
    let mut broadcast = false;
    loop {
        if broadcast {
            last_broadcast_time = Instant::now();
        }

        let Some(proxy) = proxy.upgrade() else {
            info!("Proxy state was dropped, stopping sync task");
            break;
        };

        let (mut nodes, apps) = proxy.lock().unwrap().dump_state();
        // Sort nodes by pubkey
        nodes.sort_by(|a, b| a.id.cmp(&b.id));

        let self_idx = nodes
            .iter()
            .position(|n| n.wg_peer.pk == config.wg.public_key)
            .unwrap_or(0);

        let state = GatewayState {
            nodes: nodes.into_iter().map(|n| n.into()).collect(),
            apps: apps.into_iter().map(|a| a.into()).collect(),
        };

        if state.nodes.is_empty() {
            // If no nodes exist yet, sync with bootnode
            sync_client
                .sync_state_ignore_error(&config.sync.bootnode, &state)
                .await;
        } else {
            let nodes = &state.nodes;
            // Try nodes after self, wrapping around to beginning
            let mut success = false;
            for i in 1..nodes.len() {
                let idx = (self_idx + i) % nodes.len();
                if sync_client
                    .sync_state_ignore_error(&nodes[idx].url, &state)
                    .await
                {
                    success = true;
                    if !broadcast {
                        break;
                    }
                }
            }

            // If no node succeeded, try bootnode as fallback
            if !success {
                info!("Fallback to sync with bootnode");
                sync_client
                    .sync_state_ignore_error(&config.sync.bootnode, &state)
                    .await;
            }
        }

        tokio::select! {
            event = event_rx.recv() => {
                let Some(event) = event else {
                    info!("Event channel closed, stopping sync task");
                    break;
                };
                match event {
                    SyncEvent::Broadcast => {
                        broadcast = true;
                    }
                }
            }
            _ = tokio::time::sleep(config.sync.interval) => {
                broadcast = last_broadcast_time.elapsed() >= config.sync.broadcast_interval;
            }
        }
    }
    Ok(())
}
