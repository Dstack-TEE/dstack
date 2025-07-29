use anyhow::{bail, Context, Result};
use host_api::{
    host_api_server::{HostApiRpc, HostApiServer},
    GetSealingKeyRequest, GetSealingKeyResponse, HostInfo, Notification,
};
use ra_rpc::{CallContext, RemoteEndpoint, RpcCall};
use rocket_vsock_listener::VsockEndpoint;

use crate::app::App;
use key_provider_client::host::get_key;

pub struct HostApiHandler {
    endpoint: VsockEndpoint,
    app: App,
}

impl RpcCall<App> for HostApiHandler {
    type PrpcService = HostApiServer<Self>;

    fn construct(context: CallContext<'_, App>) -> Result<Self> {
        let Some(RemoteEndpoint::Vsock { cid, port }) = context.remote_endpoint else {
            bail!("invalid remote endpoint: {:?}", context.remote_endpoint);
        };
        Ok(Self {
            endpoint: VsockEndpoint { cid, port },
            app: context.state.clone(),
        })
    }
}

impl HostApiRpc for HostApiHandler {
    async fn info(self) -> Result<HostInfo> {
        let host_info = HostInfo {
            name: "dstack VMM".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        Ok(host_info)
    }

    async fn notify(self, request: Notification) -> Result<()> {
        self.app
            .vm_event_report(self.endpoint.cid, &request.event, request.payload)
    }

    async fn get_sealing_key(self, request: GetSealingKeyRequest) -> Result<GetSealingKeyResponse> {
        let key_provider = &self.app.config.key_provider;
        if !key_provider.enabled {
            bail!("Key provider is not enabled");
        }
        let response = get_key(request.quote, key_provider.address, key_provider.port)
            .await
            .context("Failed to get sealing key from key provider")?;

        Ok(GetSealingKeyResponse {
            encrypted_key: response.encrypted_key,
            provider_quote: response.provider_quote,
        })
    }
}
