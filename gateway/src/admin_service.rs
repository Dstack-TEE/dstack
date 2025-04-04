use anyhow::{Context, Result};
use dstack_gateway_rpc::{
    admin_server::{AdminRpc, AdminServer},
    RenewCertResponse,
};
use ra_rpc::{CallContext, RpcCall};

use crate::main_service::Proxy;

pub struct AdminRpcHandler {
    state: Proxy,
}

impl AdminRpc for AdminRpcHandler {
    async fn exit(self) -> Result<()> {
        self.state.lock().exit();
    }

    async fn renew_cert(self) -> Result<RenewCertResponse> {
        let bot = self.state.certbot.context("Certbot is not enabled")?;
        let renewed = bot.renew(true).await?;
        Ok(RenewCertResponse { renewed })
    }

    async fn set_caa(self) -> Result<()> {
        let bot = self.state.certbot.context("Certbot is not enabled")?;
        bot.set_caa().await?;
        Ok(())
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
