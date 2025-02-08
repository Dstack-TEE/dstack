use anyhow::Result;
use ra_rpc::{CallContext, RpcCall};
use tproxy_rpc::tproxy_admin_server::{TproxyAdminRpc, TproxyAdminServer};

use crate::main_service::Proxy;

pub struct AdminRpcHandler {
    state: Proxy,
}

impl TproxyAdminRpc for AdminRpcHandler {
    async fn exit(self) -> Result<()> {
        self.state.lock().exit();
    }
}

impl RpcCall<Proxy> for AdminRpcHandler {
    type PrpcService = TproxyAdminServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(AdminRpcHandler {
            state: context.state.clone(),
        })
    }
}
