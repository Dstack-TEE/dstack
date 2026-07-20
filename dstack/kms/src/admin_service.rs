// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! KMS admin RPC service, served on the `[core.admin]` listener behind the
//! shared HTTP authenticator. Callers are authenticated by the admin token /
//! htpasswd via `Authorization`/`X-Admin-Token`, so the handlers do no token
//! checks of their own.

use anyhow::Result;
use dstack_kms_rpc::{
    admin_server::{AdminRpc, AdminServer},
    ClearImageCacheRequest,
};
use ra_rpc::{CallContext, RpcCall};

use crate::main_service::KmsState;

pub struct AdminRpcHandler {
    state: KmsState,
}

impl AdminRpc for AdminRpcHandler {
    async fn clear_image_cache(self, request: ClearImageCacheRequest) -> Result<()> {
        self.state
            .clear_image_cache(&request.image_hash, &request.config_hash)
    }
}

impl RpcCall<KmsState> for AdminRpcHandler {
    type PrpcService = AdminServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        Ok(AdminRpcHandler {
            state: context.state.clone(),
        })
    }
}
