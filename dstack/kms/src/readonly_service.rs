// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The read-only KMS RPCs, served on the `[listeners.public]` listener.

use anyhow::Result;
use dstack_kms_rpc::{
    kms_server::KmsRpc,
    read_only_server::{ReadOnlyRpc, ReadOnlyServer},
    AppId, GetMetaResponse, PublicKeyResponse, SealedEnvPubKeyResponse,
};
use ra_rpc::{CallContext, RpcCall};

use crate::main_service::{KmsState, RpcHandler};

pub struct ReadOnlyRpcHandler(RpcHandler);

impl ReadOnlyRpc for ReadOnlyRpcHandler {
    async fn get_meta(self) -> Result<GetMetaResponse> {
        self.0.get_meta().await
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        self.0.get_app_env_encrypt_pub_key(request).await
    }

    async fn get_sealed_env_pub_key(self, request: AppId) -> Result<SealedEnvPubKeyResponse> {
        self.0.get_sealed_env_pub_key(request).await
    }
}

impl RpcCall<KmsState> for ReadOnlyRpcHandler {
    type PrpcService = ReadOnlyServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        Ok(Self(RpcHandler::from_context(context)))
    }
}
