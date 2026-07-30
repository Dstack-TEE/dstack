// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! KMS admin RPC service, served on the `[core.admin]` listener behind the
//! shared HTTP authenticator. Callers are authenticated by the admin token /
//! htpasswd via `Authorization`/`X-Admin-Token`, so the handlers do no token
//! checks of their own.

use anyhow::{Context, Result};
use dstack_kms_rpc::{
    admin_server::{AdminRpc, AdminServer},
    ClearImageCacheRequest, SignEpochManifestRequest, SignEpochManifestResponse,
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

    async fn sign_epoch_manifest(
        self,
        request: SignEpochManifestRequest,
    ) -> Result<SignEpochManifestResponse> {
        let manifest = serde_json::from_slice(&request.manifest_json)
            .context("invalid epoch manifest JSON")?;
        let signed = self
            .state
            .key_backend()
            .sign_epoch_manifest(manifest)
            .await?;
        Ok(SignEpochManifestResponse {
            signed_manifest_json: serde_jcs::to_vec(&signed)
                .context("failed to encode signed epoch manifest")?,
        })
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
