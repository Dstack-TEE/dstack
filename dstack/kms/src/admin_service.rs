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
    ActivateEpochRequest, ActivateEpochResponse, AuthorizeReshareRequest, AuthorizeReshareResponse,
    ClearImageCacheRequest, PrepareReshareRequest, PrepareReshareResponse,
    SignEpochManifestRequest, SignEpochManifestResponse,
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

    async fn prepare_reshare(
        self,
        request: PrepareReshareRequest,
    ) -> Result<PrepareReshareResponse> {
        let plan =
            serde_json::from_slice(&request.plan_json).context("invalid reshare plan JSON")?;
        let commitments = self.state.key_backend().prepare_reshare(plan).await?;
        Ok(PrepareReshareResponse {
            commitments_json: serde_jcs::to_vec(&commitments)
                .context("failed to encode reshare commitments")?,
        })
    }

    async fn activate_epoch(self, request: ActivateEpochRequest) -> Result<ActivateEpochResponse> {
        let signed = serde_json::from_slice(&request.signed_manifest_json)
            .context("invalid signed epoch manifest JSON")?;
        let retained = self.state.key_backend().activate_epoch(signed).await?;
        self.state.request_restart();
        Ok(ActivateEpochResponse { retained })
    }

    async fn authorize_reshare(
        self,
        request: AuthorizeReshareRequest,
    ) -> Result<AuthorizeReshareResponse> {
        let plan =
            serde_json::from_slice(&request.plan_json).context("invalid reshare plan JSON")?;
        let signed = self.state.key_backend().authorize_reshare(plan).await?;
        Ok(AuthorizeReshareResponse {
            signed_plan_json: serde_jcs::to_vec(&signed)
                .context("failed to encode signed reshare authorization")?,
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
