// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_kms_rpc::{
    mpc_transport_server::{MpcTransportRpc, MpcTransportServer},
    MpcPollRequest, MpcPollResponse, MpcPushRequest,
};
use ra_rpc::{CallContext, RpcCall};

use crate::{main_service::KmsState, mpc_session::MpcEnvelope};

pub(crate) struct MpcHandler {
    state: KmsState,
    peer_public_key: Vec<u8>,
}

impl RpcCall<KmsState> for MpcHandler {
    type PrpcService = MpcTransportServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        context
            .attestation
            .context("MPC transport requires an attested RA-TLS peer")?;
        let peer_public_key = context
            .remote_public_key
            .context("MPC transport peer certificate is missing")?;
        Ok(Self {
            state: context.state.clone(),
            peer_public_key,
        })
    }
}

impl MpcHandler {
    fn peer_and_router(&self) -> Result<(&str, &crate::mpc_session::SessionRouter)> {
        let router = self.state.mpc_router().context("MPC mode is not enabled")?;
        let node_id = router.authenticated_node_id(&self.peer_public_key)?;
        Ok((node_id, router))
    }
}

impl MpcTransportRpc for MpcHandler {
    async fn push(self, request: MpcPushRequest) -> Result<()> {
        let envelope: MpcEnvelope = serde_json::from_slice(&request.envelope_json)
            .context("invalid MPC envelope encoding")?;
        let (node_id, router) = self.peer_and_router()?;
        router.push(node_id, envelope)
    }

    async fn poll(self, request: MpcPollRequest) -> Result<MpcPollResponse> {
        let (node_id, router) = self.peer_and_router()?;
        let envelope_json = router
            .drain(node_id, &request.session_id)?
            .into_iter()
            .map(|envelope| serde_json::to_vec(&envelope).context("failed to encode MPC envelope"))
            .collect::<Result<Vec<_>>>()?;
        Ok(MpcPollResponse { envelope_json })
    }
}

pub(crate) fn rpc_methods() -> &'static [&'static str] {
    <MpcTransportServer<MpcHandler>>::supported_methods()
}
