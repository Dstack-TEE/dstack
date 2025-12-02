// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV sync HTTP endpoints
//!
//! Sync data is encoded using bincode + gzip compression for efficiency.

use crate::main_service::Proxy;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use ra_tls::traits::CertExt;
use rocket::{
    data::{Data, ToByteUnit},
    http::{ContentType, Status},
    mtls::{oid::Oid, Certificate},
    post, State,
};
use std::io::{Read, Write};
use tracing::warn;
use wavekv::sync::{SyncMessage, SyncResponse};

/// Wrapper to implement CertExt for Rocket's Certificate
struct RocketCert<'a>(&'a Certificate<'a>);

impl CertExt for RocketCert<'_> {
    fn get_extension_der(&self, oid: &[u64]) -> anyhow::Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid).map_err(|_| anyhow::anyhow!("failed to create OID from slice"))?;
        let Some(ext) = self.0.extensions().iter().find(|ext| ext.oid == oid) else {
            return Ok(None);
        };
        Ok(Some(ext.value.to_vec()))
    }
}

/// Decode compressed bincode data
fn decode_sync_message(data: &[u8]) -> Result<SyncMessage, Status> {
    // Decompress
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        warn!("failed to decompress sync message: {e}");
        Status::BadRequest
    })?;

    // Decode bincode
    let config = bincode::config::standard();
    bincode::serde::decode_from_slice(&decompressed, config)
        .map(|(msg, _)| msg)
        .map_err(|e| {
            warn!("failed to decode sync message: {e}");
            Status::BadRequest
        })
}

/// Encode and compress sync response
fn encode_sync_response(response: &SyncResponse) -> Result<Vec<u8>, Status> {
    // Encode to bincode
    let config = bincode::config::standard();
    let encoded = bincode::serde::encode_to_vec(response, config).map_err(|e| {
        warn!("failed to encode sync response: {e}");
        Status::InternalServerError
    })?;

    // Compress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&encoded).map_err(|e| {
        warn!("failed to compress sync response: {e}");
        Status::InternalServerError
    })?;
    encoder.finish().map_err(|e| {
        warn!("failed to finish compression: {e}");
        Status::InternalServerError
    })
}

/// Verify that the request is from a gateway with the same app_id (mTLS verification)
fn verify_gateway_peer(state: &Proxy, cert: Option<Certificate<'_>>) -> Result<(), Status> {
    // Skip verification if not running in dstack (test mode)
    if state.config.debug.insecure_skip_attestation {
        return Ok(());
    }

    let Some(cert) = cert else {
        warn!("WaveKV sync: client certificate required but not provided");
        return Err(Status::Unauthorized);
    };

    let remote_app_id = RocketCert(&cert).get_app_id().map_err(|e| {
        warn!("WaveKV sync: failed to extract app_id from certificate: {e}");
        Status::Unauthorized
    })?;

    let Some(remote_app_id) = remote_app_id else {
        warn!("WaveKV sync: certificate does not contain app_id");
        return Err(Status::Unauthorized);
    };

    if state.my_app_id() != Some(remote_app_id.as_slice()) {
        warn!(
            "WaveKV sync: app_id mismatch, expected {:?}, got {:?}",
            state.my_app_id(),
            remote_app_id
        );
        return Err(Status::Forbidden);
    }

    Ok(())
}

/// Handle sync request (bincode + gzip encoded)
#[post("/wavekv/sync/<store>", data = "<data>")]
pub async fn sync_store(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    store: &str,
    data: Data<'_>,
) -> Result<(ContentType, Vec<u8>), Status> {
    verify_gateway_peer(state, cert)?;

    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    // Read and decode request
    let bytes = data
        .open(16.mebibytes())
        .into_bytes()
        .await
        .map_err(|_| Status::BadRequest)?;
    let msg = decode_sync_message(&bytes)?;

    // Reject sync from node_id == 0
    if msg.sender_id == 0 {
        warn!("rejected sync from invalid node_id 0");
        return Err(Status::BadRequest);
    }

    // Handle sync based on store type
    let response = match store {
        "persistent" => wavekv_sync.handle_persistent_sync(msg),
        "ephemeral" => wavekv_sync.handle_ephemeral_sync(msg),
        _ => return Err(Status::NotFound),
    }
    .map_err(|e| {
        tracing::error!("{store} sync failed: {e}");
        Status::InternalServerError
    })?;

    // Encode response
    let encoded = encode_sync_response(&response)?;

    Ok((ContentType::new("application", "x-bincode-gz"), encoded))
}
