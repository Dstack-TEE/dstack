// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV sync HTTP endpoints
//!
//! Sync data is encoded using msgpack + gzip compression for efficiency.

use crate::{
    kv::{decode, encode},
    main_service::Proxy,
};
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
use wavekv::sync::{SyncEnvelope, SyncMessage, SyncResponse};

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

/// Decode compressed msgpack data
fn decode_sync_message(data: &[u8]) -> Result<SyncMessage, Status> {
    // Decompress
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        warn!("failed to decompress sync message: {e}");
        Status::BadRequest
    })?;

    decode(&decompressed).map_err(|e| {
        warn!("failed to decode sync message: {e}");
        Status::BadRequest
    })
}

/// Encode and compress sync response
fn encode_sync_response(response: &SyncResponse) -> Result<Vec<u8>, Status> {
    let encoded = encode(response).map_err(|e| {
        warn!("failed to encode sync response: {e}");
        Status::InternalServerError
    })?;
    gzip(&encoded)
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, Status> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).map_err(|e| {
        warn!("failed to compress sync response: {e}");
        Status::InternalServerError
    })?;
    encoder.finish().map_err(|e| {
        warn!("failed to finish compression: {e}");
        Status::InternalServerError
    })
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, Status> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        warn!("failed to decompress sync payload: {e}");
        Status::BadRequest
    })?;
    Ok(decompressed)
}

/// Read a v2 envelope from a request body, applying the same size cap as the v1 route.
async fn read_envelope(data: Data<'_>) -> Result<SyncEnvelope, Status> {
    let bytes = data
        .open(16.mebibytes())
        .into_bytes()
        .await
        .map_err(|_| Status::BadRequest)?;
    let decompressed = gunzip(&bytes)?;
    // `SyncEnvelope::decode` enforces the schema version and rejects trailing bytes;
    // it is deliberately not the generic `decode` used for KV values.
    SyncEnvelope::decode(&decompressed).map_err(|e| {
        warn!("failed to decode sync envelope: {e:#}");
        Status::BadRequest
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

    let cert = RocketCert(&cert);
    let remote_app_id = match cert.get_app_id().map_err(|e| {
        warn!("WaveKV sync: failed to extract app_id from certificate: {e}");
        Status::Unauthorized
    })? {
        Some(app_id) => Some(app_id),
        None => cert
            .get_app_info()
            .map_err(|e| {
                warn!("WaveKV sync: failed to extract app_info from certificate: {e}");
                Status::Unauthorized
            })?
            .map(|info| info.app_id),
    };

    let Some(remote_app_id) = remote_app_id else {
        warn!("WaveKV sync: certificate does not contain app identity");
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

/// Handle sync request (msgpack + gzip encoded)
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

    Ok((ContentType::new("application", "x-msgpack-gz"), encoded))
}

/// Native v2 sync endpoint.
///
/// A gateway still running wavekv 1.x has no route here and answers 404, which is
/// exactly the signal its peers use to fall back to `/wavekv/sync`. Mounting this route
/// is therefore the whole of the server-side protocol negotiation.
#[post("/wavekv/sync2/<store>", data = "<data>")]
pub async fn sync_store_v2(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    store: &str,
    data: Data<'_>,
) -> Result<(ContentType, Vec<u8>), Status> {
    verify_gateway_peer(state, cert)?;

    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    let env = read_envelope(data).await?;
    if env.sender_id == 0 {
        warn!("rejected v2 sync from invalid node_id 0");
        return Err(Status::BadRequest);
    }

    let Some(result) = wavekv_sync.handle_envelope(store, env) else {
        return Err(Status::NotFound);
    };
    let response = result.map_err(|e| {
        tracing::error!("{store} v2 sync failed: {e:#}");
        Status::InternalServerError
    })?;

    let encoded = response.encode().map_err(|e| {
        warn!("failed to encode sync envelope: {e:#}");
        Status::InternalServerError
    })?;
    Ok((
        ContentType::new("application", "x-msgpack-gz"),
        gzip(&encoded)?,
    ))
}

/// Opportunistic push endpoint (wavekv RFC 0001 section 3.9).
///
/// Entries only: the receiver merges data but never moves its ack coverage from this
/// channel, so loss, duplication and reordering here are all harmless and the periodic
/// round remains the anti-entropy backstop.
#[post("/wavekv/push/<store>", data = "<data>")]
pub async fn push_store(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    store: &str,
    data: Data<'_>,
) -> Result<Status, Status> {
    verify_gateway_peer(state, cert)?;

    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    let env = read_envelope(data).await?;
    if env.sender_id == 0 {
        warn!("rejected push from invalid node_id 0");
        return Err(Status::BadRequest);
    }

    let Some(result) = wavekv_sync.handle_push(store, env) else {
        return Err(Status::NotFound);
    };
    result.map_err(|e| {
        tracing::error!("{store} push failed: {e:#}");
        Status::InternalServerError
    })?;
    Ok(Status::Ok)
}
