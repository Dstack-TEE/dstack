// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV sync HTTP endpoints
//!
//! Sync data is encoded using msgpack + gzip compression for efficiency.

use crate::{
    kv::{decode, encode, gunzip_bounded, MAX_DECOMPRESSED_SYNC_BYTES},
    main_service::Proxy,
};
use flate2::{write::GzEncoder, Compression};
use ra_tls::traits::CertExt;
use rocket::{
    data::{Data, ToByteUnit},
    http::{ContentType, Status},
    mtls::{oid::Oid, Certificate},
    post, State,
};
use std::io::Write;
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

/// Decode compressed msgpack data
fn decode_sync_message(data: &[u8]) -> Result<SyncMessage, Status> {
    let decompressed = gunzip_bounded(data, MAX_DECOMPRESSED_SYNC_BYTES).map_err(|e| {
        warn!("failed to decompress sync message: {e:#}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_config_figment, Config, MutualConfig, TlsConfig};
    use crate::kv::NodeData;
    use crate::main_service::{Proxy, ProxyOptions};
    use rocket::local::asynchronous::Client;
    use tempfile::TempDir;

    const ME: u32 = 1;
    const PEER: u32 = 2;

    fn peer_uuid() -> Vec<u8> {
        b"the-real-peer-2".to_vec()
    }

    /// A self-signed CA plus a leaf it signs. `HttpSyncNetwork::new` loads all three
    /// from disk to build its rustls client config, and the root store only accepts a
    /// trust anchor with `CA:TRUE` — so a lone self-signed leaf is not enough.
    fn write_tls_material(dir: &std::path::Path) -> TlsConfig {
        use ra_tls::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params =
            CertificateParams::new(vec!["gateway.test".to_string()]).expect("leaf params");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf cert");

        let cert_path = dir.join("node.crt");
        let key_path = dir.join("node.key");
        let ca_path = dir.join("ca.crt");
        std::fs::write(&cert_path, leaf_cert.pem()).expect("write cert");
        std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write key");
        std::fs::write(&ca_path, ca_cert.pem()).expect("write ca");

        TlsConfig {
            certs: cert_path.to_string_lossy().into_owned(),
            key: key_path.to_string_lossy().into_owned(),
            mutual: MutualConfig {
                ca_certs: ca_path.to_string_lossy().into_owned(),
            },
        }
    }

    /// A gateway serving the real sync route over Rocket's local client.
    ///
    /// `insecure_skip_attestation` stands in for the mTLS peer check, which is not what
    /// these tests are about; everything below it — route dispatch, the gzip framing,
    /// the store split — is the production path.
    async fn serving_gateway(sync_enabled: bool) -> (Client, Proxy, TempDir) {
        // `main` installs this once at startup; the sync client builds a rustls config,
        // so a test that skips it panics inside rustls rather than failing an assertion.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let figment = load_config_figment(None);
        let mut config = figment.focus("core").extract::<Config>().unwrap();
        let temp_dir = TempDir::new().expect("temp dir");

        config.sync.enabled = sync_enabled;
        config.sync.node_id = ME;
        config.sync.bootnode = String::new();
        config.sync.data_dir = temp_dir.path().to_string_lossy().into_owned();
        config.wg.config_path = temp_dir
            .path()
            .join("wg.conf")
            .to_string_lossy()
            .into_owned();
        config.debug.insecure_skip_attestation = true;

        let tls_config = write_tls_material(temp_dir.path());
        let proxy = Proxy::new(ProxyOptions {
            config,
            my_app_id: None,
            tls_config,
        })
        .await
        .expect("failed to build gateway");

        let rocket = rocket::build()
            .manage(proxy.clone())
            .mount("/", crate::web_routes::wavekv_sync_routes());
        let client = Client::tracked(rocket).await.expect("rocket client");
        (client, proxy, temp_dir)
    }

    /// Register the peer so `query_uuid` returns something: the uuid check is opt-in and
    /// an unknown sender bypasses it entirely.
    fn register_peer(proxy: &Proxy) {
        proxy
            .kv_store()
            .sync_node(
                PEER,
                &NodeData {
                    uuid: peer_uuid(),
                    url: "https://peer.test:8011".to_string(),
                    wg_public_key: String::new(),
                    wg_endpoint: String::new(),
                    wg_ip: String::new(),
                },
            )
            .expect("register peer");
    }

    /// The request framing the route expects: msgpack, then gzip.
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).expect("compress");
        encoder.finish().expect("finish")
    }

    fn sync_body(msg: &SyncMessage) -> Vec<u8> {
        gzip(&encode(msg).expect("encode sync message"))
    }

    fn sync_request() -> SyncMessage {
        SyncMessage {
            sender_id: PEER,
            sender_uuid: peer_uuid(),
            // Empty coverage, so the route answers with everything it holds.
            sender_ack: Default::default(),
            entries: Vec::new(),
        }
    }

    /// Nothing exercised the sync route end to end: the store dispatch could be deleted,
    /// the node-id-zero guard inverted, and the response body replaced with three bytes,
    /// all without turning the suite red.
    #[tokio::test]
    async fn a_sync_round_trip_serves_the_state_this_node_holds() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);
        proxy
            .kv_store()
            .persistent()
            .write()
            .put("node/7".to_string(), b"v".to_vec())
            .expect("seed");

        let response = client
            .post("/wavekv/sync/persistent")
            .body(sync_body(&sync_request()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let bytes = response.into_bytes().await.expect("body");
        let decoded: SyncResponse =
            decode(&gunzip_bounded(&bytes, MAX_DECOMPRESSED_SYNC_BYTES).expect("gunzip"))
                .expect("decode sync response");

        assert_eq!(decoded.peer_id, ME);
        assert!(
            decoded.entries.iter().any(|e| e.key == "node/7"),
            "a peer with no coverage must receive the state this node holds"
        );
    }

    /// Both stores are reachable over the route. The ephemeral arm carries the liveness
    /// data a stale peer needs most.
    #[tokio::test]
    async fn the_route_serves_the_ephemeral_store_as_well() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let response = client
            .post("/wavekv/sync/ephemeral")
            .body(sync_body(&sync_request()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
    }

    /// Node id 0 is the unset value, so an entry authored by it collides with every
    /// other unset sender.
    #[tokio::test]
    async fn a_sync_from_node_id_zero_is_refused() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let mut msg = sync_request();
        msg.sender_id = 0;
        let response = client
            .post("/wavekv/sync/persistent")
            .body(sync_body(&msg))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    /// A node with sync switched off answers 503 — an unavailable service, not a missing
    /// route. The distinction is load-bearing for a caller deciding whether the peer is
    /// down or simply does not have this endpoint.
    #[tokio::test]
    async fn a_sync_disabled_node_answers_503_rather_than_404() {
        let (client, _proxy, _tmp) = serving_gateway(false).await;

        let response = client
            .post("/wavekv/sync/persistent")
            .body(sync_body(&sync_request()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::ServiceUnavailable);
    }

    /// An unknown store is a 404 rather than a 500 or a silent success.
    #[tokio::test]
    async fn an_unknown_store_is_a_404() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let response = client
            .post("/wavekv/sync/nonesuch")
            .body(sync_body(&sync_request()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
    }

    /// gzip expands by three orders of magnitude on attacker-chosen input, so the
    /// 16 MiB cap on the request body bounds the *compressed* size and nothing else.
    /// The RA-TLS gate proves only that the sender is some gateway of this deployment.
    #[tokio::test]
    async fn a_compression_bomb_is_refused_before_it_is_decompressed() {
        let (client, _proxy, _tmp) = serving_gateway(true).await;

        // ~128 MiB of zeroes compresses to well under the request cap.
        let bomb = gzip(&vec![0u8; MAX_DECOMPRESSED_SYNC_BYTES + 1]);
        assert!(
            bomb.len() < 16 * 1024 * 1024,
            "the fixture has to fit through the body cap to be testing anything: {} bytes",
            bomb.len()
        );

        let response = client
            .post("/wavekv/sync/persistent")
            .body(bomb)
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::BadRequest,
            "the route must refuse an over-sized expansion"
        );
    }

    /// The limits have to admit the largest message the protocol can produce, or they
    /// would reject ordinary sync traffic rather than a bomb.
    #[test]
    fn the_sync_limits_admit_the_largest_message_the_protocol_can_produce() {
        // A sync response carries the whole live state of one store.
        assert!(
            MAX_DECOMPRESSED_SYNC_BYTES >= 32 * 1024 * 1024,
            "a decompression limit of {MAX_DECOMPRESSED_SYNC_BYTES} bytes is too tight \
             for a full-state response"
        );

        // The compressed ceiling mirrors what the route accepts on a request, so a peer
        // cannot answer with more than it would have been allowed to ask.
        assert_eq!(
            crate::kv::MAX_COMPRESSED_SYNC_BYTES,
            16 * 1024 * 1024,
            "this must stay equal to the 16 MiB the route accepts on a request body"
        );
    }
}
