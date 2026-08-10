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
    mtls::{oid::Oid, x509::X509Extension, Certificate},
    post, State,
};
use std::io::Write;
use tracing::warn;
use wavekv::sync::{SyncMessage, SyncResponse};

/// Adapter implementing `CertExt` over a parsed certificate's extension list.
///
/// It holds the extensions rather than the `Certificate` so that a test can build one:
/// `rocket::mtls::Certificate` has no public constructor — it can only be produced by a
/// real mTLS handshake — while an extension list comes straight out of `X509Certificate`.
struct RocketCert<'a, 'b>(&'b [X509Extension<'a>]);

impl CertExt for RocketCert<'_, '_> {
    fn get_extension_der(&self, oid: &[u64]) -> anyhow::Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid).map_err(|_| anyhow::anyhow!("failed to create OID from slice"))?;
        let Some(ext) = self.0.iter().find(|ext| ext.oid == oid) else {
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

    authorize_peer(&RocketCert(cert.extensions()), state.my_app_id())
}

/// Decide whether a certificate's app identity is one we accept.
///
/// Split out from `verify_gateway_peer` because that function's other half — the
/// attestation bypass and Rocket's certificate guard — cannot be exercised from a test,
/// which left this decision, the actual authorization rule, uncovered.
fn authorize_peer(cert: &impl CertExt, my_app_id: Option<&[u8]>) -> Result<(), Status> {
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

    if my_app_id != Some(remote_app_id.as_slice()) {
        warn!("WaveKV sync: app_id mismatch, expected {my_app_id:?}, got {remote_app_id:?}");
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
    /// `insecure_skip_attestation` is on, which makes `verify_gateway_peer` return
    /// immediately: these tests are about everything below it — route dispatch, the gzip
    /// framing, the store split. `enforcing_gateway` covers the gate itself, which this
    /// fixture cannot, because Rocket's local client speaks no TLS and so can never
    /// present a certificate.
    async fn serving_gateway(sync_enabled: bool) -> (Client, Proxy, TempDir) {
        serving_gateway_with(sync_enabled, true).await
    }

    /// The same gateway with the attestation bypass switched off, so the peer check runs
    /// for real.
    async fn enforcing_gateway() -> (Client, Proxy, TempDir) {
        serving_gateway_with(true, false).await
    }

    async fn serving_gateway_with(
        sync_enabled: bool,
        skip_attestation: bool,
    ) -> (Client, Proxy, TempDir) {
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
        config.debug.insecure_skip_attestation = skip_attestation;

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

    /// The sync route is the cluster's write surface: anything that reaches it can
    /// insert entries that replicate to every gateway. `verify_gateway_peer` is the only
    /// thing standing in front of it, and with `insecure_skip_attestation` set — which
    /// every other test here sets — its first statement returns `Ok(())`, so the gate
    /// itself was never executed by any test. Replacing the whole function body with
    /// `Ok(())` did not turn the suite red.
    ///
    /// Rocket's local client speaks no TLS and so presents no certificate, which is
    /// exactly the case that must be refused.
    #[tokio::test]
    async fn the_sync_route_refuses_a_peer_it_cannot_identify() {
        let (client, _proxy, _tmp) = enforcing_gateway().await;

        let response = client
            .post("/wavekv/sync/persistent")
            .body(Vec::new())
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Unauthorized,
            "the sync route served a request from an unauthenticated caller"
        );
    }

    /// A real certificate carrying `PHALA_RATLS_APP_ID`, minted locally.
    ///
    /// Nothing here needs a TEE: the extension is an ordinary X.509 extension that
    /// `CertRequest` adds unconditionally, and the check under test never looks at a
    /// quote — it reads two extensions and compares bytes.
    fn cert_with_app_id(app_id: &[u8]) -> Vec<u8> {
        use ra_tls::cert::CertRequest;
        use ra_tls::rcgen::KeyPair;

        let key = KeyPair::generate().expect("key");
        let cert = CertRequest::builder()
            .key(&key)
            .subject("peer.test")
            .app_id(app_id)
            .build()
            .self_signed()
            .expect("self-signed cert");
        cert.der().to_vec()
    }

    /// A certificate with no app identity at all.
    fn cert_without_app_id() -> Vec<u8> {
        use ra_tls::cert::CertRequest;
        use ra_tls::rcgen::KeyPair;

        let key = KeyPair::generate().expect("key");
        let cert = CertRequest::builder()
            .key(&key)
            .subject("peer.test")
            .build()
            .self_signed()
            .expect("self-signed cert");
        cert.der().to_vec()
    }

    fn authorize(der: &[u8], my_app_id: Option<&[u8]>) -> Result<(), Status> {
        use rocket::mtls::x509::{FromDer, X509Certificate};
        let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
        authorize_peer(&RocketCert(parsed.extensions()), my_app_id)
    }

    /// The rule the sync route is defended by: same app id or nothing.
    ///
    /// Every case below was previously unreachable, because the only tests that touched
    /// this code set `insecure_skip_attestation` and returned before it. Inverting the
    /// comparison to `==` left the suite green.
    #[test]
    fn a_peer_is_authorized_only_when_its_app_id_matches_ours() {
        let ours = b"app-id-of-this-cluster".to_vec();

        assert_eq!(authorize(&cert_with_app_id(&ours), Some(&ours)), Ok(()));

        assert_eq!(
            authorize(&cert_with_app_id(b"a-different-app"), Some(&ours)),
            Err(Status::Forbidden),
            "a valid certificate from another app must not reach the sync route"
        );
    }

    /// A certificate that proves nothing about which app presented it is refused, rather
    /// than falling through to a comparison against `None`.
    #[test]
    fn a_certificate_without_an_app_id_is_refused() {
        assert_eq!(
            authorize(&cert_without_app_id(), Some(b"app-id-of-this-cluster")),
            Err(Status::Unauthorized)
        );
    }

    /// A gateway that does not know its own app id cannot authorize anyone. Comparing
    /// `None` against a present remote id must reject, never match.
    #[test]
    fn a_gateway_without_an_app_id_authorizes_nobody() {
        assert_eq!(
            authorize(&cert_with_app_id(b"anything"), None),
            Err(Status::Forbidden)
        );
    }

    /// The adapter must match the app-id extension by OID and no other. Returning some
    /// other extension's bytes would hand `authorize_peer` a value it would happily
    /// compare.
    #[test]
    fn the_adapter_reads_the_app_id_extension_and_not_a_neighbour() {
        use ra_tls::traits::CertExt;
        use rocket::mtls::x509::{FromDer, X509Certificate};

        let der = cert_with_app_id(b"the-app-id");
        let (_, parsed) = X509Certificate::from_der(&der).expect("parse cert");
        let adapter = RocketCert(parsed.extensions());

        assert_eq!(
            adapter.get_app_id().expect("read app id"),
            Some(b"the-app-id".to_vec())
        );
        assert_eq!(
            adapter.get_special_usage().expect("read special usage"),
            None,
            "an extension that was never set must read back as absent"
        );
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
