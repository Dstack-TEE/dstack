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
use wavekv::sync::{SyncEnvelope, SyncMessage, SyncResponse};

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
    gunzip_bounded(data, MAX_DECOMPRESSED_SYNC_BYTES).map_err(|e| {
        warn!("failed to decompress sync payload: {e:#}");
        Status::BadRequest
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_config_figment, Config, MutualConfig, TlsConfig};
    use crate::kv::NodeData;
    use crate::main_service::{Proxy, ProxyOptions};
    use rocket::local::asynchronous::Client;
    use tempfile::TempDir;
    use wavekv::types::{Entry, Metadata};

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

    /// A gateway serving the real sync routes over Rocket's local client.
    ///
    /// `insecure_skip_attestation` is on, which makes `verify_gateway_peer` return
    /// immediately: these tests are about everything below it — route dispatch, the gzip
    /// framing, the store split, the uuid check. `enforcing_gateway` covers the gate
    /// itself, which this fixture cannot, because Rocket's local client speaks no TLS
    /// and so can never present a certificate.
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

    /// The sync routes are the cluster's write surface: anything that reaches them can
    /// insert entries that replicate to every gateway. `verify_gateway_peer` is the only
    /// thing standing in front of them, and with `insecure_skip_attestation` set — which
    /// every other test here sets — its first statement returns `Ok(())`, so the gate
    /// itself was never executed by any test. Replacing the whole function body with
    /// `Ok(())` did not turn the suite red.
    ///
    /// Rocket's local client speaks no TLS and so presents no certificate, which is
    /// exactly the case that must be refused.
    #[tokio::test]
    async fn every_sync_route_refuses_a_peer_it_cannot_identify() {
        let (client, _proxy, _tmp) = enforcing_gateway().await;

        for route in [
            "/wavekv/sync/persistent",
            "/wavekv/sync2/persistent",
            "/wavekv/push/persistent",
        ] {
            let response = client.post(route).body(Vec::new()).dispatch().await;
            assert_eq!(
                response.status(),
                Status::Unauthorized,
                "{route} served a request from an unauthenticated caller"
            );
        }
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

    /// The rule the sync routes are defended by: same app id or nothing.
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
            "a valid certificate from another app must not reach the sync routes"
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

    fn push_envelope(uuid: Vec<u8>, key: &str) -> SyncEnvelope {
        let mut env = SyncEnvelope::new(PEER, uuid);
        env.push_only = true;
        env.entries.push(Entry::new(
            key.to_string(),
            Some(b"v".to_vec()),
            Metadata::new(PEER, 1, 1),
        ));
        env
    }

    fn body(env: &SyncEnvelope) -> Vec<u8> {
        gzip(&env.encode().expect("encode envelope")).expect("gzip")
    }

    #[tokio::test]
    async fn a_stamped_push_is_accepted_and_lands_in_the_store() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let response = client
            .post("/wavekv/push/persistent")
            .body(body(&push_envelope(peer_uuid(), "node/9")))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        assert!(
            proxy.kv_store().persistent().read().get("node/9").is_some(),
            "a well-formed push must reach the store"
        );
    }

    /// The route-level view of the bug that made every opportunistic push fail: the
    /// sender built its envelope without stamping `sender_uuid`, and the receiver's
    /// `check_uuid` — which only the manager runs, not `merge_push` — rejected it.
    #[tokio::test]
    async fn an_unstamped_push_is_refused_at_the_route() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let response = client
            .post("/wavekv/push/persistent")
            .body(body(&push_envelope(Vec::new(), "node/9")))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::InternalServerError);
        assert!(
            proxy.kv_store().persistent().read().get("node/9").is_none(),
            "a push that fails the identity check must not write anything"
        );
    }

    #[tokio::test]
    async fn a_v2_round_trip_returns_a_decodable_envelope() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);
        proxy
            .kv_store()
            .persistent()
            .write()
            .put("node/7".to_string(), b"v".to_vec())
            .expect("seed");

        let request = SyncEnvelope::new(PEER, peer_uuid());
        let response = client
            .post("/wavekv/sync2/persistent")
            .body(body(&request))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let bytes = response.into_bytes().await.expect("body");
        let decoded = SyncEnvelope::decode(&gunzip(&bytes).expect("gunzip")).expect("decode");
        assert_eq!(decoded.sender_id, ME);
        assert!(
            decoded.entries.iter().any(|e| e.key == "node/7"),
            "an empty ack map must draw the whole live state"
        );
    }

    /// 404 is the negotiation signal: it is what tells a peer "this node has no v2
    /// route, fall back to v1". Nothing else on these routes may produce it by accident.
    #[tokio::test]
    async fn an_unknown_store_is_a_404_because_that_is_the_v1_signal() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let response = client
            .post("/wavekv/sync2/bogus")
            .body(body(&SyncEnvelope::new(PEER, peer_uuid())))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NotFound);
    }

    fn v1_body(msg: &SyncMessage) -> Vec<u8> {
        gzip(&encode(msg).expect("encode v1 message")).expect("gzip")
    }

    fn v1_request() -> SyncMessage {
        SyncMessage {
            sender_id: PEER,
            sender_uuid: peer_uuid(),
            // Empty coverage, so the shim answers with everything it holds.
            sender_ack: Default::default(),
            entries: Vec::new(),
        }
    }

    /// The v1 shim is how a gateway that has not been upgraded still receives state, and
    /// nothing exercised it at the route level: the store dispatch could be deleted, the
    /// node-id-zero guard inverted, and the response body replaced with three bytes,
    /// all without turning the suite red.
    ///
    /// Deleting the `"persistent"` arm is the sharpest of those. It falls through to
    /// `_ => 404`, and a 404 on a sync route is precisely the signal a v2 peer reads as
    /// "this node does not speak that protocol" — so the failure would not look like an
    /// error, it would look like a successful protocol downgrade.
    #[tokio::test]
    async fn a_v1_round_trip_serves_the_state_this_node_holds() {
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
            .body(v1_body(&v1_request()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let bytes = response.into_bytes().await.expect("body");
        let decoded: SyncResponse =
            decode(&gunzip(&bytes).expect("gunzip")).expect("decode v1 response");

        assert_eq!(decoded.peer_id, ME);
        assert!(
            decoded.entries.iter().any(|e| e.key == "node/7"),
            "a peer with no coverage must receive the state this node holds"
        );
    }

    /// Both stores are reachable over the v1 route. The ephemeral arm carries the
    /// liveness data a stale peer needs most, and losing it would read as a downgrade
    /// rather than a fault, exactly as above.
    #[tokio::test]
    async fn the_v1_route_serves_the_ephemeral_store_as_well() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let response = client
            .post("/wavekv/sync/ephemeral")
            .body(v1_body(&v1_request()))
            .dispatch()
            .await;

        assert_eq!(
            response.status(),
            Status::Ok,
            "a 404 here would demote this node to no-such-route in the caller's cache"
        );
    }

    /// Node id 0 is the unset value, so an entry authored by it collides with every
    /// other unset sender. The v1 route rejects it, as the push and v2 routes do.
    #[tokio::test]
    async fn a_v1_sync_from_node_id_zero_is_refused() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let mut msg = v1_request();
        msg.sender_id = 0;
        let response = client
            .post("/wavekv/sync/persistent")
            .body(v1_body(&msg))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    /// ...which is why a node with sync switched off must answer 503 and not 404. A 404
    /// here would demote this node to v1 in every peer's cache for a whole reprobe
    /// window — silently, and without sync being on to fix it.
    #[tokio::test]
    async fn a_sync_disabled_node_answers_503_rather_than_404() {
        let (client, _proxy, _tmp) = serving_gateway(false).await;

        for path in [
            "/wavekv/sync/persistent",
            "/wavekv/sync2/persistent",
            "/wavekv/push/persistent",
        ] {
            let response = client
                .post(path)
                .body(body(&SyncEnvelope::new(PEER, peer_uuid())))
                .dispatch()
                .await;
            assert_eq!(
                response.status(),
                Status::ServiceUnavailable,
                "{path} must not look like a missing v2 route"
            );
        }
    }

    /// gzip expands by three orders of magnitude on attacker-chosen input, so the
    /// 16 MiB cap on the request body bounds the *compressed* size and nothing else.
    /// mTLS proves only that the sender is some gateway of this deployment, which is
    /// the same trust level the key schema already assumes is insufficient.
    #[tokio::test]
    async fn a_compression_bomb_is_refused_before_it_is_decompressed() {
        let (client, _proxy, _tmp) = serving_gateway(true).await;

        // ~130 MiB of zeroes compresses to well under the request cap.
        let bomb = gzip(&vec![0u8; MAX_DECOMPRESSED_SYNC_BYTES + 1]).expect("gzip");
        assert!(
            bomb.len() < 16 * 1024 * 1024,
            "the fixture has to fit through the body cap to be testing anything: {} bytes",
            bomb.len()
        );

        for path in [
            "/wavekv/sync/persistent",
            "/wavekv/sync2/persistent",
            "/wavekv/push/persistent",
        ] {
            let response = client.post(path).body(bomb.clone()).dispatch().await;
            assert_eq!(
                response.status(),
                Status::BadRequest,
                "{path} must refuse an over-sized expansion"
            );
        }
    }

    /// The limit is inclusive, so a payload landing exactly on it still decodes. Without
    /// this the bound could tighten by a byte and only the bomb test would still pass.
    #[test]
    fn a_payload_exactly_on_the_limit_still_decompresses() {
        let exact = gzip(&vec![7u8; MAX_DECOMPRESSED_SYNC_BYTES]).expect("gzip");
        let out = gunzip_bounded(&exact, MAX_DECOMPRESSED_SYNC_BYTES).expect("must be accepted");
        assert_eq!(out.len(), MAX_DECOMPRESSED_SYNC_BYTES);

        let one_over = gzip(&vec![7u8; MAX_DECOMPRESSED_SYNC_BYTES + 1]).expect("gzip");
        assert!(gunzip_bounded(&one_over, MAX_DECOMPRESSED_SYNC_BYTES).is_err());
    }

    #[tokio::test]
    async fn a_push_from_node_id_zero_is_refused() {
        let (client, proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let mut env = push_envelope(peer_uuid(), "node/9");
        env.sender_id = 0;
        let response = client
            .post("/wavekv/push/persistent")
            .body(body(&env))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }
}
