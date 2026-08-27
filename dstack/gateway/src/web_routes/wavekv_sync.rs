// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV sync HTTP endpoints
//!
//! Sync data is encoded using msgpack + gzip compression for efficiency.

use crate::{
    kv::{gunzip_bounded, MAX_COMPRESSED_SYNC_BYTES, MAX_DECOMPRESSED_SYNC_BYTES},
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
use wavekv::sync::SyncEnvelope;

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

async fn read_compressed_body(data: Data<'_>) -> Result<Vec<u8>, Status> {
    let bytes = data
        .open(MAX_COMPRESSED_SYNC_BYTES.bytes())
        .into_bytes()
        .await
        .map_err(|_| Status::BadRequest)?;
    if !bytes.is_complete() {
        warn!("sync payload exceeds the {MAX_COMPRESSED_SYNC_BYTES}-byte compressed-size limit");
        return Err(Status::PayloadTooLarge);
    }
    Ok(bytes.into_inner())
}

/// Read a sync envelope from a bounded request body.
/// Decode a gzipped sync envelope.
///
/// Split from the `Data` read so the request-handling half of these endpoints
/// can be driven from a test. Rocket's local client presents no certificate, so
/// a test that went through the real route would be stopped at the peer check
/// before reaching any of this.
fn decode_envelope(compressed: &[u8]) -> Result<SyncEnvelope, Status> {
    let decompressed = gunzip(compressed)?;
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

/// WaveKV sync endpoint.
#[post("/wavekv/sync/<store>", data = "<data>")]
pub async fn sync_store(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    store: &str,
    data: Data<'_>,
) -> Result<(ContentType, Vec<u8>), Status> {
    verify_gateway_peer(state, cert)?;
    let body = read_compressed_body(data).await?;
    handle_sync(state, store, &body)
}

/// Everything `sync_store` does once the caller is known to be a peer.
pub(crate) fn handle_sync(
    state: &Proxy,
    store: &str,
    body: &[u8],
) -> Result<(ContentType, Vec<u8>), Status> {
    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    let env = decode_envelope(body)?;
    if env.sender_id == 0 {
        warn!("rejected sync from invalid node_id 0");
        return Err(Status::BadRequest);
    }
    refuse_removed_sender(state, env.sender_id)?;

    let Some(result) = wavekv_sync.handle_envelope(store, env) else {
        return Err(Status::NotFound);
    };
    let response = result.map_err(|e| {
        tracing::error!("{store} sync failed: {e:#}");
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

/// Refuse an envelope from a node an operator has removed.
///
/// The app-identity check above proves the sender is *a* gateway of this app;
/// it cannot prove the sender is still a *member*. A removed node returning
/// with its old data directory diverges from every digest, and wavekv's
/// repair would answer with a full re-exchange that resurrects every record
/// whose delete the cluster has already collected -- so the door, not the
/// merge, is where a removed sender has to stop. Re-admission is an explicit
/// operator decision: SetNodeUrl clears the marker.
fn refuse_removed_sender(state: &Proxy, sender_id: u32) -> Result<(), Status> {
    if state.kv_store().is_peer_removed(sender_id) {
        warn!("refused an envelope from removed node {sender_id}");
        return Err(Status::Forbidden);
    }
    Ok(())
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
    let body = read_compressed_body(data).await?;
    handle_push(state, store, &body)
}

/// Everything `push_store` does once the caller is known to be a peer.
pub(crate) fn handle_push(state: &Proxy, store: &str, body: &[u8]) -> Result<Status, Status> {
    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    let env = decode_envelope(body)?;
    if env.sender_id == 0 {
        warn!("rejected push from invalid node_id 0");
        return Err(Status::BadRequest);
    }
    refuse_removed_sender(state, env.sender_id)?;

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
    use crate::kv::{HttpsClient, NodeData};
    use crate::main_service::{Proxy, ProxyOptions};
    use rocket::local::asynchronous::Client;
    use tempfile::TempDir;
    use wavekv::types::{Entry, Metadata};

    const ME: u32 = 1;
    const PEER: u32 = 2;
    /// Both sides of the local mTLS test are this gateway, so one id serves for
    /// the certificate it presents and the identity it expects of a peer.
    const TEST_APP_ID: &[u8] = b"test-app-id-0000-0001";

    fn peer_uuid() -> Vec<u8> {
        b"the-real-peer-2".to_vec()
    }

    /// A self-signed CA plus a leaf it signs. `HttpSyncNetwork::new` loads all three
    /// from disk to build its rustls client config, and the root store only accepts a
    /// trust anchor with `CA:TRUE` — so a lone self-signed leaf is not enough.
    ///
    /// The leaf carries an app_id because no test here turns the peer check off, so a
    /// certificate without one is refused before any of them reach what they are about.
    /// It is also what a real peer's certificate carries.
    fn write_tls_material(dir: &std::path::Path) -> TlsConfig {
        let pki = ra_tls::test_pki::write_mtls_pki(
            dir,
            ra_tls::test_pki::TestCert::localhost().app_id(TEST_APP_ID),
        )
        .expect("write test PKI");

        TlsConfig {
            certs: pki.cert_path.to_string_lossy().into_owned(),
            key: pki.key_path.to_string_lossy().into_owned(),
            mutual: MutualConfig {
                ca_certs: pki.ca_cert_path.to_string_lossy().into_owned(),
            },
        }
    }

    /// A gateway whose request-handling half these tests drive directly.
    ///
    /// They are about everything below the peer check — the gzip framing, the store
    /// split, the uuid check, the removed-sender refusal — and they call `handle_sync`
    /// and `handle_push` rather than going through the routes, because the peer check runs
    /// on every request these tests make and Rocket's local client speaks no TLS, so a
    /// request through the route can never get past it. `enforcing_gateway` covers the check itself.
    async fn serving_gateway(sync_enabled: bool) -> (Proxy, TempDir) {
        let (_client, proxy, tmp) = serving_gateway_with(sync_enabled).await;
        (proxy, tmp)
    }

    /// The same gateway, reached through the real routes, where every request is refused
    /// for want of a certificate. That refusal is the assertion.
    async fn enforcing_gateway() -> (Client, Proxy, TempDir) {
        serving_gateway_with(true).await
    }

    /// Drive the sync endpoint's body the way its route would.
    fn post_sync(proxy: &Proxy, store: &str, body: Vec<u8>) -> (Status, Vec<u8>) {
        match handle_sync(proxy, store, &body) {
            Ok((_content_type, bytes)) => (Status::Ok, bytes),
            Err(status) => (status, Vec::new()),
        }
    }

    /// Drive the push endpoint's body the way its route would.
    fn post_push(proxy: &Proxy, store: &str, body: Vec<u8>) -> Status {
        match handle_push(proxy, store, &body) {
            Ok(status) => status,
            Err(status) => status,
        }
    }

    async fn serving_gateway_with(sync_enabled: bool) -> (Client, Proxy, TempDir) {
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

        let tls_config = write_tls_material(temp_dir.path());
        let proxy = Proxy::new(ProxyOptions {
            config,
            my_app_id: Some(TEST_APP_ID.to_vec()),
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
    /// thing standing in front of them, and no test had ever executed it: every test
    /// here reached the body below by turning the check off. Replacing the whole
    /// function body with `Ok(())` did not turn the suite red.
    ///
    /// Rocket's local client speaks no TLS and so presents no certificate, which is
    /// exactly the case that must be refused.
    #[tokio::test]
    async fn every_sync_route_refuses_a_peer_it_cannot_identify() {
        let (client, _proxy, _tmp) = enforcing_gateway().await;

        for route in ["/wavekv/sync/persistent", "/wavekv/push/persistent"] {
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
        ra_tls::test_pki::TestCert::new("peer.test")
            .app_id(app_id)
            .self_signed_der()
            .expect("self-signed cert")
    }

    /// A certificate with no app identity at all.
    fn cert_without_app_id() -> Vec<u8> {
        ra_tls::test_pki::TestCert::new("peer.test")
            .self_signed_der()
            .expect("self-signed cert")
    }

    fn authorize(der: &[u8], my_app_id: Option<&[u8]>) -> Result<(), Status> {
        use rocket::mtls::x509::{FromDer, X509Certificate};
        let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");
        authorize_peer(&RocketCert(parsed.extensions()), my_app_id)
    }

    /// The rule the sync routes are defended by: same app id or nothing.
    ///
    /// Every case below was previously unreachable, because the only tests that touched
    /// this code returned before it without checking anything. Inverting the
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
        let (proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let status = post_push(
            &proxy,
            "persistent",
            body(&push_envelope(peer_uuid(), "node/9")),
        );

        assert_eq!(status, Status::Ok);
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
        let (proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let status = post_push(
            &proxy,
            "persistent",
            body(&push_envelope(Vec::new(), "node/9")),
        );

        assert_eq!(status, Status::InternalServerError);
        assert!(
            proxy.kv_store().persistent().read().get("node/9").is_none(),
            "a push that fails the identity check must not write anything"
        );
    }

    #[tokio::test]
    async fn a_sync_round_trip_returns_a_decodable_envelope() {
        let (proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);
        proxy
            .kv_store()
            .persistent()
            .write()
            .put("node/7".to_string(), b"v".to_vec())
            .expect("seed");

        let request = SyncEnvelope::new(PEER, peer_uuid());
        let (status, bytes) = post_sync(&proxy, "persistent", body(&request));

        assert_eq!(status, Status::Ok);
        let decoded = SyncEnvelope::decode(&gunzip(&bytes).expect("gunzip")).expect("decode");
        assert_eq!(decoded.sender_id, ME);
        assert!(
            decoded.entries.iter().any(|e| e.key == "node/7"),
            "an empty ack map must draw the whole live state"
        );
    }

    /// Exercise the composed transport rather than testing the HTTPS client and Rocket
    /// routes in isolation: a real TLS listener requires a CA-signed client certificate,
    /// receives a compressed envelope, merges it, and returns a decodable response.
    #[tokio::test]
    async fn sync_and_push_cross_a_real_mutually_authenticated_tls_connection() {
        use rocket::{mtls::MtlsConfig, tls::TlsConfig as RocketTlsConfig};

        let (proxy, tmp) = serving_gateway(true).await;
        register_peer(&proxy);
        let tls = write_tls_material(tmp.path());

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
            listener.local_addr().expect("local address").port()
        };
        let server_tls = RocketTlsConfig::from_paths(&tls.certs, &tls.key)
            .with_mutual(MtlsConfig::from_path(&tls.mutual.ca_certs).mandatory(true));
        let figment = rocket::Config::figment()
            .merge(("address", "127.0.0.1"))
            .merge(("port", port))
            .merge(("tls", server_tls));
        let rocket = rocket::custom(figment)
            .manage(proxy.clone())
            .mount("/", crate::web_routes::wavekv_sync_routes())
            .ignite()
            .await
            .expect("ignite TLS Rocket server");
        let shutdown = rocket.shutdown();
        let server = tokio::spawn(async move {
            rocket.launch().await.expect("TLS Rocket server");
        });

        let client = HttpsClient::new(&crate::kv::HttpsClientConfig {
            cert_path: tls.certs.clone(),
            key_path: tls.key.clone(),
            ca_cert_path: tls.mutual.ca_certs.clone(),
            cert_validator: None,
        })
        .expect("HTTPS client");
        let base = format!("https://127.0.0.1:{port}");

        let mut request = SyncEnvelope::new(PEER, peer_uuid());
        request.entries.push(Entry::new(
            "node/21".to_string(),
            Some(b"sync".to_vec()),
            Metadata::new(PEER, 21, 1),
        ));

        let response = {
            let mut last = None;
            let mut response = None;
            for _ in 0..50 {
                match client
                    .post_bytes_response(
                        &format!("{base}/wavekv/sync/persistent"),
                        request.encode().expect("encode sync request"),
                    )
                    .await
                {
                    Ok(bytes) => {
                        response = Some(bytes);
                        break;
                    }
                    Err(err) => {
                        last = Some(err);
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
            }
            response.unwrap_or_else(|| panic!("server did not become ready: {last:?}"))
        };
        SyncEnvelope::decode(&response).expect("decode sync response");
        assert!(proxy
            .kv_store()
            .persistent()
            .read()
            .get("node/21")
            .is_some());

        let push = push_envelope(peer_uuid(), "node/22");
        client
            .post_bytes_no_response(
                &format!("{base}/wavekv/push/persistent"),
                push.encode().expect("encode push"),
            )
            .await
            .expect("push over mTLS");
        assert!(proxy
            .kv_store()
            .persistent()
            .read()
            .get("node/22")
            .is_some());

        shutdown.notify();
        server.await.expect("server task");
    }

    /// The production routes with the peer check removed.
    ///
    /// Mounted by one test, and only because the body cap it asserts lives in
    /// the route half: `handle_sync` never sees a `Data`, so a test calling it
    /// directly cannot reach the limit, and Rocket's local client cannot present
    /// the certificate the real route now requires. Two duplicated lines are
    /// cheaper than losing coverage of a bound that exists to stop a peer -- or a
    /// stranger who got that far -- from making the gateway read without end.
    #[post("/wavekv/sync/<store>", data = "<data>")]
    async fn ungated_sync(
        state: &State<Proxy>,
        store: &str,
        data: Data<'_>,
    ) -> Result<(ContentType, Vec<u8>), Status> {
        let body = read_compressed_body(data).await?;
        handle_sync(state, store, &body)
    }

    #[post("/wavekv/push/<store>", data = "<data>")]
    async fn ungated_push(
        state: &State<Proxy>,
        store: &str,
        data: Data<'_>,
    ) -> Result<Status, Status> {
        let body = read_compressed_body(data).await?;
        handle_push(state, store, &body)
    }

    #[tokio::test]
    async fn an_oversized_compressed_request_is_rejected_explicitly() {
        let (proxy, _tmp) = serving_gateway(true).await;
        let rocket = rocket::build()
            .manage(proxy)
            .mount("/", rocket::routes![ungated_sync, ungated_push]);
        let client = Client::tracked(rocket).await.expect("rocket client");

        for path in ["/wavekv/sync/persistent", "/wavekv/push/persistent"] {
            let response = client
                .post(path)
                .body(vec![0u8; 16 * 1024 * 1024 + 1])
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::PayloadTooLarge, "{path}");
        }
    }

    /// Unknown stores are rejected rather than being routed to either replicated store.
    #[tokio::test]
    async fn an_unknown_store_is_rejected() {
        let (proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let (status, _) = post_sync(&proxy, "bogus", body(&SyncEnvelope::new(PEER, peer_uuid())));

        assert_eq!(status, Status::NotFound);
    }

    /// The lockout at the door. The app-identity check proves the sender is
    /// *a* gateway of this app; only the removal marker says whether it is
    /// still a *member*. A removed node's envelopes are refused on both
    /// routes before anything merges, and clearing the marker -- the
    /// SetNodeUrl re-admission path -- opens the door again.
    #[tokio::test]
    async fn a_removed_nodes_envelopes_are_refused_at_the_door() {
        let (proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);
        proxy.kv_store().mark_peer_removed(PEER).expect("mark");

        let (sync_status, _) = post_sync(
            &proxy,
            "persistent",
            body(&SyncEnvelope::new(PEER, peer_uuid())),
        );
        assert_eq!(
            sync_status,
            Status::Forbidden,
            "sync must refuse a removed sender"
        );
        let push_status = post_push(
            &proxy,
            "persistent",
            body(&SyncEnvelope::new(PEER, peer_uuid())),
        );
        assert_eq!(
            push_status,
            Status::Forbidden,
            "push must refuse a removed sender"
        );

        proxy.kv_store().clear_peer_removed(PEER).expect("clear");
        let (readmitted, _) = post_sync(
            &proxy,
            "persistent",
            body(&SyncEnvelope::new(PEER, peer_uuid())),
        );
        assert_eq!(readmitted, Status::Ok, "re-admission opens the door again");
    }

    /// A node with synchronization disabled reports that the service is unavailable.
    #[tokio::test]
    async fn a_sync_disabled_node_answers_503() {
        let (proxy, _tmp) = serving_gateway(false).await;

        let (sync_status, _) = post_sync(
            &proxy,
            "persistent",
            body(&SyncEnvelope::new(PEER, peer_uuid())),
        );
        assert_eq!(
            sync_status,
            Status::ServiceUnavailable,
            "sync must not look like a missing v2 route"
        );
        let push_status = post_push(
            &proxy,
            "persistent",
            body(&SyncEnvelope::new(PEER, peer_uuid())),
        );
        assert_eq!(
            push_status,
            Status::ServiceUnavailable,
            "push must not look like a missing v2 route"
        );
    }

    /// gzip expands by three orders of magnitude on attacker-chosen input, so the
    /// 16 MiB cap on the request body bounds the *compressed* size and nothing else.
    /// mTLS proves only that the sender is some gateway of this deployment, so the bound
    /// has to hold against a peer running a buggy build, not just against a stranger.
    #[tokio::test]
    async fn a_compression_bomb_is_refused_before_it_is_decompressed() {
        let (proxy, _tmp) = serving_gateway(true).await;

        // ~130 MiB of zeroes compresses to well under the request cap.
        let bomb = gzip(&vec![0u8; MAX_DECOMPRESSED_SYNC_BYTES + 1]).expect("gzip");
        assert!(
            bomb.len() < 16 * 1024 * 1024,
            "the fixture has to fit through the body cap to be testing anything: {} bytes",
            bomb.len()
        );

        let (sync_status, _) = post_sync(&proxy, "persistent", bomb.clone());
        assert_eq!(
            sync_status,
            Status::BadRequest,
            "sync must refuse an over-sized expansion"
        );
        let push_status = post_push(&proxy, "persistent", bomb);
        assert_eq!(
            push_status,
            Status::BadRequest,
            "push must refuse an over-sized expansion"
        );
    }

    /// The limits must leave room for the largest legitimate message.
    ///
    /// The boundary test below asserts a payload of exactly `MAX_DECOMPRESSED_SYNC_BYTES`
    /// is accepted — but it builds that payload *from the same constant*, so it holds
    /// whatever the constant says. Shrinking the limit to a few kilobytes keeps it green
    /// while rejecting every real delta. Pin the values against what production sends,
    /// which is the property that actually matters.
    // Deliberately runtime assertions rather than `const { assert!(..) }`: a const block
    // would fail the build, which mutation testing scores as "unviable" rather than
    // "caught", and would lose the message explaining what the number is for.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_sync_limits_admit_the_largest_message_the_protocol_can_produce() {
        // A v2 delta is capped by wavekv's `max_delta_bytes` (4 MiB by default).
        const MAX_DELTA_BYTES: usize = 4 * 1024 * 1024;
        assert!(
            MAX_DECOMPRESSED_SYNC_BYTES >= 8 * MAX_DELTA_BYTES,
            "a decompression limit of {MAX_DECOMPRESSED_SYNC_BYTES} bytes would reject \
             ordinary sync traffic, not just a bomb"
        );

        // The compressed ceiling mirrors what the routes accept on a request, so a peer
        // cannot answer with more than it would have been allowed to ask.
        assert_eq!(
            crate::kv::MAX_COMPRESSED_SYNC_BYTES,
            16 * 1024 * 1024,
            "this must stay equal to the 16 MiB the routes accept on a request body"
        );
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
        let (proxy, _tmp) = serving_gateway(true).await;
        register_peer(&proxy);

        let mut env = push_envelope(peer_uuid(), "node/9");
        env.sender_id = 0;
        let status = post_push(&proxy, "persistent", body(&env));

        assert_eq!(status, Status::BadRequest);
    }
}
