// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Extension, Query, State},
    routing::{get, post},
    Json, Router,
};
use dstack_attest::attestation::AppInfo;
use ra_tls::traits::CertExt;
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsAcceptor;

use crate::{
    errors::AppError,
    lease::{load_hmac_key, Lease},
    state::AppState,
};

/// Extract AppInfo from a DER-encoded X.509 certificate's RA-TLS extension.
///
/// Returns None when the cert has no PHALA_RATLS_APP_INFO extension (non-TDX / dev mode).
fn extract_app_info(cert_der: &[u8]) -> Result<Option<AppInfo>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| anyhow::anyhow!("failed to parse peer certificate: {e}"))?;
    cert.get_app_info()
}

/// Tower service wrapper that injects `Option<AppInfo>` into each request's extensions.
/// Used to pass per-connection RA-TLS cert data to axum handlers without TDX quote handling.
#[derive(Clone)]
struct AppInfoExtractor<S> {
    inner: S,
    app_info: Option<AppInfo>,
}

impl<S, B> tower::Service<hyper::Request<B>> for AppInfoExtractor<S>
where
    S: tower::Service<hyper::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: hyper::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.app_info.clone());
        self.inner.call(req)
    }
}

#[derive(Deserialize)]
pub struct AcquireRequest {
    pub app_id: String,
    pub instance_id: String,
    pub compose_hash: String,
    pub image_digest: String,
}

/// One image-decryption keypair's PRIVATE key in the leased keyring. `kid`
/// labels it for management; the launcher hands all `priv_pem`s to skopeo and
/// ocicrypt (native JWE) decrypts with whichever is the image's recipient.
#[derive(Serialize)]
pub struct KeyEntry {
    pub kid: String,
    /// PEM-encoded EC P-256 private key (PKCS#8)
    pub priv_pem: String,
}

#[derive(Serialize)]
pub struct AcquireResponse {
    /// serialized Lease JSON
    pub lease: String,
    /// the authorized decryption keyring (private keys). Long-lived, not
    /// one-per-digest — entitlement is the attested identity checks above.
    pub keyset: Vec<KeyEntry>,
}

#[derive(Deserialize)]
pub struct RenewRequest {
    pub slot_id: String,
    pub instance_id: String,
}

#[derive(Serialize)]
pub struct RenewResponse {
    pub lease: String,
}

#[derive(Deserialize)]
pub struct VersionQuery {
    pub app_id: String,
}

#[derive(Serialize)]
pub struct VersionResponse {
    pub current_image_digest: String,
    pub bundle_seq: u64,
}

pub async fn lease_acquire(
    State(state): State<Arc<AppState>>,
    // AppInfo extracted from the launcher's RA-TLS client certificate.
    // None in dev/non-TDX mode (cert has no PHALA_RATLS_APP_INFO extension).
    Extension(cert_info): Extension<Option<AppInfo>>,
    Json(req): Json<AcquireRequest>,
) -> Result<Json<AcquireResponse>, AppError> {
    // FAIL-CLOSED: the identity MUST come from the RA-TLS client cert (attested,
    // KMS-CA-signed). There is no insecure/dev bypass — a request without an
    // attested cert is refused, and the request body is only allowed to echo
    // what the cert already proves.
    let Some(ref info) = cert_info else {
        return Err(AppError::from(anyhow::anyhow!(
            "no attested app_info in client cert — refusing CEK"
        )));
    };
    let app_id = hex::encode(&info.app_id);
    let compose_hash = hex::encode(&info.compose_hash);
    let cert_os_image = hex::encode(&info.os_image_hash);
    if !req.app_id.is_empty() && req.app_id != app_id {
        return Err(AppError::from(anyhow::anyhow!(
            "app_id mismatch: cert={app_id} body={}",
            req.app_id
        )));
    }
    if !req.compose_hash.is_empty() && req.compose_hash != compose_hash {
        return Err(AppError::from(anyhow::anyhow!(
            "compose_hash mismatch: cert={compose_hash} body={}",
            req.compose_hash
        )));
    }

    let bundle_guard = state.auth_bundle.read().await;
    let bundle = bundle_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no auth bundle installed"))?;

    // FAIL-CLOSED: the attested OS image must be in the bundle's os_images
    // whitelist (empty whitelist ⇒ deny). No bypass.
    {
        let want = cert_os_image.trim_start_matches("0x").to_lowercase();
        let allowed: Vec<String> = bundle["os_images"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str())
                    .map(|h| h.trim_start_matches("0x").to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        if !allowed.contains(&want) {
            return Err(AppError::from(anyhow::anyhow!(
                "os_image not in whitelist (fail-closed)"
            )));
        }
    }

    // app_whitelist is an array; find the entry with matching app_id
    let app_entry = bundle["app_whitelist"]
        .as_array()
        .and_then(|apps| {
            apps.iter()
                .find(|app| app["app_id"].as_str() == Some(app_id.as_str()))
        })
        .ok_or_else(|| anyhow::anyhow!("app_id {} not in app_whitelist", app_id))?;

    // verify the launcher's attested compose_hash ∈ allowed_launcher_digests
    // (the "*" wildcard allows any — dev only).
    let launcher_digests: Vec<&str> = app_entry["allowed_launcher_digests"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !launcher_digests.contains(&"*") && !launcher_digests.contains(&compose_hash.as_str()) {
        return Err(AppError::from(anyhow::anyhow!(
            "compose_hash not in allowed_launcher_digests (fail-closed)"
        )));
    }

    // verify the REQUESTED workload image digest ∈ allowed_workload_digests
    // (the payload gate — "*" allows any; empty list ⇒ deny). This bounds which
    // images this app may lease keys to decrypt, not just which launcher runs.
    let workload_digests: Vec<&str> = app_entry["allowed_workload_digests"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !workload_digests.contains(&"*") && !workload_digests.contains(&req.image_digest.as_str()) {
        return Err(AppError::from(anyhow::anyhow!(
            "image_digest not in allowed_workload_digests (fail-closed)"
        )));
    }

    // Lease the tenant's decryption keyring (private keys). SELECTION is the
    // launcher+ocicrypt's job (try-each against the image's JWE recipient);
    // ENTITLEMENT was the attested app/compose/os checks above. Keys are
    // long-lived and shared across images — no per-digest match here.
    // FAIL-CLOSED: an empty keyring authorizes no decryption.
    let now = now_secs();
    let keyset: Vec<KeyEntry> = bundle["keyring"]
        .as_array()
        .map(|ring| {
            ring.iter()
                .filter(|k| {
                    // drop expired keys (not_after in the past); keep keys without one
                    k["not_after"].as_u64().map(|exp| exp > now).unwrap_or(true)
                })
                .filter_map(|k| {
                    Some(KeyEntry {
                        kid: k["kid"].as_str()?.to_string(),
                        priv_pem: k["priv_pem"].as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if keyset.is_empty() {
        return Err(AppError::from(anyhow::anyhow!(
            "no live keys in bundle keyring (fail-closed)"
        )));
    }

    // slot_quota comes from the AuthBundle (authoritative); config default is a last resort
    let slot_quota = {
        let bg = state.auth_bundle.read().await;
        bg.as_ref()
            .and_then(|b| b["slot_quota"].as_u64())
            .unwrap_or(state.config.slot_quota as u64) as usize
    };

    drop(bundle_guard);

    let binding = state
        .slots
        .acquire(&app_id, &req.instance_id, &compose_hash, slot_quota, now)
        .await?;

    let hmac_key = load_hmac_key(&state.config.kms_volume)?;
    let lease = Lease::sign(
        &req.instance_id,
        &app_id,
        &binding.slot_id,
        &compose_hash,
        now,
        now + state.config.lease_ttl_secs,
        &hmac_key,
    )?;

    let lease_json = serde_json::to_string(&lease)?;
    Ok(Json(AcquireResponse {
        lease: lease_json,
        keyset,
    }))
}

pub async fn lease_renew(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenewRequest>,
) -> Result<Json<RenewResponse>, AppError> {
    let now = now_secs();
    let lease_ttl = state.config.lease_ttl_secs;

    // lazy cleanup: evict slots not seen for 2x lease_ttl
    let cutoff = now.saturating_sub(2 * lease_ttl);
    state.slots.cleanup_stale(cutoff).await;

    let binding = state.slots.renew(&req.slot_id, &req.instance_id, now).await?;

    let hmac_key = load_hmac_key(&state.config.kms_volume)?;
    let lease = Lease::sign(
        &req.instance_id,
        &binding.app_id,
        &binding.slot_id,
        &binding.compose_hash,
        now,
        now + lease_ttl,
        &hmac_key,
    )?;

    let lease_json = serde_json::to_string(&lease)?;
    Ok(Json(RenewResponse { lease: lease_json }))
}

pub async fn version_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<VersionQuery>,
) -> Result<Json<VersionResponse>, AppError> {
    let bundle_guard = state.auth_bundle.read().await;
    let bundle = bundle_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no auth bundle installed"))?;

    let bundle_seq = bundle["bundle_seq"].as_u64().unwrap_or(0);
    let current_image_digest = bundle["app_whitelist"]
        .as_array()
        .and_then(|apps| {
            apps.iter()
                .find(|app| app["app_id"].as_str() == Some(q.app_id.as_str()))
        })
        .and_then(|app| app["current_image_digest"].as_str())
        .unwrap_or("")
        .to_string();

    Ok(Json(VersionResponse {
        current_image_digest,
        bundle_seq,
    }))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the mTLS server config from the KMS-CA-signed rpc cert (so the launcher
/// can verify the key-broker against the KMS CA from GetMeta) and a MANDATORY
/// client-cert verifier rooted at the KMS CA. FAIL-CLOSED: there is no
/// ephemeral/self-signed cert and no "accept any client" fallback.
fn build_server_tls_config(
    server_cert_pem: &str,
    server_key_pem: &str,
    ca_pem: &str,
) -> Result<ServerConfig> {
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(server_cert_pem.as_bytes());
        rustls_pemfile::certs(&mut cursor)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse rpc server cert PEM")?
    };
    if cert_chain.is_empty() {
        anyhow::bail!("rpc.crt contained no certificates");
    }

    let private_key: rustls::pki_types::PrivateKeyDer<'static> = {
        let mut cursor = std::io::Cursor::new(server_key_pem.as_bytes());
        rustls_pemfile::private_key(&mut cursor)
            .context("failed to parse rpc private key PEM")?
            .context("no private key found in rpc.key")?
    };

    // mandatory client-cert verification against the KMS CA — no bypass.
    let client_auth = build_client_verifier(ca_pem)
        .context("failed to build mandatory client verifier from KMS CA")?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert_chain, private_key)
        .context("failed to build TLS server config")?;

    Ok(config)
}

fn build_client_verifier(
    ca_pem: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.context("failed to parse CA cert")?;
        roots.add(cert).context("failed to add CA cert to store")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to build client verifier")?;
    Ok(verifier)
}

/// Spawn the mTLS server on port_mtls.
pub async fn spawn_mtls_server(state: Arc<AppState>) -> Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;

    let port = state.config.port_mtls;

    // FAIL-CLOSED: the mTLS endpoint serves the KMS-CA-signed rpc cert and
    // requires KMS-CA-signed client certs. Both come from the provisioned keyset,
    // so wait until it exists (the launcher only connects post-provision anyway).
    let cert_dir = state.config.kms_volume.join("certs");
    let rpc_crt = cert_dir.join("rpc.crt");
    let rpc_key = cert_dir.join("rpc.key");
    let root_ca = cert_dir.join("root-ca.crt");
    tracing::info!("mtls: waiting for provisioned keyset (rpc.crt + root-ca.crt)…");
    while !(rpc_crt.exists() && rpc_key.exists() && root_ca.exists()) {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let server_cert_pem = std::fs::read_to_string(&rpc_crt)
        .with_context(|| format!("failed to read {}", rpc_crt.display()))?;
    let server_key_pem = std::fs::read_to_string(&rpc_key)
        .with_context(|| format!("failed to read {}", rpc_key.display()))?;
    let ca_pem = std::fs::read_to_string(&root_ca)
        .with_context(|| format!("failed to read {}", root_ca.display()))?;

    let tls_config = build_server_tls_config(&server_cert_pem, &server_key_pem, &ca_pem)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    tracing::info!("mtls: serving KMS-CA-signed rpc cert with mandatory client auth");

    let app = Router::new()
        .route("/lease/acquire", post(lease_acquire))
        .route("/lease/renew", post(lease_renew))
        .route("/version", get(version_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .with_context(|| format!("failed to bind mtls port {}", port))?;

    tracing::info!("kms-sidecar mtls server listening on port {}", port);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("mtls accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let tower_svc = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // Extract AppInfo from the peer's RA-TLS client certificate.
                    // This is the gateway pattern: chain verification is handled by rustls
                    // (WebPkiClientVerifier above); here we only parse the extension.
                    let app_info: Option<AppInfo> = tls_stream
                        .get_ref().1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .and_then(|cert| extract_app_info(cert.as_ref()).ok().flatten());

                    if app_info.is_some() {
                        tracing::debug!("mtls: accepted connection from {} with AppInfo", peer_addr);
                    } else {
                        tracing::debug!("mtls: accepted connection from {} (no AppInfo, non-TDX mode)", peer_addr);
                    }

                    // Inject Option<AppInfo> into every request on this connection.
                    let svc = AppInfoExtractor { inner: tower_svc, app_info };

                    let io = TokioIo::new(tls_stream);
                    let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
                    let _ = ConnBuilder::new(TokioExecutor::new())
                        .serve_connection(io, hyper_svc)
                        .await;
                }
                Err(e) => {
                    tracing::warn!("mtls tls handshake failed from {}: {}", peer_addr, e);
                }
            }
        });
    }
}
