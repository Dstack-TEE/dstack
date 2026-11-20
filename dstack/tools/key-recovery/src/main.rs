// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Recover dstack application keys from an older KMS root epoch.
//!
//! The guest agent only serves its boot (current) epoch, so after a root
//! rotation the old keys are no longer reachable through `getKey`. This tool
//! asks the KMS for the app root of a chosen epoch and re-applies the frozen
//! derivation:
//!
//!   * v0 (`getKey(path, purpose, algorithm)`) — HKDF-SHA256 under `RATLS`
//!   * v1 (`getKey(domain, algorithm)`)        — HKDF-SHA256 under
//!     `dstack-guest-v1` with the length-prefixed claim
//!
//! It reads the KMS URL, pinned CA, launch ticket and collateral config from the
//! guest's own files, so nothing has to be passed on the command line:
//!
//!   * `/dstack/.host-shared/.appkeys.json`
//!   * `/dstack/.host-shared/.sys-config.json`
//!
//! Run it inside the CVM (it needs the platform quote), either once or as a
//! small HTTP server on a Unix socket and/or localhost TCP port.

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use dstack_types::shared_filenames::{host_shared_dir, APP_KEYS, SYS_CONFIG};
use dstack_types::{AppKeys, KeyProvider, SysConfig, VmConfig};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_tls::api_v1::{derive_app_key, key_claim, sign_recoverable_keccak256, KeyAlgorithm};
use ra_tls::cert::generate_self_signed_ra_cert;
use ra_tls::kdf::derive_key;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(about = "Recover dstack application keys from an older KMS root epoch")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Derive one key and print it
    Key(KeyArgs),
    /// Show the CVM's current epochs and whether epoch 0 is available
    Info(InfoArgs),
    /// Serve the same operations over HTTP
    Serve(ServeArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApiArg {
    /// v1 on dstack >= 0.6.0, v0 otherwise
    Auto,
    /// Frozen v0 GetKey(path, purpose, algorithm)
    V0,
    /// v1 GetKey(domain, algorithm)
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Api {
    V0,
    V1,
}

impl Api {
    fn as_str(self) -> &'static str {
        match self {
            Self::V0 => "v0",
            Self::V1 => "v1",
        }
    }
}

#[derive(Args)]
struct KeyArgs {
    /// Key name: v0 path or v1 domain
    name: String,

    /// Which key surface to reproduce
    #[arg(long, value_enum, default_value_t = ApiArg::Auto)]
    api: ApiArg,

    /// v0 purpose. Only affects signature_chain[0], not the key.
    #[arg(long, default_value = "")]
    purpose: String,

    /// secp256k1 or ed25519
    #[arg(long, default_value = "secp256k1")]
    algorithm: String,

    /// KMS root epoch
    #[arg(long, default_value_t = 0)]
    root_epoch: u32,

    /// App epoch
    #[arg(long, default_value_t = 0)]
    app_epoch: u32,

    /// Path to .appkeys.json
    #[arg(long)]
    keys_file: Option<PathBuf>,

    /// Path to .sys-config.json
    #[arg(long)]
    sys_config: Option<PathBuf>,

    /// Print JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct InfoArgs {
    /// Path to .appkeys.json
    #[arg(long)]
    keys_file: Option<PathBuf>,

    /// Path to .sys-config.json
    #[arg(long)]
    sys_config: Option<PathBuf>,

    /// Print JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ServeArgs {
    /// Unix socket to listen on
    #[arg(long, default_value = "/var/run/dstack-key-recovery.sock")]
    socket: PathBuf,

    /// Do not listen on a Unix socket
    #[arg(long)]
    no_socket: bool,

    /// TCP address to listen on
    #[arg(long, default_value = "127.0.0.1:8099")]
    addr: std::net::SocketAddr,

    /// Do not listen on TCP
    #[arg(long)]
    no_addr: bool,

    /// Path to .appkeys.json
    #[arg(long)]
    keys_file: Option<PathBuf>,

    /// Path to .sys-config.json
    #[arg(long)]
    sys_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct KeyParams {
    name: Option<String>,
    path: Option<String>,
    domain: Option<String>,
    purpose: Option<String>,
    algorithm: Option<String>,
    root_epoch: Option<u32>,
    app_epoch: Option<u32>,
}

#[derive(Clone)]
struct AppRoot {
    k256_key: Vec<u8>,
    k256_signature: Vec<u8>,
}

struct AppState {
    keys: AppKeys,
    sys: SysConfig,
    kms_url: String,
    current_root: u32,
    current_app: u32,
    guest_version: Option<semver::Version>,
    roots: Mutex<HashMap<(u32, u32), AppRoot>>,
    epoch0: Mutex<Option<Result<(), String>>>,
}

impl AppState {
    fn load(keys_file: Option<PathBuf>, sys_config: Option<PathBuf>) -> Result<Self> {
        let keys_path = keys_file.unwrap_or_else(|| host_shared_dir().join(APP_KEYS));
        let sys_path = sys_config.unwrap_or_else(|| host_shared_dir().join(SYS_CONFIG));

        let keys: AppKeys = serde_json::from_slice(
            &fs::read(&keys_path)
                .with_context(|| format!("failed to read {}", keys_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", keys_path.display()))?;
        let sys: SysConfig = serde_json::from_slice(
            &fs::read(&sys_path)
                .with_context(|| format!("failed to read {}", sys_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", sys_path.display()))?;

        let (kms_url, current_root, current_app) = match &keys.key_provider {
            KeyProvider::Kms {
                url,
                root_epoch,
                app_epoch,
                ..
            } => (url.clone(), *root_epoch, *app_epoch),
            _ => bail!("keys were not provided by a KMS, nothing to recover"),
        };
        let guest_version = detect_version(&sys);

        Ok(Self {
            keys,
            sys,
            kms_url,
            current_root,
            current_app,
            guest_version,
            roots: Default::default(),
            epoch0: Default::default(),
        })
    }

    fn default_api(&self) -> Api {
        match &self.guest_version {
            Some(v) if *v >= semver::Version::new(0, 6, 0) => Api::V1,
            _ => Api::V0,
        }
    }

    async fn app_root(&self, root_epoch: u32, app_epoch: u32) -> Result<AppRoot> {
        if root_epoch == self.current_root && app_epoch == self.current_app {
            return Ok(AppRoot {
                k256_key: self.keys.k256_key.clone(),
                k256_signature: self.keys.k256_signature.clone(),
            });
        }
        if let Some(root) = self.roots.lock().await.get(&(root_epoch, app_epoch)) {
            return Ok(root.clone());
        }

        let request = dstack_kms_rpc::GetAppKeyRequest {
            api_version: 1,
            vm_config: String::new(),
            root_epoch: Some(root_epoch),
            app_epoch: Some(app_epoch),
            launch_ticket: self.sys.launch_ticket.clone().unwrap_or_default(),
        };
        let cert_pair = generate_self_signed_ra_cert(None)
            .context("failed to generate the self-issued RA-TLS certificate")?;
        let verifier = std::sync::Arc::new(
            dstack_attest::default_verifier(&self.sys.collateral_urls())
                .context("failed to build the attestation verifier")?,
        );
        let response = cert_client::request_app_keys(
            self.kms_url.clone(),
            request,
            cert_pair,
            verifier,
            Some(self.keys.ca_cert.clone()),
        )
        .await
        .with_context(|| {
            format!(
                "failed to get the keys of root epoch {root_epoch}, app epoch {app_epoch} \
                 from {}; the policy rows of those epochs must still allow this instance",
                self.kms_url
            )
        })?;

        let root = AppRoot {
            k256_key: response.k256_key,
            k256_signature: response.k256_signature,
        };
        self.roots
            .lock()
            .await
            .insert((root_epoch, app_epoch), root.clone());
        Ok(root)
    }

    async fn epoch0_status(&self) -> Result<(), String> {
        if self.current_root == 0 {
            return Ok(());
        }
        let mut guard = self.epoch0.lock().await;
        if let Some(status) = guard.as_ref() {
            return status.clone();
        }
        let status = self
            .app_root(0, 0)
            .await
            .map(|_| ())
            .map_err(|err| format!("{err:#}"));
        *guard = Some(status.clone());
        status
    }

    async fn derive(
        &self,
        api: Api,
        name: &str,
        purpose: &str,
        algorithm: &str,
        root_epoch: u32,
        app_epoch: u32,
    ) -> Result<KeyResult> {
        let root = self.app_root(root_epoch, app_epoch).await?;
        let (key, public_key, link0) = match api {
            Api::V0 => derive_v0(&root.k256_key, name, purpose, algorithm)?,
            Api::V1 => derive_v1(&root.k256_key, name, algorithm)?,
        };
        Ok(KeyResult {
            api,
            key,
            public_key,
            signature_chain: vec![link0, root.k256_signature],
            root_epoch,
            app_epoch,
        })
    }

    async fn derive_params(&self, api: Api, params: KeyParams) -> Result<KeyResult> {
        let name = params
            .name
            .or(params.path)
            .or(params.domain)
            .context("missing name, path or domain")?;
        self.derive(
            api,
            &name,
            params.purpose.as_deref().unwrap_or(""),
            params.algorithm.as_deref().unwrap_or("secp256k1"),
            params.root_epoch.unwrap_or(0),
            params.app_epoch.unwrap_or(0),
        )
        .await
    }

    async fn info_json(&self) -> Value {
        let epoch0 = self.epoch0_status().await;
        json!({
            "guest_version": self.guest_version.as_ref().map(ToString::to_string),
            "api": self.default_api().as_str(),
            "kms_url": self.kms_url,
            "current_root_epoch": self.current_root,
            "current_app_epoch": self.current_app,
            "root_epochs": (0..=self.current_root).collect::<Vec<_>>(),
            "app_epochs": (0..=self.current_app).collect::<Vec<_>>(),
            "epoch0_available": epoch0.is_ok(),
            "epoch0_error": epoch0.err(),
        })
    }
}

struct KeyResult {
    api: Api,
    key: Vec<u8>,
    public_key: Vec<u8>,
    signature_chain: Vec<Vec<u8>>,
    root_epoch: u32,
    app_epoch: u32,
}

impl KeyResult {
    fn to_json(&self) -> Value {
        json!({
            "api": self.api.as_str(),
            "key": hex::encode(&self.key),
            "public_key": hex::encode(&self.public_key),
            "signature_chain": self.signature_chain.iter().map(hex::encode).collect::<Vec<_>>(),
            "root_epoch": self.root_epoch,
            "app_epoch": self.app_epoch,
        })
    }
}

fn detect_version(sys: &SysConfig) -> Option<semver::Version> {
    let vm: VmConfig = serde_json::from_str(&sys.vm_config).ok()?;
    let image = vm.image?;
    let version = image.rsplit_once('-').map(|(_, v)| v).unwrap_or(&image);
    semver::Version::parse(version).ok()
}

fn public_key_bytes(secret: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    match algorithm {
        "secp256k1" | "k256" | "" => {
            let sk = SigningKey::from_slice(secret).context("invalid secp256k1 scalar")?;
            Ok(sk.verifying_key().to_sec1_bytes().to_vec())
        }
        "ed25519" => {
            let seed: [u8; 32] = secret
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid ed25519 seed length"))?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            Ok(sk.verifying_key().to_bytes().to_vec())
        }
        other => bail!("unsupported algorithm: {other}"),
    }
}

/// Frozen v0 derivation. Returns `(key, public_key, signature_chain[0])`.
fn derive_v0(
    app_root: &[u8],
    path: &str,
    purpose: &str,
    algorithm: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let derived =
        derive_key(app_root, &[path.as_bytes()], 32).context("failed to derive the v0 key")?;
    let public_key = public_key_bytes(&derived, algorithm)?;
    let app_signing_key =
        SigningKey::from_slice(app_root).context("app root k256 key is not a valid scalar")?;
    let link0 = sign_recoverable_keccak256(
        &app_signing_key,
        format!("{purpose}:{}", hex::encode(&public_key)).as_bytes(),
    )?;
    Ok((derived, public_key, link0))
}

/// v1 derivation. Returns `(key, public_key, signature_chain[0])`.
fn derive_v1(
    app_root: &[u8],
    domain: &str,
    algorithm: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let algorithm = KeyAlgorithm::parse(algorithm)?;
    let secret = derive_app_key(app_root, domain, algorithm)?;
    let public_key = public_key_bytes(&secret, algorithm.name())?;
    let claim = key_claim(algorithm, domain, &public_key)?;
    let app_signing_key =
        SigningKey::from_slice(app_root).context("app root k256 key is not a valid scalar")?;
    let link0 = sign_recoverable_keccak256(&app_signing_key, &claim)?;
    Ok((secret.to_vec(), public_key, link0))
}

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, format!("{:#}", self.0)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self(err)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self(err.into())
    }
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn info(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.info_json().await)
}

async fn auto_key(
    State(state): State<Arc<AppState>>,
    Query(params): Query<KeyParams>,
) -> Result<Json<Value>, ApiError> {
    let result = state.derive_params(state.default_api(), params).await?;
    Ok(Json(result.to_json()))
}

async fn auto_key_post(
    State(state): State<Arc<AppState>>,
    Json(params): Json<KeyParams>,
) -> Result<Json<Value>, ApiError> {
    let result = state.derive_params(state.default_api(), params).await?;
    Ok(Json(result.to_json()))
}

async fn v0_key(
    State(state): State<Arc<AppState>>,
    Query(params): Query<KeyParams>,
) -> Result<Json<Value>, ApiError> {
    let result = state.derive_params(Api::V0, params).await?;
    Ok(Json(result.to_json()))
}

async fn v1_key(
    State(state): State<Arc<AppState>>,
    Query(params): Query<KeyParams>,
) -> Result<Json<Value>, ApiError> {
    let result = state.derive_params(Api::V1, params).await?;
    Ok(Json(result.to_json()))
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/key", get(auto_key).post(auto_key_post))
        .route("/v0/key", get(v0_key))
        .route("/v1/key", get(v1_key))
        .with_state(state)
}

async fn serve_unix(path: PathBuf, app: Router) -> Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("failed to bind unix:{}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
    }
    eprintln!("listening on unix:{}", path.display());
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_tcp(addr: std::net::SocketAddr, app: Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    eprintln!("listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn cmd_key(args: KeyArgs) -> Result<()> {
    let state = AppState::load(args.keys_file, args.sys_config)?;
    let api = match args.api {
        ApiArg::Auto => state.default_api(),
        ApiArg::V0 => Api::V0,
        ApiArg::V1 => Api::V1,
    };
    let result = state
        .derive(
            api,
            &args.name,
            &args.purpose,
            &args.algorithm,
            args.root_epoch,
            args.app_epoch,
        )
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result.to_json())?);
    } else {
        println!("api:        {}", result.api.as_str());
        println!("root_epoch: {}", result.root_epoch);
        println!("app_epoch:  {}", result.app_epoch);
        println!("key:        {}", hex::encode(&result.key));
        println!("public_key: {}", hex::encode(&result.public_key));
        println!("signature_chain:");
        for (i, link) in result.signature_chain.iter().enumerate() {
            println!("  [{i}] {}", hex::encode(link));
        }
    }
    Ok(())
}

async fn cmd_info(args: InfoArgs) -> Result<()> {
    let state = AppState::load(args.keys_file, args.sys_config)?;
    let info = state.info_json().await;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!(
            "guest_version:       {}",
            info["guest_version"].as_str().unwrap_or("unknown")
        );
        println!(
            "api:                 {}",
            info["api"].as_str().unwrap_or("?")
        );
        println!(
            "kms_url:             {}",
            info["kms_url"].as_str().unwrap_or("?")
        );
        println!(
            "current_root_epoch:  {}",
            info["current_root_epoch"].as_u64().unwrap_or(0)
        );
        println!(
            "current_app_epoch:   {}",
            info["current_app_epoch"].as_u64().unwrap_or(0)
        );
        println!(
            "epoch0_available:    {}",
            info["epoch0_available"].as_bool().unwrap_or(false)
        );
        if let Some(err) = info["epoch0_error"].as_str() {
            println!("epoch0_error:        {err}");
        }
    }
    Ok(())
}

async fn cmd_serve(args: ServeArgs) -> Result<()> {
    if args.no_socket && args.no_addr {
        bail!("nothing to listen on: both --no-socket and --no-addr are set");
    }
    let state = Arc::new(AppState::load(args.keys_file, args.sys_config)?);
    let app = router(state);

    match (args.no_socket, args.no_addr) {
        (false, false) => {
            tokio::try_join!(
                serve_unix(args.socket, app.clone()),
                serve_tcp(args.addr, app)
            )?;
        }
        (false, true) => serve_unix(args.socket, app).await?,
        (true, false) => serve_tcp(args.addr, app).await?,
        (true, true) => unreachable!(),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Key(args) => cmd_key(args).await,
        Command::Info(args) => cmd_info(args).await,
        Command::Serve(args) => cmd_serve(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DUMMY_K256_KEY` from the guest-agent tests.
    const DUMMY_K256_KEY: [u8; 32] = [
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B, 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C,
        0x6D, 0x7E, 0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0x0F,
        0x1A, 0x2B,
    ];

    /// The same vector `get_key_pins_the_frozen_chain_link` asserts in the
    /// guest agent: path "test", purpose "signing", secp256k1.
    #[test]
    fn v0_matches_the_frozen_vector() {
        let (key, public_key, link0) =
            derive_v0(&DUMMY_K256_KEY, "test", "signing", "secp256k1").unwrap();
        assert_eq!(
            hex::encode(&key),
            "52786aa123b0971e283af97f32e25767483d099d66e6c40afeb3a49046b5379e"
        );
        assert_eq!(
            hex::encode(&public_key),
            "02ead9e0064aad1bb151c270c78ef82a4caf6d3fc92c311804e79751deb3476919"
        );
        assert_eq!(
            hex::encode(&link0),
            "c8a3dcf06c4e95bd78a5d7a1c8fcff171fc5848cfae804c6fc11bda4dc5d4062\
             379995390843827444992c4c0e4bac70f0f878e01b9fc8b98cd7126fe5a3876b01"
        );
    }

    /// v0 ignored `purpose` in the KDF, so the key is the same with or without it.
    #[test]
    fn v0_purpose_does_not_change_the_key() {
        let (a, _, _) = derive_v0(&DUMMY_K256_KEY, "test", "", "secp256k1").unwrap();
        let (b, _, _) = derive_v0(&DUMMY_K256_KEY, "test", "signing", "secp256k1").unwrap();
        assert_eq!(a, b);
    }

    /// v1 vector from `docs/guest-api-v1.md`.
    #[test]
    fn v1_matches_the_documented_vector() {
        let (key, public_key, _) =
            derive_v1(&DUMMY_K256_KEY, "storage-encryption", "secp256k1").unwrap();
        assert_eq!(
            hex::encode(&key),
            "5510330f86902ddae38c6d89c93a8408019332c17a429e1abd01c4a28d1544a6"
        );
        assert_eq!(
            hex::encode(&public_key),
            "03d962450a41748021c8b02787ac36ce642ff0ae25f4c55019eb527e1112cfd764"
        );
    }

    /// v1 and v0 must not collide for the same name.
    #[test]
    fn v0_and_v1_differ() {
        let (v0, _, _) = derive_v0(&DUMMY_K256_KEY, "test", "", "secp256k1").unwrap();
        let (v1, _, _) = derive_v1(&DUMMY_K256_KEY, "test", "secp256k1").unwrap();
        assert_ne!(v0, v1);
    }

    /// ed25519 reads the same 32 bytes as an RFC 8032 seed.
    #[test]
    fn ed25519_uses_the_same_kdf_output() {
        let (key, public_key, _) = derive_v0(&DUMMY_K256_KEY, "test", "", "ed25519").unwrap();
        let seed: [u8; 32] = key.as_slice().try_into().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(public_key, sk.verifying_key().to_bytes());
    }
}
