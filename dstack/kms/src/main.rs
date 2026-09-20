// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use config::KmsConfig;
use main_service::{KmsState, RpcHandler};
use onboard_service::{OnboardHandler, OnboardState};
use ra_rpc::ratls_client_verifier::RaTlsClientAuth;
use ra_rpc::rocket_helper::QuoteVerifier;
use ra_tls::attestation::AttestationVerifier;
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
    response::content::{RawHtml, RawText},
    tls::Resolver as _,
    Shutdown, State,
};
use tracing::{info, warn};

mod admin_auth;
mod admin_service;
mod config;
mod crypto;
mod main_service;
mod onboard_auth;
mod onboard_service;

fn app_version() -> String {
    dstack_build_info::app_version!()
}

#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

fn build_onboard_rocket(
    kms_config: &KmsConfig,
    figment: Figment,
    state: OnboardState,
) -> Result<rocket::Rocket<rocket::Build>> {
    #[rocket::get("/")]
    async fn index() -> RawHtml<&'static str> {
        RawHtml(include_str!("www/onboard.html"))
    }
    #[rocket::get("/finish")]
    fn finish(shutdown: Shutdown) -> &'static str {
        shutdown.notify();
        "OK"
    }

    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("core.onboard")?));

    // No `tls` section is merged here: the KMS has no certificate to serve until
    // bootstrap has produced one. Callers are operators rather than attested
    // peers, so this listener is guarded by a shared credential - see
    // `onboard_auth`.
    Ok(rocket::custom(figment)
        .attach(onboard_auth::OnboardAuthFairing::from_config(
            &kms_config.onboard,
        )?)
        .mount("/", rocket::routes![index, finish, health])
        .mount("/", onboard_auth::routes())
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(OnboardState, OnboardHandler, trim: "Onboard."),
        )
        .manage(state))
}

async fn run_onboard_service(kms_config: KmsConfig, figment: Figment) -> Result<()> {
    if !kms_config.onboard.auto_bootstrap_domain.is_empty() {
        let verifier = AttestationVerifier::load(&kms_config.attestation)
            .context("failed to load attestation verifier")?;
        onboard_service::bootstrap_keys(&kms_config, &verifier).await?;
        return Ok(());
    }

    let state = OnboardState::new(kms_config.clone())?;
    let rocket = build_onboard_rocket(&kms_config, figment, state.clone())?
        .ignite()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    state.set_shutdown(rocket.shutdown())?;
    let _ = rocket
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

#[rocket::get("/health")]
fn health() -> RawText<&'static str> {
    RawText("OK")
}

#[rocket::get("/metrics")]
fn metrics(state: &State<KmsState>) -> RawText<String> {
    RawText(state.metrics().render_prometheus())
}

// Count only RPCs whose primary job is to verify caller/app attestation.
// Recording in a response fairing also catches failures that happen before
// RpcHandler is constructed, such as malformed RA-TLS attestation.
fn is_attestation_rpc_path(path: &str) -> bool {
    let Some(method) = path.strip_prefix("/prpc/") else {
        return false;
    };
    let method = method.trim_start_matches("KMS.");
    matches!(method, "GetAppKey" | "GetKmsKey" | "SignCert")
}

fn record_attestation_metrics(req: &rocket::Request<'_>, res: &rocket::Response<'_>) {
    if !is_attestation_rpc_path(req.uri().path().as_str()) {
        return;
    }
    let Some(state) = req.rocket().state::<KmsState>() else {
        return;
    };
    state
        .metrics()
        .record_attestation_request(res.status().code >= 400);
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }
    let args = Args::parse();

    let figment = config::load_config_figment(args.config.as_deref());
    let config: KmsConfig = figment.focus("core").extract()?;

    if !config.attest_rpc_cert {
        warn!(
            "attest_rpc_cert = false; the KMS RPC certificate carries no attestation, so \
             guests cannot verify which KMS they are talking to. Intended for local \
             development only"
        );
    }

    if config.onboard.enabled && !config.keys_exists() {
        info!("Onboarding");
        run_onboard_service(config.clone(), figment.clone()).await?;
        if !config.keys_exists() {
            bail!("Failed to onboard");
        }
    }

    info!("Updating certs");
    if let Err(err) = onboard_service::update_certs(&config).await {
        if config.attest_rpc_cert {
            return Err(err).context(
                "Failed to reissue the attested KMS RPC certificate; refusing to start with a \
                 potentially unattested certificate",
            );
        }
        warn!("Failed to update certs: {err}");
    };

    info!("Starting KMS");
    info!("Supported methods:");
    for method in main_service::rpc_methods() {
        info!("  /prpc/{method}");
    }

    let metrics_enabled = config.metrics.enabled;
    let admin_config = config.admin.clone();
    // build the admin listener figment from `[core.admin]` before `config` is
    // moved into the state; the fairing is built now so a misconfigured admin
    // (enabled but no credential) fails fast before we start serving.
    let admin_setup = if admin_config.enabled {
        let admin_value = figment
            .find_value("core.admin")
            .context("core.admin section not found")?;
        let admin_figment =
            Figment::from(rocket::Config::default()).merge(Serialized::defaults(admin_value));
        let admin_fairing = admin_auth::AdminAuthFairing::from_config(&admin_config)?;
        Some((admin_figment, admin_fairing))
    } else {
        None
    };
    let state = main_service::KmsState::new(config).context("Failed to initialize KMS state")?;
    let quote_verifier = QuoteVerifier::new(state.attestation_verifier());
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("rpc")?));
    let mut rocket = rocket::custom(figment)
        // Verify client certificates by their attestation rather than by issuer. The
        // certificates guests and onboarding mint from the temp CA today keep working
        // unchanged - they are now accepted for the attestation they carry rather than
        // for who signed them - and a self-issued certificate would be accepted too.
        .attach(RaTlsClientAuth::fairing())
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(KmsState, RpcHandler, trim: "KMS."),
        )
        .mount("/", rocket::routes![health])
        .manage(state.clone());

    if metrics_enabled {
        info!("Prometheus metrics endpoint enabled at /metrics");
        rocket = rocket
            .attach(AdHoc::on_response(
                "Record KMS attestation metrics",
                |req, res| Box::pin(async move { record_attestation_metrics(req, res) }),
            ))
            .mount("/", rocket::routes![metrics]);
    }

    rocket = rocket.manage(quote_verifier);

    let main_srv = rocket.launch();
    match admin_setup {
        Some((admin_figment, admin_fairing)) => {
            if admin_config.insecure_no_auth {
                warn!(
                    "admin API is served with insecure_no_auth = true; the admin RPCs are exposed without authentication"
                );
            } else {
                info!("admin API authentication enabled");
            }
            let admin_srv = rocket::custom(admin_figment)
                .attach(admin_fairing)
                .mount("/", admin_auth::routes())
                .mount(
                    "/prpc",
                    ra_rpc::prpc_routes!(KmsState, admin_service::AdminRpcHandler, trim: "Admin."),
                )
                .manage(state)
                .launch();
            tokio::try_join!(
                async { main_srv.await.map_err(|err| anyhow!(err.to_string())) },
                async { admin_srv.await.map_err(|err| anyhow!(err.to_string())) },
            )?;
        }
        None => {
            main_srv.await.map_err(|err| anyhow!(err.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::providers::{Format, Toml};
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::Client;

    async fn onboard_client(auth_token: &str) -> Client {
        // Nothing in these tests reads or writes the cert dir; the onboarding
        // listener only needs a config that parses.
        let cert_dir = std::env::temp_dir().join("dstack-kms-onboard-auth-test");
        let overrides = format!(
            r#"
            [core]
            cert_dir = "{}"
            attest_rpc_cert = false
            enforce_self_authorization = false

            [core.onboard]
            address = "127.0.0.1"
            port = 0
            auth_token = "{auth_token}"
            "#,
            cert_dir.display()
        );
        let figment = Figment::from(rocket::Config::default())
            .merge(Toml::string(config::DEFAULT_CONFIG))
            .merge(Toml::string(&overrides));
        let kms_config: KmsConfig = figment.focus("core").extract().unwrap();
        let state = OnboardState::new(kms_config.clone()).unwrap();
        let rocket = build_onboard_rocket(&kms_config, figment, state).unwrap();
        Client::tracked(rocket).await.unwrap()
    }

    #[rocket::async_test]
    async fn onboarding_listener_rejects_anonymous_callers_when_a_token_is_set() {
        let client = onboard_client("onboard-secret").await;

        for anonymous in [
            client.get("/").dispatch().await.status(),
            client.get("/finish").dispatch().await.status(),
            client
                .post("/prpc/Onboard.Bootstrap?json")
                .body(r#"{"domain":"kms.example.com"}"#)
                .dispatch()
                .await
                .status(),
            client
                .post("/prpc/Onboard.Onboard?json")
                .body(r#"{"domain":"kms.example.com","source_url":"https://attacker.example"}"#)
                .dispatch()
                .await
                .status(),
        ] {
            assert_eq!(anonymous, Status::Unauthorized);
        }

        let authorized = client
            .get("/finish")
            .header(Header::new("Authorization", "Bearer onboard-secret"))
            .dispatch()
            .await;
        assert_eq!(authorized.status(), Status::Ok);
    }

    /// The documented bring-up drives this listener with plain `curl`, so an
    /// unset token has to keep working. It is warned about at startup instead.
    #[rocket::async_test]
    async fn onboarding_listener_stays_open_when_no_token_is_configured() {
        let client = onboard_client("").await;
        assert_eq!(client.get("/finish").dispatch().await.status(), Status::Ok);
    }
}
