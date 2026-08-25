// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{future::pending, os::unix::net::UnixListener as StdUnixListener, time::Duration};

use crate::config::BindAddr;
use crate::guest_api_service::GuestApiHandler;
use crate::http_routes;
use crate::rpc_service::{AppState, ExternalRpcHandler, InternalRpcHandler, InternalRpcHandlerV0};
use crate::rpc_service_v1::{ExternalV1RpcHandler, V1RpcHandler};
use crate::socket_activation::{ActivatedSockets, ActivatedUnixListener};
use anyhow::{anyhow, Context, Result};
use ra_rpc::rocket_helper::UnixPeerCredListener;
use rocket::{
    fairing::AdHoc,
    figment::Figment,
    listener::{unix::UnixListener, Bind, DefaultListener, Endpoint},
    Build, Rocket,
};
use rocket_vsock_listener::VsockListener;
use sd_notify::{notify as sd_notify, NotifyState};
use tokio::sync::oneshot;
use tracing::{error, info};

pub fn app_version() -> String {
    dstack_build_info::app_version!()
}

async fn run_internal_v0(
    state: AppState,
    figment: Figment,
    activated_socket: Option<StdUnixListener>,
    sock_ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let rocket = rocket::custom(figment)
        .mount(
            "/prpc/",
            ra_rpc::prpc_routes!(AppState, InternalRpcHandlerV0, trim: "Tappd."),
        )
        .manage(state);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;

    if let Some(std_listener) = activated_socket {
        info!("Using systemd-activated socket for tappd.sock");
        let listener = UnixPeerCredListener::new(ActivatedUnixListener::new(std_listener)?);
        sock_ready_tx.send(()).ok();
        ignite
            .launch_on(listener)
            .await
            .map_err(|err: rocket::Error| anyhow!(err.to_string()))?;
    } else {
        let endpoint = DefaultListener::bind_endpoint(&ignite)
            .map_err(|err| anyhow!("Failed to get endpoint: {err}"))?;
        sock_ready_tx.send(()).ok();
        match endpoint {
            Endpoint::Unix(_) => {
                let listener = UnixPeerCredListener::new(
                    <UnixListener as Bind>::bind(&ignite)
                        .await
                        .map_err(|err| anyhow!("Failed to bind on {endpoint}: {err}"))?,
                );
                ignite
                    .launch_on(listener)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
            }
            _ => {
                let listener = DefaultListener::bind(&ignite)
                    .await
                    .map_err(|err| anyhow!("Failed to bind on {endpoint}: {err}"))?;
                ignite
                    .launch_on(listener)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
            }
        }
    }
    Ok(())
}

/// Mount everything the internal socket serves.
///
/// `/v0` is the name of the frozen v0.5.11 surface and `/v1` is the current
/// one. `/` is the same frozen surface under its historical path, kept as a
/// compatibility alias so a pre-0.6 client keeps working unchanged -- it is the
/// identical handler, not a copy, so the two paths cannot drift.
///
/// Selection is by URL path alone: no header negotiation, no default-version
/// redirect, so a caller's URL is the whole record of which contract it asked
/// for.
///
/// Factored out of `run_internal` so a test can exercise the real mount table
/// rather than a restatement of it.
fn mount_internal(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket
        .mount("/", ra_rpc::prpc_routes!(AppState, InternalRpcHandler))
        .mount("/v0", ra_rpc::prpc_routes!(AppState, InternalRpcHandler))
        .mount("/v1", ra_rpc::prpc_routes!(AppState, V1RpcHandler))
}

/// Mount the pRPC services the external listener serves.
///
/// Same scheme as the internal socket, one level down: `/prpc/v0` is the frozen
/// v0.5.11 `Worker`, `/prpc/v1` is the v1 `Worker`, and `/prpc` is the frozen
/// surface under its historical path.
///
/// The `trim` on the frozen mounts strips the service name a pre-0.6 client
/// prefixes, so `/prpc/Worker.Info` and `/prpc/Info` both land on `Info`.
fn mount_external(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(AppState, ExternalRpcHandler, trim: "Worker."),
        )
        .mount(
            "/prpc/v0",
            ra_rpc::prpc_routes!(AppState, ExternalRpcHandler, trim: "Worker."),
        )
        .mount(
            "/prpc/v1",
            ra_rpc::prpc_routes!(AppState, ExternalV1RpcHandler),
        )
}

async fn run_internal(
    state: AppState,
    figment: Figment,
    activated_socket: Option<StdUnixListener>,
    sock_ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let rocket = mount_internal(rocket::custom(figment)).manage(state);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;

    if let Some(std_listener) = activated_socket {
        info!("Using systemd-activated socket for dstack.sock");
        let listener = UnixPeerCredListener::new(ActivatedUnixListener::new(std_listener)?);
        sock_ready_tx.send(()).ok();
        ignite
            .launch_on(listener)
            .await
            .map_err(|err: rocket::Error| anyhow!(err.to_string()))?;
    } else {
        let endpoint = DefaultListener::bind_endpoint(&ignite)
            .map_err(|err| anyhow!("Failed to get endpoint: {err}"))?;
        sock_ready_tx.send(()).ok();
        match endpoint {
            Endpoint::Unix(_) => {
                let listener = UnixPeerCredListener::new(
                    <UnixListener as Bind>::bind(&ignite)
                        .await
                        .map_err(|err| anyhow!("Failed to bind on {endpoint}: {err}"))?,
                );
                ignite
                    .launch_on(listener)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
            }
            _ => {
                let listener = DefaultListener::bind(&ignite)
                    .await
                    .map_err(|err| anyhow!("Failed to bind on {endpoint}: {err}"))?;
                ignite
                    .launch_on(listener)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
            }
        }
    }
    Ok(())
}

async fn run_external(state: AppState, figment: Figment) -> Result<()> {
    let rocket = mount_external(rocket::custom(figment))
        .mount("/", http_routes::external_routes(state.config()))
        .attach(AdHoc::on_response("Add app version header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .manage(state);
    let _ = rocket
        .launch()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    Ok(())
}

async fn run_guest_api(state: AppState, figment: Figment) -> Result<()> {
    let rocket = rocket::custom(figment)
        .mount("/api", ra_rpc::prpc_routes!(AppState, GuestApiHandler))
        .manage(state);

    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    if DefaultListener::bind_endpoint(&ignite).is_ok() {
        let listener = DefaultListener::bind(&ignite)
            .await
            .map_err(|err| anyhow!("Failed to bind guest API : {err}"))?;
        ignite
            .launch_on(listener)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
    } else {
        let listener = VsockListener::bind_rocket(&ignite)
            .map_err(|err| anyhow!("Failed to bind guest API : {err}"))?;
        ignite
            .launch_on(listener)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
    }
    Ok(())
}

async fn run_watchdog(port: u16) {
    let mut watchdog_usec = 0;
    let enabled = sd_notify::watchdog_enabled(false, &mut watchdog_usec);
    if !enabled {
        info!("Watchdog is not enabled in systemd service");
        return pending::<()>().await;
    }

    info!("Starting watchdog");
    if let Err(err) = sd_notify(false, &[NotifyState::Ready]) {
        error!("Failed to notify systemd: {err}");
    }
    let heatbeat_interval = Duration::from_micros(watchdog_usec / 2);
    let heatbeat_interval = heatbeat_interval.max(Duration::from_secs(1));
    info!("Watchdog enabled, interval={watchdog_usec}us, heartbeat={heatbeat_interval:?}");
    let mut interval = tokio::time::interval(heatbeat_interval);

    let probe_url = format!("http://localhost:{port}/prpc/Worker.Version");
    loop {
        interval.tick().await;

        let client = reqwest::Client::new();
        match client.get(&probe_url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Err(err) = sd_notify(false, &[NotifyState::Watchdog]) {
                    error!("Failed to notify systemd: {err}");
                }
            }
            Ok(response) => {
                error!("Health check failed with status: {}", response.status());
            }
            Err(err) => {
                error!("Health check request failed: {err:?}");
            }
        }
    }
}

pub async fn run(state: AppState, figment: Figment, watchdog: bool) -> Result<()> {
    let internal_v0_figment = figment.clone().select("internal-v0");
    let internal_figment = figment.clone().select("internal");
    let external_figment = figment.clone().select("external");
    let bind_addr = if watchdog {
        Some(
            external_figment
                .extract::<BindAddr>()
                .context("Failed to extract bind address")?,
        )
    } else {
        None
    };
    let guest_api_figment = figment.select("guest-api");

    let activated = ActivatedSockets::from_env();
    if activated.any_activated() {
        info!("Systemd socket activation detected");
    }

    let (tappd_ready_tx, tappd_ready_rx) = oneshot::channel();
    let (sock_ready_tx, sock_ready_rx) = oneshot::channel();
    tokio::select!(
        res = run_internal_v0(state.clone(), internal_v0_figment, activated.tappd, tappd_ready_tx) => res?,
        res = run_internal(state.clone(), internal_figment, activated.dstack, sock_ready_tx) => res?,
        res = run_external(state.clone(), external_figment) => res?,
        res = run_guest_api(state.clone(), guest_api_figment) => res?,
        _ = async {
            let _ = tappd_ready_rx.await;
            let _ = sock_ready_rx.await;
            if let Some(bind_addr) = bind_addr {
                run_watchdog(bind_addr.port).await;
            } else {
                pending::<()>().await;
            }
        } => {}
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_service::tests::setup_test_state;
    use rocket::local::asynchronous::Client;

    /// One agent, serving a whole mount table, for the life of a test.
    ///
    /// A `Client` per request would compare two different rocket instances and
    /// two different `AppState`s; the alias property under test is that `/v0`
    /// and `/` reach the *same* handler on the *same* instance.
    async fn client(
        mount: fn(Rocket<Build>) -> Rocket<Build>,
    ) -> (Client, tempfile::NamedTempFile) {
        let (state, guard) = setup_test_state().await;
        let client = Client::tracked(mount(rocket::build()).manage(state))
            .await
            .expect("rocket failed to ignite");
        (client, guard)
    }

    async fn get(client: &Client, path: &str) -> (u16, String) {
        let response = client.get(path).dispatch().await;
        let status = response.status().code;
        (status, response.into_string().await.unwrap_or_default())
    }

    /// The frozen surface answers identically on `/v0` and on the unversioned
    /// path it has always had.
    ///
    /// The alias is what lets a pre-0.6 client keep working, so it has to stay
    /// the same handler rather than a second one that happens to agree today.
    #[tokio::test]
    async fn the_internal_v0_mount_is_an_alias_for_the_unversioned_path() {
        let (client, _guard) = client(mount_internal).await;
        let (unversioned_status, unversioned) = get(&client, "/Version").await;
        let (v0_status, v0) = get(&client, "/v0/Version").await;

        assert_eq!(unversioned_status, 200, "{unversioned}");
        assert_eq!(v0_status, 200, "{v0}");
        assert_eq!(unversioned, v0);
        assert!(v0.contains("version"), "{v0}");
    }

    /// Same on the external listener, one level down.
    #[tokio::test]
    async fn the_external_v0_mount_is_an_alias_for_the_unversioned_path() {
        let (client, _guard) = client(mount_external).await;
        let (unversioned_status, unversioned) = get(&client, "/prpc/Version").await;
        let (v0_status, v0) = get(&client, "/prpc/v0/Version").await;

        assert_eq!(unversioned_status, 200, "{unversioned}");
        assert_eq!(v0_status, 200, "{v0}");
        assert_eq!(unversioned, v0);
    }

    /// A pre-0.6 client prefixes the service name. That has to keep working on
    /// the alias and on `/v0`.
    #[tokio::test]
    async fn the_external_mounts_accept_the_service_name_prefix() {
        let (client, _guard) = client(mount_external).await;
        for path in ["/prpc/Worker.Version", "/prpc/v0/Worker.Version"] {
            let (status, body) = get(&client, path).await;
            assert_eq!(status, 200, "{path}: {body}");
        }
    }

    /// The version in the path selects the surface, and nothing else does.
    #[tokio::test]
    async fn each_internal_mount_serves_only_its_own_surface() {
        let (client, _guard) = client(mount_internal).await;

        // `Verify` is frozen-only; `IssueCert` is v1-only.
        let (status, _) = get(&client, "/v1/Verify").await;
        assert_ne!(status, 200, "/v1 must not serve the frozen Verify");

        for path in ["/IssueCert", "/v0/IssueCert"] {
            let (status, _) = get(&client, path).await;
            assert_ne!(status, 200, "{path} must not serve the v1 IssueCert");
        }
    }

    #[tokio::test]
    async fn each_external_mount_serves_only_its_own_surface() {
        let (client, _guard) = client(mount_external).await;

        // `Health` is v1-only on the external listener.
        for path in ["/prpc/Health", "/prpc/v0/Health"] {
            let (status, _) = get(&client, path).await;
            assert_ne!(status, 200, "{path} must not serve the v1 Health");
        }
    }

    /// How a client tells "this agent has no v1" from "v1 said no".
    ///
    /// Both an absent mount and an unknown method answer 404, so the status
    /// alone is not enough: only the body separates them. A failed handler is
    /// the 400. `docs/guest-api-v1.md` documents this as the probe rule, and
    /// this test is what keeps the documented rule true.
    #[tokio::test]
    async fn version_probing_can_tell_an_absent_mount_from_an_unknown_method() {
        let (state, _guard) = setup_test_state().await;
        // An agent that predates v1: the frozen surface and nothing else.
        let pre_v1 = Client::tracked(
            rocket::build()
                .mount("/", ra_rpc::prpc_routes!(AppState, InternalRpcHandler))
                .manage(state),
        )
        .await
        .expect("rocket failed to ignite");

        // No `/v1` mount: Rocket has no route to match, and answers its own
        // 404 page. This is what an agent too old for v1 looks like.
        let (status, body) = get(&pre_v1, "/v1/GetKey").await;
        assert_eq!(status, 404);
        assert!(!body.contains("Service not found"), "{body}");

        // A mounted surface, unknown method: also 404, but prpc's, naming the
        // method. This is what a *current* agent says to a method it lacks.
        let (status, body) = get(&pre_v1, "/NoSuchMethod").await;
        assert_eq!(status, 404);
        assert!(body.contains("Service not found: NoSuchMethod"), "{body}");

        // A mounted surface, known method, handler says no: 400.
        let (status, _) = get(&pre_v1, "/EmitEvent").await;
        assert_eq!(status, 400);
    }
}
