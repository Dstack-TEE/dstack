// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{future::pending, os::unix::net::UnixListener as StdUnixListener, time::Duration};

use crate::config::BindAddr;
use crate::guest_api_service::GuestApiHandler;
use crate::http_routes;
use crate::rpc_service::{AppState, ExternalRpcHandler, InternalRpcHandler, InternalRpcHandlerV0};
use crate::socket_activation::{ActivatedSockets, ActivatedUnixListener};
use anyhow::{anyhow, Context, Result};
use ra_rpc::rocket_helper::UnixPeerCredListener;
use rocket::{
    fairing::AdHoc,
    figment::Figment,
    listener::{unix::UnixListener, Bind, DefaultListener, Endpoint},
};
use rocket_vsock_listener::VsockListener;
use sd_notify::{notify as sd_notify, NotifyState};
use tokio::sync::oneshot;
use tracing::{error, info};

pub fn app_version() -> String {
    format!("v{} ({})", crate::CARGO_PKG_VERSION, crate::GIT_REV)
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

async fn run_internal(
    state: AppState,
    figment: Figment,
    activated_socket: Option<StdUnixListener>,
    sock_ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let rocket = rocket::custom(figment)
        .mount("/", ra_rpc::prpc_routes!(AppState, InternalRpcHandler))
        .manage(state);
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
    let rocket = rocket::custom(figment)
        .mount("/", http_routes::external_routes(state.config()))
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(AppState, ExternalRpcHandler, trim: "Worker."),
        )
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
