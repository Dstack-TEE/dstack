// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use rocket::figment::Figment;
use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Build, Rocket, State};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tracing::info;

use crate::process::{ProcessConfig, ProcessInfo};
use crate::supervisor::Supervisor;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response<T> {
    Data(T),
    Error(String),
}

impl<T> Response<T> {
    pub fn into_result(self) -> Result<T> {
        match self {
            Response::Data(data) => Ok(data),
            Response::Error(e) => Err(anyhow!(e)),
        }
    }
}

fn to_json<T: Serialize>(r: Result<T>) -> Json<Response<T>> {
    match r {
        Ok(data) => Json(Response::Data(data)),
        Err(e) => Json(Response::Error(format!("{e:?}"))),
    }
}

#[post("/deploy", data = "<config>")]
async fn deploy(supervisor: &State<Supervisor>, config: Json<ProcessConfig>) -> Json<Response<()>> {
    to_json(supervisor.deploy(config.into_inner()))
}

#[post("/start/<id>")]
async fn start(supervisor: &State<Supervisor>, id: &str) -> Json<Response<()>> {
    to_json(supervisor.start(id))
}

#[post("/stop/<id>")]
async fn stop(supervisor: &State<Supervisor>, id: &str) -> Json<Response<()>> {
    to_json(supervisor.stop(id))
}

#[delete("/remove/<id>")]
async fn remove(supervisor: &State<Supervisor>, id: &str) -> Json<Response<()>> {
    to_json(supervisor.remove(id))
}

#[get("/list")]
fn list(supervisor: &State<Supervisor>) -> Json<Response<Vec<ProcessInfo>>> {
    to_json(Ok(supervisor.list()))
}

#[get("/info/<id>")]
fn info(supervisor: &State<Supervisor>, id: &str) -> Json<Response<Option<ProcessInfo>>> {
    to_json(Ok(supervisor.info(id)))
}

#[get("/ping")]
fn ping() -> Json<Response<&'static str>> {
    Json(Response::Data("pong"))
}

#[post("/clear")]
fn clear(supervisor: &State<Supervisor>) -> Json<Response<()>> {
    to_json({
        supervisor.clear();
        Ok(())
    })
}

#[post("/shutdown")]
async fn shutdown(supervisor: &State<Supervisor>) -> Json<Response<()>> {
    to_json(perform_shutdown(supervisor, false).await)
}

async fn perform_shutdown(supervisor: &Supervisor, force: bool) -> Result<()> {
    info!("Shutting down supervisor");
    let result = supervisor.shutdown().await;
    if result.is_ok() || force {
        info!("Supervisor shutdown successfully");
        std::process::exit(0);
    }
    result
}

pub fn rocket(figment: Figment) -> Rocket<Build> {
    let supervisor = Supervisor::new();
    let rocket = rocket::custom(figment).manage(supervisor.clone()).mount(
        "/",
        routes![deploy, start, stop, remove, list, info, ping, clear, shutdown],
    );
    tokio::spawn(handle_shutdown_signals(supervisor));
    rocket
}

async fn handle_shutdown_signals(supervisor: Supervisor) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            println!("Received Ctrl+C signal, initiating shutdown...");
        }
        _ = terminate => {
            println!("Received terminate signal, initiating shutdown...");
        }
    }

    perform_shutdown(&supervisor, true)
        .await
        .expect("Force shutdown should never return");
}
