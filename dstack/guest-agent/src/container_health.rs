// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Aggregate container health, as polled by the gateway.
//!
//! The gateway uses this to decide whether this instance belongs in its app's
//! load-balancing rotation. Registration happens during boot, long before
//! `app-compose.service` has pulled an image or started a container, so
//! "registered" on its own is a poor proxy for "can serve a request".

use std::collections::HashMap;

use anyhow::{Context, Result};
use bollard::container::ListContainersOptions;
use bollard::secret::HealthStatusEnum;
use bollard::Docker;

/// The label `docker compose` stamps on every container it starts.
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";

/// One container that is not reporting healthy.
pub(crate) struct UnhealthyContainer {
    pub name: String,
    pub status: String,
}

/// Health of the app's containers.
pub(crate) struct HealthReport {
    pub healthy: bool,
    pub unhealthy: Vec<UnhealthyContainer>,
}

/// Judge every container that declares a Compose `healthcheck`.
///
/// Containers without one are not judged. Docker populates `State.Health` only
/// for containers that declare a healthcheck, so its absence is the app saying
/// "I have not told you how to test this one" rather than a pass. That keeps
/// this from failing an app for a one-shot init container that exited cleanly.
///
/// `starting` counts as not healthy: that state is exactly the boot window
/// this is meant to keep traffic out of.
///
/// Scoped to Compose-managed containers. The CVM is single-tenant, so every
/// Compose container belongs to the app; anything started outside Compose has
/// nothing routed to it and should not be able to gate the instance.
pub(crate) async fn collect() -> Result<HealthReport> {
    let docker = Docker::connect_with_defaults().context("failed to connect to docker")?;
    let mut filters = HashMap::new();
    filters.insert("label", vec![COMPOSE_PROJECT_LABEL]);
    let containers = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
        .context("failed to list containers")?;

    let mut unhealthy = Vec::new();
    for summary in containers {
        let Some(id) = summary.id.as_deref() else {
            continue;
        };
        let details = docker
            .inspect_container(id, None)
            .await
            .with_context(|| format!("failed to inspect container {id}"))?;
        let status = details
            .state
            .and_then(|state| state.health)
            .and_then(|health| health.status);
        match status {
            // No healthcheck declared, or none reported yet.
            None | Some(HealthStatusEnum::EMPTY) | Some(HealthStatusEnum::NONE) => {}
            Some(HealthStatusEnum::HEALTHY) => {}
            Some(state @ (HealthStatusEnum::STARTING | HealthStatusEnum::UNHEALTHY)) => {
                unhealthy.push(UnhealthyContainer {
                    name: container_name(summary.names.as_deref(), id),
                    status: state.to_string(),
                });
            }
        }
    }

    Ok(HealthReport {
        healthy: unhealthy.is_empty(),
        unhealthy,
    })
}

/// Docker returns names with a leading slash; strip it so log lines read the
/// way `docker ps` prints them. Falls back to the id when a container somehow
/// has no name.
fn container_name(names: Option<&[String]>, id: &str) -> String {
    names
        .and_then(|names| names.first())
        .map(|name| name.trim_start_matches('/').to_string())
        .unwrap_or_else(|| id.to_string())
}
