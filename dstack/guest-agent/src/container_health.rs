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
/// this is meant to keep traffic out of. So does finding no Compose container
/// at all, which means Compose has not yet got as far as creating one.
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

    let mut observed = Vec::with_capacity(containers.len());
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
        observed.push((container_name(summary.names.as_deref(), id), status));
    }
    Ok(judge(observed))
}

/// Turn what Docker reported into a verdict.
///
/// Split from [`collect`] so the rule itself can be tested without a Docker
/// daemon to talk to.
fn judge(containers: Vec<(String, Option<HealthStatusEnum>)>) -> HealthReport {
    // No Compose container exists yet. Registration happens in
    // `dstack-prepare.service` and `app-compose.service` is ordered after it,
    // so this is the window where the image may still be pulling -- exactly
    // what the gateway must keep traffic out of. Docker answering while having
    // nothing to show is not the same as the app being fine.
    if containers.is_empty() {
        return HealthReport {
            healthy: false,
            unhealthy: vec![UnhealthyContainer {
                name: "<compose>".to_string(),
                status: "no container has been created yet".to_string(),
            }],
        };
    }

    let mut unhealthy = Vec::new();
    for (name, status) in containers {
        match status {
            // No healthcheck declared, or none reported yet.
            None | Some(HealthStatusEnum::EMPTY) | Some(HealthStatusEnum::NONE) => {}
            Some(HealthStatusEnum::HEALTHY) => {}
            Some(state @ (HealthStatusEnum::STARTING | HealthStatusEnum::UNHEALTHY)) => {
                unhealthy.push(UnhealthyContainer {
                    name,
                    status: state.to_string(),
                });
            }
        }
    }

    HealthReport {
        healthy: unhealthy.is_empty(),
        unhealthy,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str, status: Option<HealthStatusEnum>) -> (String, Option<HealthStatusEnum>) {
        (name.to_string(), status)
    }

    /// The window this whole feature exists for: the CVM has registered, Docker
    /// is answering, and Compose has not created anything yet.
    #[test]
    fn no_compose_container_yet_is_not_healthy() {
        let report = judge(vec![]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy.len(), 1);
        assert_eq!(report.unhealthy[0].name, "<compose>");
    }

    /// Most existing compose files declare no healthcheck. The app has not said
    /// how to test it, so it is not judged.
    #[test]
    fn containers_without_a_healthcheck_are_not_judged() {
        let report = judge(vec![
            named("web", None),
            named("db", Some(HealthStatusEnum::NONE)),
            named("init", Some(HealthStatusEnum::EMPTY)),
        ]);
        assert!(report.healthy);
        assert!(report.unhealthy.is_empty());
    }

    #[test]
    fn every_declared_healthcheck_passing_is_healthy() {
        let report = judge(vec![
            named("web", Some(HealthStatusEnum::HEALTHY)),
            named("sidecar", None),
        ]);
        assert!(report.healthy);
    }

    /// `starting` is the boot window, so it must not count as ready.
    #[test]
    fn a_starting_container_is_not_healthy() {
        let report = judge(vec![
            named("web", Some(HealthStatusEnum::HEALTHY)),
            named("api", Some(HealthStatusEnum::STARTING)),
        ]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].name, "api");
        assert_eq!(report.unhealthy[0].status, "starting");
    }

    #[test]
    fn one_unhealthy_container_fails_the_instance() {
        let report = judge(vec![
            named("web", Some(HealthStatusEnum::HEALTHY)),
            named("api", Some(HealthStatusEnum::UNHEALTHY)),
        ]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].status, "unhealthy");
    }

    #[test]
    fn docker_names_lose_their_leading_slash() {
        assert_eq!(
            container_name(Some(&["/app-web-1".to_string()]), "id"),
            "app-web-1"
        );
        assert_eq!(container_name(None, "fallback-id"), "fallback-id");
    }
}
