// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Aggregate container health, as polled by the gateway.
//!
//! The gateway uses this to decide whether this instance belongs in its app's
//! load-balancing rotation. Registration happens during boot, long before
//! `app-compose.service` has pulled an image or started a container, so
//! "registered" on its own is a poor proxy for "can serve a request".
//!
//! Both container runners are covered. Docker is queried over its socket;
//! nerdctl is queried by running the CLI, because its state lives in containerd
//! rather than behind a Docker-compatible socket. The two report the same four
//! health strings -- nerdctl's inspect output is generated from its
//! `dockercompat` types -- so the rule itself is shared.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use bollard::container::ListContainersOptions;
use bollard::Docker;
use serde::Deserialize;
use tokio::process::Command;

/// The label `docker compose` stamps on every container it starts.
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";

/// The containerd namespace `app-compose.sh` runs nerdctl in.
///
/// Kept in sync with `NERDCTL_NAMESPACE` there. The namespace is dedicated to
/// the app, which is why the nerdctl path needs no label filter: everything in
/// it belongs to the app by construction.
const NERDCTL_NAMESPACE: &str = "dstack";

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

impl HealthReport {
    /// Nothing to judge, so nothing to hold traffic back for.
    fn not_judged() -> Self {
        Self {
            healthy: true,
            unhealthy: vec![],
        }
    }
}

/// Judge the app's containers, dispatching on the runner it was started with.
///
/// Only containers that declare a Compose `healthcheck` are judged. Both
/// runtimes populate a health status exclusively for those, so its absence is
/// the app saying "I have not told you how to test this one" rather than a
/// pass. That keeps this from failing an app for a one-shot init container
/// that exited cleanly.
pub(crate) async fn collect(runner: &str) -> Result<HealthReport> {
    match runner {
        "docker-compose" => collect_docker().await,
        "nerdctl-compose" => collect_nerdctl().await,
        // The `bash` runner runs a script, not containers. There is nothing to
        // inspect and never will be, so it must not sit at "not started yet".
        _ => Ok(HealthReport::not_judged()),
    }
}

async fn collect_docker() -> Result<HealthReport> {
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
            .and_then(|health| health.status)
            .map(|status| status.to_string());
        observed.push((container_name(summary.names.as_deref(), id), status));
    }
    Ok(judge(observed))
}

async fn collect_nerdctl() -> Result<HealthReport> {
    let ids = nerdctl(&["ps", "-a", "-q"])
        .await
        .context("failed to list nerdctl containers")?;
    let ids = ids
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(judge(vec![]));
    }

    let mut args = vec!["inspect"];
    args.extend_from_slice(&ids);
    let raw = nerdctl(&args)
        .await
        .context("failed to inspect nerdctl containers")?;
    let containers: Vec<NerdctlContainer> =
        serde_json::from_str(&raw).context("failed to parse nerdctl inspect output")?;

    let observed = containers
        .into_iter()
        .map(|container| {
            let status = container
                .state
                .and_then(|state| state.health)
                .map(|health| health.status);
            let name = if container.name.is_empty() {
                container.id
            } else {
                container.name
            };
            (name.trim_start_matches('/').to_string(), status)
        })
        .collect();
    Ok(judge(observed))
}

async fn nerdctl(args: &[&str]) -> Result<String> {
    let output = Command::new("nerdctl")
        .arg("--namespace")
        .arg(NERDCTL_NAMESPACE)
        .args(args)
        .output()
        .await
        .context("failed to run nerdctl")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nerdctl {} failed: {}", args.join(" "), stderr.trim());
    }
    String::from_utf8(output.stdout).context("nerdctl produced non-utf8 output")
}

/// The slice of `nerdctl inspect` output this needs. Generated from nerdctl's
/// `dockercompat` types, so the shape and the status strings match Docker's.
#[derive(Deserialize)]
struct NerdctlContainer {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "State", default)]
    state: Option<NerdctlState>,
}

#[derive(Deserialize)]
struct NerdctlState {
    #[serde(rename = "Health", default)]
    health: Option<NerdctlHealth>,
}

#[derive(Deserialize)]
struct NerdctlHealth {
    #[serde(rename = "Status", default)]
    status: String,
}

/// Turn what the runtime reported into a verdict.
///
/// Split from the collectors so the rule itself can be tested without a
/// container runtime to talk to, and so both runners share one definition of
/// what "healthy" means.
///
/// `starting` counts as not healthy: that state is exactly the boot window this
/// is meant to keep traffic out of. So does finding no container at all, which
/// means Compose has not yet got as far as creating one.
fn judge(containers: Vec<(String, Option<String>)>) -> HealthReport {
    // No container exists yet. Registration happens in
    // `dstack-prepare.service` and `app-compose.service` is ordered after it,
    // so this is the window where the image may still be pulling -- exactly
    // what the gateway must keep traffic out of. A runtime answering while
    // having nothing to show is not the same as the app being fine.
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
        match status.as_deref() {
            // No healthcheck declared, or none reported yet.
            None | Some("") | Some("none") => {}
            Some("healthy") => {}
            // "starting", "unhealthy", and anything a future runtime version
            // invents. Unknown states hold traffic back rather than pass.
            Some(other) => unhealthy.push(UnhealthyContainer {
                name,
                status: other.to_string(),
            }),
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

    fn named(name: &str, status: Option<&str>) -> (String, Option<String>) {
        (name.to_string(), status.map(str::to_string))
    }

    /// The window this whole feature exists for: the CVM has registered, the
    /// runtime is answering, and Compose has not created anything yet.
    #[test]
    fn no_container_yet_is_not_healthy() {
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
            named("db", Some("none")),
            named("init", Some("")),
        ]);
        assert!(report.healthy);
        assert!(report.unhealthy.is_empty());
    }

    #[test]
    fn every_declared_healthcheck_passing_is_healthy() {
        let report = judge(vec![named("web", Some("healthy")), named("sidecar", None)]);
        assert!(report.healthy);
    }

    /// `starting` is the boot window, so it must not count as ready.
    #[test]
    fn a_starting_container_is_not_healthy() {
        let report = judge(vec![
            named("web", Some("healthy")),
            named("api", Some("starting")),
        ]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].name, "api");
        assert_eq!(report.unhealthy[0].status, "starting");
    }

    #[test]
    fn one_unhealthy_container_fails_the_instance() {
        let report = judge(vec![
            named("web", Some("healthy")),
            named("api", Some("unhealthy")),
        ]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].status, "unhealthy");
    }

    /// Fail closed: a state neither runtime documents today must hold traffic
    /// back rather than be waved through as "not healthy but not a problem".
    #[test]
    fn an_unrecognised_state_holds_traffic_back() {
        let report = judge(vec![named("web", Some("degraded"))]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].status, "degraded");
    }

    #[test]
    fn docker_names_lose_their_leading_slash() {
        assert_eq!(
            container_name(Some(&["/app-web-1".to_string()]), "id"),
            "app-web-1"
        );
        assert_eq!(container_name(None, "fallback-id"), "fallback-id");
    }

    /// nerdctl's inspect output is generated from its `dockercompat` types, so
    /// the fields this depends on line up with Docker's.
    #[test]
    fn nerdctl_inspect_output_parses() {
        let raw = r#"[
          {"Id":"abc123","Name":"/dstack-web-1",
           "State":{"Status":"running","Running":true,
                    "Health":{"Status":"healthy","FailingStreak":0}}},
          {"Id":"def456","Name":"dstack-db-1",
           "State":{"Status":"running","Running":true}}
        ]"#;
        let containers: Vec<NerdctlContainer> = serde_json::from_str(raw).unwrap();
        assert_eq!(containers.len(), 2);
        assert_eq!(
            containers[0]
                .state
                .as_ref()
                .and_then(|s| s.health.as_ref())
                .map(|h| h.status.as_str()),
            Some("healthy")
        );
        // A container with no healthcheck has no Health object at all.
        assert!(containers[1]
            .state
            .as_ref()
            .and_then(|s| s.health.as_ref())
            .is_none());
    }
}
