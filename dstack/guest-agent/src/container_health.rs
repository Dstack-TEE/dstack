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
//!
//! Only the app's own Compose project is judged. Container state lives on the
//! persistent data disk (`/var/lib/{docker,containerd,nerdctl}` are rbind
//! mounted there by `dstack-prepare.sh`), so it outlives reboots and app
//! upgrades: without the filter, one exited container left behind by a previous
//! deployment under a different project name would hold the instance out of
//! rotation forever, and nothing cleans it up -- `--remove-orphans` only ever
//! touches the project it was invoked for.
//!
//! What they do not agree on is what happens to that string once the container
//! stops, which is why the run state is read alongside it. See [`judge`].

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bollard::container::ListContainersOptions;
use bollard::Docker;
use serde::Deserialize;
use tokio::process::Command;
use tracing::debug;
use yaml_rust2::YamlLoader;

/// The label Compose stamps on every container it starts.
///
/// This is the only project label both runners agree on. Measured on docker
/// compose 5.1.4 and nerdctl 2.3.5: docker also writes
/// `com.docker.compose.project.working_dir` and `.config_files`, nerdctl writes
/// neither -- it sets exactly `project`, `service` and `config-hash`. Filtering
/// on a docker-only label would return an empty list under nerdctl, which
/// `judge` reads as "nothing has started yet", i.e. permanently unhealthy on
/// the runner the guest image actually uses.
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";

/// The project name Compose derives when the compose file does not name one.
///
/// Compose uses the basename of the directory it was brought up from, and
/// `app-compose.service` sets `WorkingDirectory=/dstack`.
const DEFAULT_COMPOSE_PROJECT: &str = "dstack";

/// The containerd namespace `app-compose.sh` runs nerdctl in by default.
///
/// An app is free to override `NERDCTL_NAMESPACE` in its own environment. That
/// is not a hole -- everything the app does is measured -- but it does mean an
/// app that overrides it and asks for health gating gets an empty container
/// list, so the label filter below is what carries the meaning either way.
const NERDCTL_NAMESPACE: &str = "dstack";

/// How long a single container-runtime call may take.
///
/// Without this a wedged containerd stalls the refresh loop indefinitely; with
/// it, plus `kill_on_drop`, an abandoned call also reclaims its child process.
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(5);

/// One container that is not reporting healthy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnhealthyContainer {
    pub name: String,
    pub status: String,
}

/// One container as the runtime described it.
#[derive(Debug, PartialEq)]
struct Observed {
    name: String,
    /// `State.Health.Status`. Absent when the container declares no
    /// healthcheck: both runtimes populate this field only for containers that
    /// do.
    health: Option<String>,
    /// `State.Status`: `running`, `exited`, `paused`, `restarting`, ... Absent
    /// when the runtime did not report one.
    state: Option<String>,
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
pub(crate) async fn collect(runner: &str, project: &str) -> Result<HealthReport> {
    match runner {
        "docker-compose" => collect_docker(project).await,
        "nerdctl-compose" => collect_nerdctl(project).await,
        // The `bash` runner runs a script, not containers. There is nothing to
        // inspect and never will be, so it must not sit at "not started yet".
        _ => Ok(HealthReport::not_judged()),
    }
}

/// The Compose project name the app's containers carry.
///
/// Compose takes the top-level `name:` from the compose file and falls back to
/// the basename of the working directory, lowercasing either way. Verified
/// identical on docker compose 5.1.4 and nerdctl 2.3.5: `name: MyApp_X` becomes
/// `myapp_x` on both, and `--filter label=com.docker.compose.project=myapp_x`
/// matches while the un-normalized spelling does not.
///
/// Getting this wrong in the safe direction -- guessing a project that does not
/// exist -- shows up immediately as "no container has been created yet", not as
/// an app being silently waved through.
///
/// Resolved once, when the monitor starts. The compose file is immutable for the
/// life of the CVM, and re-parsing YAML on every refresh would be both waste and
/// a way for an app to spend the agent's CPU: alias expansion is exponential and
/// synchronous, so a crafted file blocks a tokio worker thread past any timeout
/// wrapped around it.
pub(crate) fn compose_project(compose_file: Option<&str>) -> String {
    compose_file
        .and_then(|contents| YamlLoader::load_from_str(contents).ok())
        .and_then(|docs| docs.first()?["name"].as_str().map(str::to_string))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| DEFAULT_COMPOSE_PROJECT.to_string())
}

/// The label filter both runners are queried with, as `key=value`.
fn compose_filter(project: &str) -> String {
    format!("{COMPOSE_PROJECT_LABEL}={project}")
}

async fn collect_docker(project: &str) -> Result<HealthReport> {
    let docker = Docker::connect_with_defaults().context("failed to connect to docker")?;
    let filter = compose_filter(project);
    let mut filters = HashMap::new();
    filters.insert("label", vec![filter.as_str()]);
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
        let details = match docker.inspect_container(id, None).await {
            Ok(details) => details,
            // The container went away between the list and the inspect.
            // `docker compose up` recreates containers on every redeploy and
            // `app-compose.sh` prunes right after, so this window is raced
            // routinely. Judging the rest is strictly better than failing the
            // whole report and dropping the instance out of rotation.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                debug!("container {id} disappeared between list and inspect");
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to inspect container {id}"))
            }
        };
        let state = details.state;
        let health = state
            .as_ref()
            .and_then(|state| state.health.as_ref())
            .and_then(|health| health.status)
            .map(|status| status.to_string());
        let run_state = state
            .as_ref()
            .and_then(|state| state.status)
            .map(|status| status.to_string());
        observed.push(Observed {
            name: container_name(summary.names.as_deref(), id),
            health,
            state: run_state,
        });
    }
    Ok(judge(observed))
}

async fn collect_nerdctl(project: &str) -> Result<HealthReport> {
    let filter = format!("label={}", compose_filter(project));
    let ids = nerdctl(&["ps", "-a", "-q", "--filter", &filter])
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
    Ok(judge(inspect_nerdctl(&ids).await?))
}

/// Inspect every id, tolerating the ones that vanished under us.
///
/// `nerdctl inspect a b c` exits non-zero if *any* id is gone, and -- unlike
/// docker, which still writes the entries it did find -- it writes **nothing**
/// to stdout. Measured on 2.3.5 with one bogus id in a batch of three: exit 1,
/// 0 bytes of stdout, `level=fatal msg="1 errors: [no such object ...]"` on
/// stderr, regardless of where in the batch the bogus id sits.
///
/// So one container recreated between `ps` and `inspect` -- which every
/// redeploy does, and `app-compose.sh`'s prune right after start makes routine
/// -- would otherwise fail the entire report and drop the instance out of
/// rotation. The batch stays the fast path; only when it fails do we pay for
/// one call per container and skip the ones that no longer exist.
async fn inspect_nerdctl(ids: &[&str]) -> Result<Vec<Observed>> {
    let mut args = vec!["inspect"];
    args.extend_from_slice(ids);
    match nerdctl(&args).await {
        Ok(raw) => Ok(parse_nerdctl(&raw)?),
        Err(err) => {
            debug!("batch inspect failed, falling back to one call per container: {err:#}");
            let mut observed = Vec::with_capacity(ids.len());
            for id in ids {
                match nerdctl(&["inspect", id]).await {
                    Ok(raw) => observed.extend(parse_nerdctl(&raw)?),
                    Err(err) => debug!("skipping container {id}: {err:#}"),
                }
            }
            // Every single inspect failing too means the runtime itself is the
            // problem, not a raced container. Report the original error rather
            // than an empty list, which `judge` would read as "nothing started
            // yet".
            if observed.is_empty() {
                return Err(err);
            }
            Ok(observed)
        }
    }
}

fn parse_nerdctl(raw: &str) -> Result<Vec<Observed>> {
    let containers: Vec<NerdctlContainer> =
        serde_json::from_str(raw).context("failed to parse nerdctl inspect output")?;
    Ok(containers.into_iter().map(observe_nerdctl).collect())
}

async fn nerdctl(args: &[&str]) -> Result<String> {
    let run = Command::new("nerdctl")
        .arg("--namespace")
        .arg(NERDCTL_NAMESPACE)
        .args(args)
        // Without this, abandoning the future on timeout leaves the child
        // running: `tokio::process` does not kill it on drop by default.
        .kill_on_drop(true)
        .output();
    let output = match tokio::time::timeout(RUNTIME_TIMEOUT, run).await {
        Ok(output) => output.context("failed to run nerdctl")?,
        Err(_) => bail!("nerdctl {} timed out after {RUNTIME_TIMEOUT:?}", args[0]),
    };
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
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Health", default)]
    health: Option<NerdctlHealth>,
}

/// Reshape one `nerdctl inspect` entry into what [`judge`] reads.
fn observe_nerdctl(container: NerdctlContainer) -> Observed {
    let name = if container.name.is_empty() {
        container.id
    } else {
        container.name
    };
    let (health, state) = match container.state {
        Some(state) => (
            state.health.map(|health| health.status),
            (!state.status.is_empty()).then_some(state.status),
        ),
        None => (None, None),
    };
    Observed {
        name: name.trim_start_matches('/').to_string(),
        health,
        state,
    }
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
///
/// A container that declares a healthcheck and is not running is not healthy
/// either, whatever its last recorded verdict says. That verdict cannot be
/// trusted across a stop, because the two runtimes disagree about it:
///
/// - Docker's daemon re-marks the container `unhealthy` when it leaves the
///   running state (verified on 29.5.3 for `stop`, `kill`, `pause`, and a
///   container exiting on its own).
/// - nerdctl leaves the last result in place. Its `container healthcheck`
///   returns early with "container is not running" *without* writing a new
///   state, and `nerdctl inspect` renders `State.Health` out of the stored
///   state regardless of run state. Verified on 2.3.5: a container that passed
///   its check and then exited -- by `nerdctl stop` or by crashing -- still
///   reports `"Status": "healthy"` with `"Running": false`.
///
/// nerdctl is what the guest image runs, so without this an app whose container
/// crashed after one passing check keeps its instance in the rotation
/// indefinitely: exactly the state this feature exists to detect.
///
/// Containers that declare no healthcheck stay unjudged even when they have
/// exited. A one-shot init container that ran and stopped is normal, and the
/// app has not said how to tell the difference.
fn judge(containers: Vec<Observed>) -> HealthReport {
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
    for container in containers {
        let Observed {
            name,
            health,
            state,
        } = container;
        match health.as_deref() {
            // No healthcheck declared, or none reported yet.
            None | Some("") | Some("none") => {}
            Some(health) if !is_running(state.as_deref()) => unhealthy.push(UnhealthyContainer {
                name,
                status: format!(
                    "{} (last health check: {health})",
                    state.as_deref().unwrap_or("not running")
                ),
            }),
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

/// Whether the runtime says this container is running.
///
/// A container the runtime gave no state for is judged on its health alone: a
/// missing field is not evidence that it stopped, and inventing a failure from
/// one would take an app out of rotation over a shape change in the runtime's
/// output.
fn is_running(state: Option<&str>) -> bool {
    match state {
        None => true,
        Some(state) => state == "running",
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

    /// A running container reporting `status`.
    fn named(name: &str, status: Option<&str>) -> Observed {
        Observed {
            name: name.to_string(),
            health: status.map(str::to_string),
            state: Some("running".to_string()),
        }
    }

    /// A container that is no longer running, with whatever health verdict the
    /// runtime left behind.
    fn stopped(name: &str, state: &str, status: Option<&str>) -> Observed {
        Observed {
            name: name.to_string(),
            health: status.map(str::to_string),
            state: Some(state.to_string()),
        }
    }

    /// The literal, not the constant: what this pins is that the default agrees
    /// with `WorkingDirectory=/dstack` in `app-compose.service`, which Compose
    /// derives the project name from. Comparing against the constant would pass
    /// no matter what the constant said.
    #[test]
    fn a_compose_file_without_a_name_uses_the_working_directory() {
        let compose = "services:\n  web:\n    image: my-app:1.0\n";
        assert_eq!(compose_project(Some(compose)), "dstack");
    }

    #[test]
    fn no_compose_file_at_all_uses_the_working_directory() {
        assert_eq!(compose_project(None), "dstack");
    }

    /// Compose lowercases the project name and both runtimes filter on the
    /// normalized value -- measured on docker compose 5.1.4 and nerdctl 2.3.5,
    /// where `name: MyApp_X` becomes `myapp_x` and matching on the original
    /// spelling returns nothing.
    #[test]
    fn a_declared_name_is_lowercased_the_way_compose_does() {
        let compose = "name: MyApp_X\nservices:\n  web:\n    image: my-app:1.0\n";
        assert_eq!(compose_project(Some(compose)), "myapp_x");
    }

    /// Guessing a project that does not exist shows up immediately as "no
    /// container has been created yet"; guessing nothing and judging everything
    /// is what lets a previous deployment's leftovers hold an instance down.
    #[test]
    fn an_unparseable_compose_file_falls_back_rather_than_judging_everything() {
        assert_eq!(compose_project(Some("\tname: [unbalanced")), "dstack");
        assert_eq!(compose_project(Some("")), "dstack");
        assert_eq!(
            compose_project(Some("name: '  '\nservices: {}\n")),
            "dstack"
        );
    }

    #[test]
    fn the_filter_is_the_label_both_runtimes_set() {
        assert_eq!(
            compose_filter("myapp"),
            "com.docker.compose.project=myapp",
            "nerdctl sets only project/service/config-hash, so this is the only \
             project label the two runtimes agree on"
        );
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

    /// The case the run-state check exists for. Captured behaviour, not a
    /// hypothesis: on nerdctl 2.3.5 a container that passed its check and then
    /// exited still reports `healthy`, so judging on the health string alone
    /// keeps a dead app in the rotation.
    #[test]
    fn a_container_that_passed_its_check_and_then_exited_is_not_healthy() {
        let report = judge(vec![stopped("web", "exited", Some("healthy"))]);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].name, "web");
        assert_eq!(
            report.unhealthy[0].status,
            "exited (last health check: healthy)"
        );
    }

    /// Not running covers more than exited: a paused or endlessly restarting
    /// container is not serving either, and neither runtime is relied on to
    /// have rewritten the verdict.
    #[test]
    fn a_paused_or_restarting_container_is_not_healthy() {
        for state in ["paused", "restarting", "created", "dead"] {
            let report = judge(vec![stopped("web", state, Some("healthy"))]);
            assert!(!report.healthy, "{state} should not count as healthy");
        }
    }

    /// The carve-out that must survive: an app that declares no healthcheck for
    /// a one-shot init container is not failed when that container exits, which
    /// is what it was written to do.
    #[test]
    fn a_container_without_a_healthcheck_may_exit() {
        let report = judge(vec![
            named("web", Some("healthy")),
            stopped("init", "exited", None),
        ]);
        assert!(report.healthy);
    }

    /// A runtime that stops reporting `State.Status` must not take every
    /// instance out of rotation; the health string still decides.
    #[test]
    fn a_missing_run_state_falls_back_to_the_health_status() {
        let unknown = |name: &str, status: Option<&str>| Observed {
            name: name.to_string(),
            health: status.map(str::to_string),
            state: None,
        };
        assert!(judge(vec![unknown("web", Some("healthy"))]).healthy);
        assert!(!judge(vec![unknown("web", Some("unhealthy"))]).healthy);
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

    /// Captured from a real `nerdctl --namespace ... inspect` on nerdctl 2.3.5,
    /// trimmed of the fields this does not read.
    ///
    /// Two details this pins, both confirmed on hardware rather than assumed:
    /// `Name` has **no** leading slash (Docker's does), and `State.Health` is
    /// absent entirely -- not `"none"` -- for a container that declares no
    /// healthcheck.
    const NERDCTL_INSPECT_2_3_5: &str = r#"[
      {
        "Id": "aed39a5956f7cf11bb438296e804c712d038678a05627ff97f70d5f691eafe17",
        "Created": "2026-08-20T04:50:32.726557612Z",
        "Name": "nchp-failcheck-1",
        "Image": "docker.io/library/busybox:latest",
        "Platform": "linux",
        "State": {
          "Status": "running", "Running": true, "Paused": false,
          "Restarting": false, "Pid": 5157, "ExitCode": 0, "Error": "",
          "StartedAt": "2026-08-20T04:50:32.817445652Z", "FinishedAt": "",
          "Health": {
            "Status": "unhealthy", "FailingStreak": 17,
            "Log": [{"Start": "2026-08-20T04:51:17.56949457Z",
                     "End": "2026-08-20T04:51:17.602166707Z",
                     "ExitCode": 1, "Output": ""}]
          }
        }
      },
      {
        "Id": "8b92c5ef3f1855d5c35f37b8e7dd3ffe6b928e919a8b749409f707bf0addee05",
        "Created": "2026-08-20T04:50:32.52880536Z",
        "Name": "nchp-nocheck-1",
        "Image": "docker.io/library/busybox:latest",
        "Platform": "linux",
        "State": {
          "Status": "running", "Running": true, "Paused": false,
          "Restarting": false, "Pid": 5063, "ExitCode": 0, "Error": "",
          "StartedAt": "2026-08-20T04:50:32.627815194Z", "FinishedAt": ""
        }
      },
      {
        "Id": "6e7d785b3b5b05fe55f2b0ec07762aa387435b359bda185f925d44f00381f3b5",
        "Created": "2026-08-20T04:50:32.294111652Z",
        "Name": "nchp-withcheck-1",
        "Image": "docker.io/library/busybox:latest",
        "Platform": "linux",
        "State": {
          "Status": "running", "Running": true, "Paused": false,
          "Restarting": false, "Pid": 4921, "ExitCode": 0, "Error": "",
          "StartedAt": "2026-08-20T04:50:32.401211753Z", "FinishedAt": "",
          "Health": {
            "Status": "healthy", "FailingStreak": 0,
            "Log": [{"Start": "2026-08-20T04:51:18.12Z",
                     "End": "2026-08-20T04:51:18.15Z",
                     "ExitCode": 0, "Output": ""}]
          }
        }
      }
    ]"#;

    /// Parse the real payload the way `collect_nerdctl` does.
    fn parse_nerdctl(raw: &str) -> Vec<Observed> {
        let containers: Vec<NerdctlContainer> = serde_json::from_str(raw).unwrap();
        containers.into_iter().map(observe_nerdctl).collect()
    }

    #[test]
    fn real_nerdctl_inspect_output_parses() {
        let observed = parse_nerdctl(NERDCTL_INSPECT_2_3_5);
        assert_eq!(
            observed,
            vec![
                named("nchp-failcheck-1", Some("unhealthy")),
                // No healthcheck declared: no Health object at all.
                named("nchp-nocheck-1", None),
                named("nchp-withcheck-1", Some("healthy")),
            ]
        );
    }

    /// Captured from the same nerdctl 2.3.5 after `nerdctl stop`, and the
    /// reason [`is_running`] exists: the container is `exited` with
    /// `"Running": false`, and `State.Health.Status` is still `healthy` --
    /// nerdctl never rewrites the stored verdict, because
    /// `container healthcheck` returns "container is not running" before it
    /// gets that far. A container that crashes on its own produces the same
    /// pair, which is the shape this actually has to catch in production.
    const NERDCTL_INSPECT_2_3_5_STOPPED: &str = r#"[
      {
        "Id": "28e06fc13e2a6c487949b3291e319b7a8e88e155b00eb8cce33c620d95e87d03",
        "Created": "2026-08-20T15:15:36.647689318Z",
        "Name": "hc",
        "Image": "docker.io/library/busybox:latest",
        "Platform": "linux",
        "State": {
          "Status": "exited", "Running": false, "Paused": false,
          "Restarting": false, "Pid": 0, "ExitCode": 137, "Error": "",
          "StartedAt": "2026-08-20T15:15:36.968241457Z",
          "FinishedAt": "2026-08-20T15:16:08.374095926Z",
          "Health": {
            "Status": "healthy", "FailingStreak": 0,
            "Log": [{"Start": "2026-08-20T08:15:37.102770955-07:00",
                     "End": "2026-08-20T08:15:37.162666079-07:00",
                     "ExitCode": 0, "Output": ""}]
          }
        }
      }
    ]"#;

    /// Over the captured payload rather than a hand-built one: the guest agent
    /// must not report this instance healthy.
    #[test]
    fn a_real_stopped_nerdctl_container_keeps_its_healthy_verdict_but_is_judged_by_run_state() {
        let observed = parse_nerdctl(NERDCTL_INSPECT_2_3_5_STOPPED);
        assert_eq!(
            observed,
            vec![stopped("hc", "exited", Some("healthy"))],
            "nerdctl still reports the stale verdict; that is the point"
        );

        let report = judge(observed);
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].name, "hc");
        assert_eq!(
            report.unhealthy[0].status,
            "exited (last health check: healthy)"
        );
    }

    /// End to end over the real payload: one failing healthcheck holds the
    /// instance out, and the container without one does not save it.
    #[test]
    fn a_real_nerdctl_project_with_a_failing_check_is_not_healthy() {
        let report = judge(parse_nerdctl(NERDCTL_INSPECT_2_3_5));
        assert!(!report.healthy);
        assert_eq!(report.unhealthy.len(), 1);
        assert_eq!(report.unhealthy[0].name, "nchp-failcheck-1");
        assert_eq!(report.unhealthy[0].status, "unhealthy");
    }
}
