// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use crate::config::Config;
use crate::guest_api_service::{list_containers, GuestApiHandler};
use crate::rpc_service::{AppState, ExternalRpcHandler};
use anyhow::Result;
use docker_logs::parse_duration;
use dstack_guest_agent_rpc::{worker_server::WorkerRpc, AppInfo};
use guest_api::guest_api_server::GuestApiRpc;
use ra_rpc::{CallContext, RpcCall};
use rinja::Template;
use rocket::futures::StreamExt;
use rocket::response::stream::TextStream;
use rocket::{get, response::content::RawHtml, routes, Route, State};

pub fn external_routes(config: &Config) -> Vec<Route> {
    let mut routes = routes![index];
    if config.app_compose.public_logs {
        routes.extend(routes![get_logs]);
    }
    if config.app_compose.public_sysinfo {
        routes.extend(routes![metrics]);
    }
    routes
}

#[get("/")]
async fn index(state: &State<AppState>) -> Result<RawHtml<String>, String> {
    let public_logs = state.config().app_compose.public_logs;
    let public_sysinfo = state.config().app_compose.public_sysinfo;
    let public_tcbinfo = state.config().app_compose.public_tcbinfo;
    let context = CallContext::builder().state(&**state).build();
    let handler = ExternalRpcHandler::construct(context.clone())
        .map_err(|e| format!("Failed to construct RPC handler: {}", e))?;
    let AppInfo {
        app_name,
        app_id,
        instance_id,
        device_id,
        mr_aggregated: _,
        os_image_hash: _,
        key_provider_info,
        compose_hash: _,
        tcb_info,
        app_cert: _,
        vm_config: _,
    } = handler
        .info()
        .await
        .map_err(|e| format!("Failed to get worker info: {}", e))?;

    let handler = GuestApiHandler::construct(context)
        .map_err(|e| format!("Failed to construct RPC handler: {}", e))?;
    let system_info = handler.sys_info().await.unwrap_or_default();

    let containers = list_containers().await.unwrap_or_default().containers;
    let model = crate::models::Dashboard {
        app_name,
        app_id,
        instance_id,
        device_id,
        key_provider_info,
        tcb_info,
        containers,
        system_info,
        public_sysinfo,
        public_logs,
        public_tcbinfo,
    };
    match model.render() {
        Ok(html) => Ok(RawHtml(html)),
        Err(err) => Err(format!("Failed to render template: {}", err)),
    }
}

// Returns metrics about the guest in prometheus format if public_sysinfo is enabled
#[get("/metrics")]
async fn metrics(state: &State<AppState>) -> Result<String, String> {
    let public_sysinfo = state.config().app_compose.public_sysinfo;
    if !public_sysinfo {
        return Err("Sysinfo API is disabled".to_string());
    }
    let context = CallContext::builder().state(&**state).build();
    let handler = GuestApiHandler::construct(context.clone())
        .map_err(|e| format!("Failed to construct RPC handler: {}", e))?;

    let system_info = handler.sys_info().await.unwrap_or_default();
    let model = crate::models::Metrics { system_info };
    match model.render() {
        Ok(body) => Ok(body),
        Err(err) => Err(format!("Failed to render template: {err}")),
    }
}

#[get("/logs/<container_name>?<since>&<until>&<follow>&<text>&<timestamps>&<bare>&<tail>&<ansi>")]
#[allow(clippy::too_many_arguments)]
fn get_logs(
    container_name: String,
    since: Option<&str>,
    until: Option<&str>,
    follow: bool,
    text: bool,
    bare: bool,
    timestamps: bool,
    tail: Option<String>,
    ansi: bool,
) -> TextStream![String] {
    // default to 1 hour ago
    let since = since.map_or(Ok(0), parse_duration);
    let until = until.map_or(Ok(0), parse_duration);
    let tail = tail.unwrap_or("1000".to_string());
    TextStream! {
        let Ok(since) = since else {
            yield serde_json::json!({ "error": "Invalid since" }).to_string();
            return;
        };
        let Ok(until) = until else {
            yield serde_json::json!({ "error": "Invalid until" }).to_string();
            return;
        };
        let config = docker_logs::LogConfig {
            since,
            until,
            follow,
            text,
            bare,
            timestamps,
            tail,
            ansi,
        };
        let mut stream = match docker_logs::get_logs(&container_name, config) {
            Ok(stream) => stream,
            Err(e) => {
                yield serde_json::json!({ "error": e.to_string() }).to_string();
                return;
            }
        };
        loop {
            let log = match tokio::time::timeout(Duration::from_secs(600), stream.next()).await {
                Ok(Some(log)) => log,
                Ok(None) => break,
                Err(_) => {
                    break;
                }
            };
            match log {
                Ok(log) => {
                    yield log;
                }
                Err(e) => yield serde_json::json!({ "error": e.to_string() }).to_string(),
            }
        }
    }
}

mod docker_logs {
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use base64::Engine;
    use bollard::container::{LogOutput, LogsOptions};
    use bollard::Docker;
    use rocket::futures::{Stream, StreamExt};

    pub(crate) struct LogConfig {
        pub since: i64,
        pub until: i64,
        pub follow: bool,
        pub text: bool,
        pub bare: bool,
        pub timestamps: bool,
        pub tail: String,
        pub ansi: bool,
    }

    pub fn parse_duration(duration: &str) -> Result<i64> {
        parse_duration_inner(duration, SystemTime::now())
    }

    fn parse_duration_inner(duration: &str, now: SystemTime) -> Result<i64> {
        if duration.is_empty() {
            return Ok(0);
        }

        // If the string contains only digits, treat as seconds
        if duration.chars().all(|c| c.is_ascii_digit()) {
            return duration.parse::<i64>().context("Invalid duration");
        }

        let (value, unit) = duration
            .split_at_checked(duration.len() - 1)
            .context("Invalid duration")?;

        let value = value.parse::<u64>().context("Invalid duration")?;

        let seconds = match unit {
            "s" => value,
            "m" => value * 60,
            "h" => value * 3600,
            "d" => value * 24 * 3600,
            _ => {
                anyhow::bail!("Invalid time unit. Use s, m, h, or d");
            }
        };
        let now = now
            .duration_since(UNIX_EPOCH)
            .context("Failed to get current time")?;
        Ok(now.as_secs().saturating_sub(seconds) as i64)
    }

    pub fn get_logs(
        container_name: &str,
        config: LogConfig,
    ) -> Result<impl Stream<Item = Result<String, bollard::errors::Error>>> {
        let LogConfig {
            since,
            until,
            follow,
            text,
            bare,
            timestamps,
            tail,
            ansi,
        } = config;
        let docker = Docker::connect_with_local_defaults()?;
        let options = LogsOptions {
            stdout: true,
            stderr: true,
            since,
            until,
            follow,
            timestamps,
            tail: tail.to_string(),
        };

        Ok(docker
            .logs(container_name, Some(options))
            .map(move |result| result.map(|m| log_to_json(m, text, bare, ansi))))
    }

    fn log_to_json(log: LogOutput, text: bool, bare: bool, ansi: bool) -> String {
        let channel = match &log {
            LogOutput::StdErr { .. } => "stderr",
            LogOutput::StdOut { .. } => "stdout",
            LogOutput::StdIn { .. } => "stdin",
            LogOutput::Console { .. } => "console",
        };

        let message: &[u8] = log.as_ref();
        let message = if text {
            String::from_utf8_lossy(message).to_string()
        } else {
            base64::engine::general_purpose::STANDARD.encode(message)
        };
        if bare {
            if ansi || !text {
                return message;
            } else {
                return strip_ansi_escapes::strip_str(&message);
            }
        }
        let log_line = serde_json::json!({
            "channel": channel,
            "message": message,
        })
        .to_string();
        format!("{log_line}\n")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::{SystemTime, UNIX_EPOCH};

        #[test]
        fn test_parse_duration_empty() {
            assert_eq!(parse_duration("").unwrap(), 0);
        }

        #[test]
        fn test_parse_duration_numeric() {
            // When passing just numbers, it should treat as seconds
            let result = parse_duration("120").unwrap();
            assert_eq!(result, 120);
        }

        #[test]
        fn test_parse_duration_units() {
            let now = SystemTime::now();
            let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

            // Test seconds
            assert_eq!(parse_duration_inner("30s", now).unwrap(), now_secs - 30);

            // Test minutes
            assert_eq!(
                parse_duration_inner("5m", now).unwrap(),
                now_secs - (5 * 60)
            );

            // Test hours
            assert_eq!(
                parse_duration_inner("2h", now).unwrap(),
                now_secs - (2 * 3600)
            );

            // Test days
            assert_eq!(
                parse_duration_inner("1d", now).unwrap(),
                now_secs - (24 * 3600)
            );
        }

        #[test]
        fn test_parse_duration_errors() {
            // Invalid unit
            assert!(parse_duration("30x").is_err());

            // No numeric value
            assert!(parse_duration("h").is_err());

            // Invalid numeric value
            assert!(parse_duration("abc").is_err());
            assert!(parse_duration("abc").is_err());

            // Empty unit
            assert!(parse_duration("30").is_ok());
        }

        #[test]
        fn test_parse_duration_large_values() {
            // Test with a large number that shouldn't overflow
            assert!(parse_duration("999999999s").is_ok());

            // Test with a very large number of days
            assert!(parse_duration("365d").is_ok());
        }
    }
}
