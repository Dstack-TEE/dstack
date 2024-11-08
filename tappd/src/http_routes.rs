use crate::rpc_service::{list_containers, AppState, ExternalRpcHandler, InternalRpcHandler};
use anyhow::Result;
use ra_rpc::{rocket_helper::handle_prpc, RpcCall};
use rinja::Template;
use rocket::futures::StreamExt;
use rocket::response::stream::TextStream;
use rocket::{
    data::{Data, Limits},
    get,
    http::ContentType,
    mtls::Certificate,
    post,
    response::{content::RawHtml, status::Custom},
    routes, Route, State,
};
use tappd_rpc::{worker_server::WorkerRpc, WorkerInfo};

#[post("/prpc/<method>?<json>", data = "<data>")]
async fn prpc_post(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, InternalRpcHandler>(
        &*state,
        cert,
        method,
        Some(data),
        limits,
        content_type,
        json,
    )
    .await
    .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/prpc/<method>")]
async fn prpc_get(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, InternalRpcHandler>(&*state, cert, method, None, limits, content_type, true)
        .await
        .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

pub fn internal_routes() -> Vec<Route> {
    routes![prpc_post, prpc_get]
}

#[get("/")]
async fn index(state: &State<AppState>) -> Result<RawHtml<String>, String> {
    let handler = ExternalRpcHandler::construct(state, None)
        .map_err(|e| format!("Failed to construct RPC handler: {}", e))?;
    let WorkerInfo {
        app_id,
        instance_id,
        tcb_info,
        app_cert,
    } = handler
        .info()
        .await
        .map_err(|e| format!("Failed to get worker info: {}", e))?;

    let containers = list_containers().await.unwrap_or_default().containers;
    let model = crate::models::Dashboard {
        app_id,
        instance_id,
        app_cert,
        tcb_info,
        containers,
    };
    match model.render() {
        Ok(html) => Ok(RawHtml(html)),
        Err(err) => Err(format!("Failed to render template: {}", err)),
    }
}

#[post("/prpc/<method>?<json>", data = "<data>")]
async fn external_prpc_post(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, ExternalRpcHandler>(
        &*state,
        cert,
        method,
        Some(data),
        limits,
        content_type,
        json,
    )
    .await
    .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/prpc/<method>")]
async fn external_prpc_get(
    state: &State<AppState>,
    cert: Option<Certificate<'_>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Result<Custom<Vec<u8>>, String> {
    handle_prpc::<_, ExternalRpcHandler>(&*state, cert, method, None, limits, content_type, true)
        .await
        .map_err(|e| format!("Failed to handle PRPC request: {e}"))
}

#[get("/logs/<container_name>?<since>&<until>&<follow>&<text>&<timestamps>&<bare>")]
fn get_logs(
    container_name: String,
    since: Option<i64>,
    until: Option<i64>,
    follow: bool,
    text: bool,
    bare: bool,
    timestamps: bool,
) -> TextStream![String] {
    // default to 1 hour ago
    let since = since.unwrap_or_else(|| chrono::Utc::now().timestamp().saturating_sub(3600).max(0));
    TextStream! {
        let config = docker_logs::LogConfig {
            since,
            until: until.unwrap_or(0),
            follow,
            text,
            bare,
            timestamps,
        };
        let mut stream = match docker_logs::get_logs(&container_name, config) {
            Ok(stream) => stream,
            Err(e) => {
                yield serde_json::json!({ "error": e.to_string() }).to_string();
                return;
            }
        };
        while let Some(log) = stream.next().await {
            match log {
                Ok(log) => yield log,
                Err(e) => yield serde_json::json!({ "error": e.to_string() }).to_string(),
            }
        }
    }
}

pub fn external_routes() -> Vec<Route> {
    routes![index, external_prpc_post, external_prpc_get, get_logs]
}

mod docker_logs {
    use anyhow::Result;
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
        } = config;
        let docker = Docker::connect_with_local_defaults()?;
        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            since,
            until,
            follow,
            timestamps,
            ..Default::default()
        };

        Ok(docker
            .logs(container_name, Some(options))
            .map(move |result| result.map(|m| log_to_json(m, text, bare))))
    }

    fn log_to_json(log: LogOutput, text: bool, bare: bool) -> String {
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
            return message;
        }
        let log_line = serde_json::json!({
            "channel": channel,
            "message": message,
        })
        .to_string();
        format!("{log_line}\n")
    }
}
