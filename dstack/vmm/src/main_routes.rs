// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::app::App;
use fs_err as fs;
use rocket::{
    get,
    http::ContentType,
    response::{status::Custom, stream::TextStream},
    routes, Route, State,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

const CONSOLE_V1: &str = include_str!(concat!(env!("OUT_DIR"), "/console_v1.html"));

macro_rules! file_or_include_str {
    ($path:literal) => {
        fs::metadata($path)
            .is_ok()
            .then(|| fs::read_to_string($path).ok())
            .flatten()
            .unwrap_or_else(|| include_str!($path).to_string())
    };
}

fn replace_title(app: &App, html: &str) -> String {
    let title = if app.config.node_name.is_empty() {
        "dstack-vmm".to_string()
    } else {
        format!("{} | dstack-vmm", app.config.node_name)
    };
    html.replace("{{TITLE}}", &title)
}

fn render_console(html: String, app: &State<App>) -> (ContentType, String) {
    let html = replace_title(app, &html);
    (ContentType::HTML, html)
}

#[get("/")]
async fn index(app: &State<App>) -> (ContentType, String) {
    render_console(CONSOLE_V1.to_string(), app)
}

#[get("/v1")]
async fn v1(app: &State<App>) -> (ContentType, String) {
    index(app).await
}

#[get("/beta")]
async fn beta(app: &State<App>) -> (ContentType, String) {
    index(app).await
}

#[get("/res/<path>")]
async fn res(path: &str) -> Result<(ContentType, String), Custom<String>> {
    match path {
        "x25519.js" => Ok((ContentType::JavaScript, file_or_include_str!("x25519.js"))),
        _ => Err(Custom(
            rocket::http::Status::NotFound,
            "Not found".to_string(),
        )),
    }
}

static STREAM_CREATED_COUNTER: AtomicUsize = AtomicUsize::new(0);
static STREAM_DROPPED_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct StreamCounter {
    id: usize,
}

impl StreamCounter {
    fn new() -> Self {
        let id = STREAM_CREATED_COUNTER.fetch_add(1, Ordering::Relaxed);
        info!(
            "Stream {id} created, created: {}, dropped: {}",
            STREAM_CREATED_COUNTER.load(Ordering::Relaxed),
            STREAM_DROPPED_COUNTER.load(Ordering::Relaxed)
        );
        Self { id }
    }
}

impl Drop for StreamCounter {
    fn drop(&mut self) {
        STREAM_DROPPED_COUNTER.fetch_add(1, Ordering::Relaxed);
        info!(
            "Stream {} dropped, created: {}, dropped: {}",
            self.id,
            STREAM_CREATED_COUNTER.load(Ordering::Relaxed),
            STREAM_DROPPED_COUNTER.load(Ordering::Relaxed)
        );
    }
}

#[get("/logs?<id>&<follow>&<ansi>&<lines>&<ch>")]
fn vm_logs(
    app: &State<App>,
    id: String,
    follow: bool,
    ansi: bool,
    lines: Option<usize>,
    ch: Option<&str>,
) -> Result<TextStream![String], Custom<String>> {
    // Resolve only an inventory-owned VM before deriving a filesystem path.
    // This keeps arbitrary IDs (including traversal strings) outside run_path.
    if app.lock().get(&id).is_none() {
        return Err(Custom(
            rocket::http::Status::NotFound,
            "VM not found".to_string(),
        ));
    }
    let workdir = app
        .work_dir(&id)
        .map_err(|err| Custom(rocket::http::Status::BadRequest, err.to_string()))?;
    let log_file = match ch.unwrap_or("serial") {
        "serial" => workdir.serial_file(),
        "stdout" => workdir.stdout_file(),
        "stderr" => workdir.stderr_file(),
        channel => {
            return Err(Custom(
                rocket::http::Status::BadRequest,
                format!("Unknown channel {channel}"),
            ));
        }
    };

    Ok(TextStream! {
        let counter = StreamCounter::new();

        const DEFAULT_TAIL_LINES: usize = 10000;
        let tailer_result = tailf::Options::builder()
            .num_lines(lines.or(Some(DEFAULT_TAIL_LINES)))
            .follow(follow)
            .build()
            .tail(log_file);
        let mut tailer = match tailer_result {
            Err(err) => {
                yield format!("{err:?}");
                return;
            }
            Ok(tailer) => tailer,
        };

        loop {
            // This is a workaround for https://github.com/rwf2/Rocket/issues/2888
            // However, If is is accessed via vscode's port forwarding, it will still get trouble:
            // https://github.com/microsoft/vscode-remote-release/issues/3561
            let next = match timeout(Duration::from_secs(60), tailer.next()).await {
                Ok(next) => next,
                Err(_) => {
                    yield format!("[vmm heartbeat]\n");
                    let created = STREAM_CREATED_COUNTER.load(Ordering::Relaxed);
                    let dropped = STREAM_DROPPED_COUNTER.load(Ordering::Relaxed);
                    let diff = created.saturating_sub(dropped);
                    debug!(
                        "Stream {} heartbeat, created: {created}, dropped: {dropped}, diff: {diff}",
                        counter.id,
                    );
                    continue;
                }
            };
            match next {
                Ok(Some(line)) => {
                    let line_str = String::from_utf8_lossy(&line);
                    if ansi {
                        yield line_str.to_string();
                    } else {
                        yield strip_ansi_escapes::strip_str(&line_str);
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    yield format!("<failed to read line: {err}>");
                    break;
                }
            }
        }
    })
}

pub fn routes() -> Vec<Route> {
    routes![index, v1, beta, res, vm_logs]
}
