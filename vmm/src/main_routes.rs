use crate::app::App;
use anyhow::Result;
use fs_err as fs;
use rocket::{
    get,
    http::ContentType,
    response::{status::Custom, stream::TextStream},
    routes, Route, State,
};
use rocket_apitoken::Authorized;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

macro_rules! file_or_include_str {
    ($path:literal) => {
        fs::metadata($path)
            .is_ok()
            .then(|| fs::read_to_string($path).ok())
            .flatten()
            .unwrap_or_else(|| include_str!($path).to_string())
    };
}

#[get("/")]
async fn index() -> (ContentType, String) {
    (ContentType::HTML, file_or_include_str!("console.html"))
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
    _auth: Authorized,
    app: &State<App>,
    id: String,
    follow: bool,
    ansi: bool,
    lines: Option<usize>,
    ch: Option<&str>,
) -> TextStream![String] {
    let workdir = app.work_dir(&id);
    let ch = ch.unwrap_or("serial").to_string();
    TextStream! {
        let log_file = match ch.as_str() {
            "serial" => workdir.serial_file(),
            "stdout" => workdir.stdout_file(),
            "stderr" => workdir.stderr_file(),
            _ => {
                yield format!("Unknown channel {ch}");
                return;
            }
        };

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
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    yield format!("<failed to read line: {err}>");
                    break;
                }
            }
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![index, res, vm_logs]
}
