// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One line per request on every listener, written to stdout and so to the
//! serial console the host can read.
//!
//! Only what identifies the call is logged: the listener, the peer, the method,
//! the path, the status and the latency. Headers (bearer tokens among them) and
//! bodies stay out. So does the query string, except on listeners that opt in
//! with [`AccessLog::with_query`]: a prpc GET takes its arguments from the
//! query, and on the internal sockets those arguments may be secrets.

use std::time::Instant;

use ra_rpc::RemoteEndpoint;
use rocket::{
    fairing::{Fairing, Info, Kind},
    Data, Request, Response,
};

/// What the systemd watchdog polls on the external listener. Logging it would
/// put a line on the console every few seconds for the life of the CVM.
pub const WATCHDOG_PROBE_PATH: &str = "/prpc/Worker.Version";

const MAX_URI_LEN: usize = 512;

pub struct AccessLog {
    listener: &'static str,
    log_query: bool,
}

impl AccessLog {
    pub fn new(listener: &'static str) -> Self {
        Self {
            listener,
            log_query: false,
        }
    }

    /// Also log the query string, for a listener whose callers never put
    /// secrets in it.
    pub fn with_query(listener: &'static str) -> Self {
        Self {
            listener,
            log_query: true,
        }
    }
}

/// Captured before any other fairing can rewrite the URI, so a request
/// `ScopeFairing` turned away is logged under the path the caller asked for.
struct Started {
    at: Instant,
    path: String,
    query: Option<String>,
}

#[rocket::async_trait]
impl Fairing for AccessLog {
    fn info(&self) -> Info {
        Info {
            name: "access log",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        req.local_cache(|| Started::now(req, self.log_query));
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let started = req.local_cache(|| Started::now(req, self.log_query));
        let path = started.path.as_str();
        let peer = req.remote().cloned().map(RemoteEndpoint::from);
        if path == WATCHDOG_PROBE_PATH
            && matches!(&peer, Some(RemoteEndpoint::Tcp(addr)) if addr.ip().is_loopback())
        {
            return;
        }
        let uri = match &started.query {
            Some(query) => format!("{path}?{query}"),
            None => path.to_string(),
        };
        tracing::info!(
            "{} {} \"{} {}\" {} {:?}",
            self.listener,
            peer.as_ref().map_or_else(|| "-".into(), describe),
            req.method(),
            dstack_types::sanitize_for_log(&uri, MAX_URI_LEN),
            res.status().code,
            started.at.elapsed(),
        );
    }
}

impl Started {
    fn now(req: &Request<'_>, log_query: bool) -> Self {
        let uri = req.uri();
        Self {
            at: Instant::now(),
            path: uri.path().to_string(),
            query: uri.query().filter(|_| log_query).map(|q| q.to_string()),
        }
    }
}

fn describe(peer: &RemoteEndpoint) -> String {
    match peer {
        RemoteEndpoint::Tcp(addr) | RemoteEndpoint::Quic(addr) => addr.to_string(),
        RemoteEndpoint::Unix {
            peer: Some(cred), ..
        } => format!("pid={},uid={}", cred.pid, cred.uid),
        RemoteEndpoint::Unix { peer: None, .. } => "unix".into(),
        RemoteEndpoint::Vsock { cid, port } => format!("vsock:{cid}:{port}"),
        RemoteEndpoint::Other(address) => dstack_types::sanitize_for_log(address, MAX_URI_LEN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::{http::Header, local::asynchronous::Client};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[rocket::get("/secret")]
    fn secret() -> &'static str {
        "ok"
    }

    async fn log_of(access_log: AccessLog) -> String {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter("dstack_guest_agent::access_log=info")
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let client = Client::untracked(
            rocket::build()
                .mount("/", rocket::routes![secret])
                .attach(access_log),
        )
        .await
        .unwrap();
        client
            .get("/secret?path=hunter2")
            .header(Header::new("Authorization", "Bearer hunter3"))
            .dispatch()
            .await;
        let log = captured.0.lock().unwrap().clone();
        String::from_utf8(log).unwrap()
    }

    #[tokio::test]
    async fn neither_the_query_nor_the_token_reaches_the_log() {
        let log = log_of(AccessLog::new("test")).await;
        assert!(log.contains(r#"test - "GET /secret" 200"#), "{log}");
        assert!(!log.contains("hunter"), "{log}");
    }

    #[tokio::test]
    async fn an_opted_in_listener_logs_the_query_but_not_the_token() {
        let log = log_of(AccessLog::with_query("test")).await;
        assert!(
            log.contains(r#"test - "GET /secret?path=hunter2" 200"#),
            "{log}"
        );
        assert!(!log.contains("hunter3"), "{log}");
    }
}
