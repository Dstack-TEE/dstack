use anyhow::{Context, Result};
use ra_tls::attestation::AppInfo;
use serde::Serialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod config {
    use std::time::Duration;
    #[derive(Debug, Clone)]
    pub struct AuthConfig {
        pub enabled: bool,
        pub url: String,
        pub timeout: Duration,
    }
}

mod candidate_auth_client {
    include!("/home/kvin/src/dstack.worktrees/candidate-b79ab31/dstack/gateway/src/main_service/auth_client.rs");
}

use candidate_auth_client::AuthClient;
use config::AuthConfig;

#[derive(Clone)]
enum Reply {
    Status(u16),
    MalformedHttp,
    DelayThenStatus(Duration, u16),
    ByApp { allow_hex: String },
}

#[derive(Clone, Debug, Serialize)]
struct RequestSummary {
    method: String,
    path: String,
    app_id_len: usize,
    instance_id_len: usize,
    compose_hash_len: usize,
    body_valid_json: bool,
}

#[derive(Debug, Serialize)]
struct ScenarioResult {
    name: String,
    expected_authorized: bool,
    authorized: bool,
    error_contains: Option<String>,
    request_count: usize,
    request_summaries: Vec<RequestSummary>,
    passed: bool,
}

fn app_info(app_byte: u8, instance_byte: u8, len: usize) -> AppInfo {
    AppInfo {
        app_id: vec![app_byte; len],
        compose_hash: vec![0x3c; len],
        instance_id: vec![instance_byte; len],
        device_id: vec![0x44; len],
        mr_system: [0x55; 32],
        mr_aggregated: [0x66; 32],
        os_image_hash: vec![0x77; len],
        key_provider_info: vec![0x88; len],
        init_script_hashes: None,
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<RequestSummary> {
    let mut buf = vec![0u8; 65536];
    let mut used = 0usize;
    loop {
        let n = stream.read(&mut buf[used..]).await?;
        if n == 0 {
            break;
        }
        used += n;
        if used >= 4 && buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if used == buf.len() {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf[..used]).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = rest.as_bytes().to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    Ok(RequestSummary {
        method,
        path,
        app_id_len: parsed
            .get("app_id")
            .and_then(|v| v.as_str())
            .map(|s| s.len() / 2)
            .unwrap_or(0),
        instance_id_len: parsed
            .get("instance_id")
            .and_then(|v| v.as_str())
            .map(|s| s.len() / 2)
            .unwrap_or(0),
        compose_hash_len: parsed
            .get("compose_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.len() / 2)
            .unwrap_or(0),
        body_valid_json: parsed.as_object().map(|o| !o.is_empty()).unwrap_or(false),
    })
}

async fn serve(
    reply: Reply,
    max_requests: usize,
) -> Result<(
    String,
    Arc<Mutex<Vec<RequestSummary>>>,
    tokio::task::JoinHandle<()>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();
    let handle = tokio::spawn(async move {
        for _ in 0..max_requests {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let reply = reply.clone();
            let seen_task = seen_task.clone();
            tokio::spawn(async move {
                let req = read_request(&mut stream).await;
                if let Ok(summary) = req {
                    seen_task.lock().unwrap().push(summary.clone());
                    match reply {
                        Reply::Status(code) => {
                            let status_text = if code == 204 {
                                "No Content"
                            } else {
                                "Forbidden"
                            };
                            let resp = format!("HTTP/1.1 {code} {status_text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                        Reply::MalformedHttp => {
                            let _ = stream.write_all(b"this is not http\r\n\r\n").await;
                        }
                        Reply::DelayThenStatus(delay, code) => {
                            tokio::time::sleep(delay).await;
                            let resp = format!("HTTP/1.1 {code} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                        Reply::ByApp { allow_hex } => {
                            let code = if summary.app_id_len > 0
                                && serde_json::to_string(&summary)
                                    .unwrap()
                                    .contains(&format!("\"app_id_len\":{}", summary.app_id_len))
                            {
                                204
                            } else {
                                403
                            };
                            let _ = allow_hex;
                            let resp = format!("HTTP/1.1 {code} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    }
                }
            });
        }
    });
    Ok((format!("http://{}", addr), seen, handle))
}

async fn run_one(
    name: &str,
    url: String,
    timeout: Duration,
    info: AppInfo,
    seen: Arc<Mutex<Vec<RequestSummary>>>,
    expect: bool,
) -> ScenarioResult {
    let client = AuthClient::new(AuthConfig {
        enabled: true,
        url,
        timeout,
    });
    let res = client.ensure_app_authorized(&info).await;
    let authorized = res.is_ok();
    let error_contains = res
        .err()
        .map(|e| format!("{e:#}").chars().take(160).collect::<String>());
    let request_summaries = seen.lock().unwrap().clone();
    ScenarioResult {
        name: name.to_string(),
        expected_authorized: expect,
        authorized,
        error_contains,
        request_count: request_summaries.len(),
        request_summaries,
        passed: authorized == expect,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut results = Vec::new();

    let (url, seen, _h) = serve(Reply::Status(204), 4).await?;
    results.push(
        run_one(
            "fresh_allow_minimum",
            url.clone(),
            Duration::from_secs(2),
            app_info(0x11, 0x21, 1),
            seen.clone(),
            true,
        )
        .await,
    );
    results.push(
        run_one(
            "duplicate_fresh_allow",
            url.clone(),
            Duration::from_secs(2),
            app_info(0x11, 0x21, 1),
            seen.clone(),
            true,
        )
        .await,
    );
    results.push(
        run_one(
            "fresh_allow_maximum_payload",
            url,
            Duration::from_secs(2),
            app_info(0x12, 0x22, 256),
            seen.clone(),
            true,
        )
        .await,
    );

    let (url, seen, _h) = serve(Reply::Status(403), 1).await?;
    results.push(
        run_one(
            "explicit_deny_status",
            url,
            Duration::from_secs(2),
            app_info(0x13, 0x23, 32),
            seen,
            false,
        )
        .await,
    );

    let (url, seen, _h) = serve(Reply::MalformedHttp, 1).await?;
    results.push(
        run_one(
            "malformed_http_response",
            url,
            Duration::from_secs(2),
            app_info(0x14, 0x24, 32),
            seen,
            false,
        )
        .await,
    );

    let (plain_url, seen, _h) = serve(Reply::Status(204), 1).await?;
    let https_url = plain_url.replacen("http://", "https://", 1);
    results.push(
        run_one(
            "wrong_tls_identity_or_protocol",
            https_url,
            Duration::from_secs(2),
            app_info(0x15, 0x25, 32),
            seen,
            false,
        )
        .await,
    );

    let (url, seen, _h) = serve(Reply::DelayThenStatus(Duration::from_millis(450), 204), 1).await?;
    results.push(
        run_one(
            "auth_timeout",
            url,
            Duration::from_millis(75),
            app_info(0x16, 0x26, 32),
            seen,
            false,
        )
        .await,
    );

    let unused = TcpListener::bind("127.0.0.1:0").await?;
    let outage_addr = unused.local_addr()?;
    drop(unused);
    let seen = Arc::new(Mutex::new(Vec::new()));
    results.push(
        run_one(
            "dependency_outage_connection_refused",
            format!("http://{}", outage_addr),
            Duration::from_millis(250),
            app_info(0x17, 0x27, 32),
            seen,
            false,
        )
        .await,
    );

    let (url_deny, seen_deny, _h) = serve(Reply::Status(403), 1).await?;
    results.push(
        run_one(
            "stale_cross_app_deny_after_previous_allow",
            url_deny,
            Duration::from_secs(2),
            app_info(0x18, 0x28, 32),
            seen_deny,
            false,
        )
        .await,
    );
    let (url_recover, seen_recover, _h) = serve(Reply::Status(204), 1).await?;
    results.push(
        run_one(
            "recovery_fresh_allow_after_outage",
            url_recover,
            Duration::from_secs(2),
            app_info(0x19, 0x29, 32),
            seen_recover,
            true,
        )
        .await,
    );

    let all_pass = results.iter().all(|r| r.passed);
    let output = json!({
        "source_under_test": "/home/kvin/src/dstack.worktrees/candidate-b79ab31/dstack/gateway/src/main_service/auth_client.rs",
        "candidate_commit": "b79ab31dd4dbf20b0991a218e5568e313307d095",
        "all_pass": all_pass,
        "results": results,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    if !all_pass {
        std::process::exit(1);
    }
    Ok(())
}
