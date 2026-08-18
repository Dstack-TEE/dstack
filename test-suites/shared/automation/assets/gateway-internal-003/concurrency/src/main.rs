use anyhow::Result;
use ra_tls::attestation::AppInfo;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
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
    include!("@REPOSITORY@/dstack/gateway/src/main_service/auth_client.rs");
}
use candidate_auth_client::AuthClient;
use config::AuthConfig;

#[derive(Clone, Debug, Serialize)]
struct Op {
    name: String,
    committed: bool,
    phase: String,
    err: Option<String>,
}

fn app_info(app_byte: u8, instance_byte: u8) -> AppInfo {
    AppInfo {
        app_id: vec![app_byte; 32],
        compose_hash: vec![0x43; 32],
        instance_id: vec![instance_byte; 32],
        device_id: vec![0x44; 32],
        mr_system: [0x55; 32],
        mr_aggregated: [0x66; 32],
        os_image_hash: vec![0x77; 32],
        key_provider_info: vec![0x88; 32],
        init_script_hashes: None,
    }
}
async fn read_req(s: &mut tokio::net::TcpStream) -> (usize, String) {
    let mut buf = vec![0u8; 65536];
    let mut used = 0usize;
    loop {
        match s.read(&mut buf[used..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                used += n;
                if used >= 4 && buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if used == buf.len() {
                    break;
                }
            }
        }
    }
    let txt = String::from_utf8_lossy(&buf[..used]);
    let (_, rest) = txt.split_once("\r\n\r\n").unwrap_or(("", ""));
    let app = serde_json::from_str::<serde_json::Value>(rest)
        .ok()
        .and_then(|v| {
            v.get("app_id")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    (app.len() / 2, app.chars().take(2).collect())
}
async fn interrupted_server(
) -> Result<(String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let h = tokio::spawn(async move {
        for idx in 0..2u8 {
            if let Ok((mut s, _)) = listener.accept().await {
                let ev = ev.clone();
                tokio::spawn(async move {
                    let (len, first) = read_req(&mut s).await;
                    if first == "31" {
                        ev.lock().unwrap().push(format!(
                            "request{idx}:primary_len{len}:closed_before_auth_decision"
                        ));
                    } else {
                        ev.lock()
                            .unwrap()
                            .push(format!("request{idx}:conflict_len{len}:allowed"));
                        let _=s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    }
                });
            }
        }
    });
    Ok((url, events, h))
}
async fn allow_server() -> Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let h = tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let _ = read_req(&mut s).await;
            let _ = s
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    });
    Ok((url, h))
}
async fn gated_register(
    name: &str,
    client: AuthClient,
    info: AppInfo,
    state: Arc<Mutex<BTreeSet<String>>>,
) -> Op {
    match client.ensure_app_authorized(&info).await {
        Ok(()) => {
            state.lock().unwrap().insert(name.to_string());
            Op {
                name: name.into(),
                committed: true,
                phase: "commit_after_auth".into(),
                err: None,
            }
        }
        Err(e) => Op {
            name: name.into(),
            committed: false,
            phase: "authorization".into(),
            err: Some(format!("{e:#}").chars().take(180).collect()),
        },
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let state = Arc::new(Mutex::new(BTreeSet::new()));
    let (url, events, _h) = interrupted_server().await?;
    let c1 = AuthClient::new(AuthConfig {
        enabled: true,
        url: url.clone(),
        timeout: Duration::from_millis(700),
    });
    let c2 = AuthClient::new(AuthConfig {
        enabled: true,
        url: url.clone(),
        timeout: Duration::from_millis(700),
    });
    let a = tokio::spawn(gated_register(
        "interrupted-primary",
        c1,
        app_info(0x31, 0x41),
        state.clone(),
    ));
    let b = tokio::spawn(gated_register(
        "concurrent-conflict",
        c2,
        app_info(0x32, 0x42),
        state.clone(),
    ));
    let mut ops = vec![a.await?, b.await?];
    let commits_after_interrupt = state.lock().unwrap().len();
    let failed: Vec<_> = ops
        .iter()
        .filter(|o| !o.committed)
        .map(|o| o.name.clone())
        .collect();
    let (url2, _h2) = allow_server().await?;
    let retry = gated_register(
        "retry-after-restore",
        AuthClient::new(AuthConfig {
            enabled: true,
            url: url2,
            timeout: Duration::from_millis(700),
        }),
        app_info(0x31, 0x41),
        state.clone(),
    )
    .await;
    ops.push(retry);
    let final_state: Vec<_> = state.lock().unwrap().iter().cloned().collect();
    let passed = commits_after_interrupt == 1
        && failed == vec!["interrupted-primary".to_string()]
        && ops.last().unwrap().committed
        && final_state.len() == 2
        && ops
            .iter()
            .any(|o| !o.committed && o.phase == "authorization");
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"candidate_commit":"@CANDIDATE_COMMIT@","source_under_test":"@REPOSITORY@/dstack/gateway/src/main_service/auth_client.rs","dependency_events":events.lock().unwrap().clone(),"operations":ops,"commits_after_interrupt":commits_after_interrupt,"final_committed_state":final_state,"passed":passed})
        )?
    );
    if !passed {
        std::process::exit(1);
    }
    Ok(())
}
