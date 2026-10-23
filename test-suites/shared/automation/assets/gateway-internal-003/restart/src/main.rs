use anyhow::Result;
use ra_tls::attestation::AppInfo;
use serde_json::json;
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
fn app_info(app: u8, inst: u8) -> AppInfo {
    AppInfo {
        app_id: vec![app; 32],
        compose_hash: vec![0x43; 32],
        instance_id: vec![inst; 32],
        device_id: vec![0x44; 32],
        mr_system: [0x55; 32],
        mr_aggregated: [0x66; 32],
        os_image_hash: vec![0x77; 32],
        key_provider_info: vec![0x88; 32],
        init_script_hashes: None,
    }
}
async fn read_req(s: &mut tokio::net::TcpStream) -> String {
    let mut buf = vec![0u8; 65536];
    let mut used = 0;
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
    let (_, body) = txt.split_once("\r\n\r\n").unwrap_or(("", ""));
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("app_id")
                .and_then(|x| x.as_str())
                .map(|s| s.chars().take(2).collect())
        })
        .unwrap_or_default()
}
async fn server(
    code: u16,
    seen: Arc<Mutex<Vec<String>>>,
) -> Result<(String, tokio::task::JoinHandle<()>)> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", l.local_addr()?);
    let h = tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let app = read_req(&mut s).await;
            seen.lock().unwrap().push(app);
            let reason = if code == 204 {
                "No Content"
            } else {
                "Forbidden"
            };
            let resp = format!(
                "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
    Ok((url, h))
}
#[tokio::main]
async fn main() -> Result<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (u1, _) = server(204, seen.clone()).await?;
    let first = AuthClient::new(AuthConfig {
        enabled: true,
        url: u1,
        timeout: Duration::from_secs(1),
    })
    .ensure_app_authorized(&app_info(0x51, 0x61))
    .await
    .is_ok();
    let (u2, _) = server(403, seen.clone()).await?;
    let adjacent = AuthClient::new(AuthConfig {
        enabled: true,
        url: u2,
        timeout: Duration::from_secs(1),
    })
    .ensure_app_authorized(&app_info(0x52, 0x62))
    .await
    .is_ok();
    let (u3, _) = server(204, seen.clone()).await?;
    let after_restart = AuthClient::new(AuthConfig {
        enabled: true,
        url: u3,
        timeout: Duration::from_secs(1),
    })
    .ensure_app_authorized(&app_info(0x51, 0x61))
    .await
    .is_ok();
    let seen = seen.lock().unwrap().clone();
    let passed = first
        && !adjacent
        && after_restart
        && seen == vec!["51".to_string(), "52".to_string(), "51".to_string()];
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"candidate_commit":"@CANDIDATE_COMMIT@","source_under_test":"@REPOSITORY@/dstack/gateway/src/main_service/auth_client.rs","first_allow_before_restart":first,"adjacent_identity_authorized":adjacent,"allow_after_client_restart":after_restart,"auth_request_identity_order":seen,"passed":passed})
        )?
    );
    if !passed {
        std::process::exit(1);
    }
    Ok(())
}
